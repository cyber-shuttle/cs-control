package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	pathpkg "path"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
)

func (s Service) Validate(ctx context.Context, request CreateRequest) (*ValidationResult, error) {
	if request.IdempotencyKey == "" {
		return nil, apierr.New("invalid_idempotency_key", "idempotencyKey is required for runtime validation", 400)
	}
	prepared, err := s.prepareRuntime(ctx, request)
	if err != nil {
		return nil, err
	}
	result, err := s.validateScript(ctx, prepared.request.SSHHost, prepared.script)
	if err != nil {
		return nil, err
	}
	return validationResult(prepared, result), nil
}

// Script is the reviewed script before Slurm has seen it, so a caller can read
// what is about to be validated while the validation runs.
func (s Service) Script(ctx context.Context, request CreateRequest) (*RuntimeScript, error) {
	if request.IdempotencyKey == "" {
		return nil, apierr.New("invalid_idempotency_key", "idempotencyKey is required for runtime validation", 400)
	}
	prepared, err := s.prepareRuntime(ctx, request)
	if err != nil {
		return nil, err
	}
	return &RuntimeScript{RuntimeID: prepared.runtime.ID, Script: prepared.script}, nil
}

func (s Service) Create(ctx context.Context, request CreateRequest) (*Runtime, error) {
	var err error
	request, err = assignRuntimeID(request)
	if err != nil {
		return nil, err
	}
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if request.IdempotencyKey != "" {
		var existing *Runtime
		err := s.Store.withLock(func(_ Store, current *state) error {
			if runtime := current.Runtimes[request.ID]; runtime != nil {
				if runtime.Owner != auth.Principal {
					return errOwnerMismatch
				}
				if !sameCreateRequest(runtime, request) {
					return apierr.New("idempotency_conflict", "idempotency key was already used for another request", 409)
				}
				existing = detached(runtime)
			}
			return nil
		})
		if err != nil || existing != nil {
			return existing, err
		}
	}
	prepared, err := s.prepareRuntime(ctx, request)
	if err != nil {
		return nil, err
	}

	s.runtimeStatus(request.ID, "Validating runtime with Slurm")
	checked, err := s.validateScript(ctx, request.SSHHost, prepared.script)
	if err != nil {
		s.runtimeStatus(request.ID, "Slurm validation failed")
		return nil, err
	}
	if !checked.passed {
		s.runtimeStatus(request.ID, "Slurm validation failed")
		return nil, apierr.New("slurm_validation_failed", validationMessage(checked), 400)
	}
	s.runtimeStatus(request.ID, "Slurm validation passed")

	var intent Runtime
	var record devtunnel.Record
	var jupyterToken string
	reused, tunnelCreated := false, false
	err = s.Store.withLock(func(store Store, current *state) error {
		existing := current.Runtimes[request.ID]
		if existing != nil {
			if existing.Owner != auth.Principal {
				return errOwnerMismatch
			}
			if request.IdempotencyKey != "" && sameCreateRequest(existing, request) {
				intent = *existing
				reused = true
				return nil
			}
			if !request.relaunch {
				return apierr.New("runtime_exists", "runtime ID already exists", 409)
			}
			if !terminalRuntime(existing.State) {
				return errRuntimeRunning
			}
		}
		now := s.now()
		intent = prepared.runtime
		intent.State, intent.CreatedAt, intent.UpdatedAt = "SUBMITTING", now, now
		if existing != nil {
			intent.CreatedAt = existing.CreatedAt
		}
		var createErr error
		record, jupyterToken, createErr = s.createAllocationTunnel(ctx, &intent, auth)
		if createErr != nil {
			return createErr
		}
		tunnelCreated = true
		current.Runtimes[intent.ID] = &intent
		if err := store.save(current); err != nil {
			if existing != nil {
				current.Runtimes[intent.ID] = existing
			} else {
				delete(current.Runtimes, intent.ID)
			}
			return fmt.Errorf("persist submit intent: %w", err)
		}
		return nil
	})
	if err != nil {
		if tunnelCreated {
			return nil, errors.Join(err, s.compensateAllocationTunnel(auth, intent))
		}
		return nil, err
	}
	if reused {
		return &intent, nil
	}

	// A host that has never run one of these has neither the interpreter the
	// script starts nor the binary it execs, and installing them takes minutes.
	// The runtime is already durable here, so the reader watching it sees the
	// preparation happen rather than a request that says nothing until it ends.
	if err := s.provisionRuntime(ctx, request.SSHHost, intent, prepared.linkspan); err != nil {
		s.runtimeStatus(intent.ID, "Runtime environment preparation failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(auth, intent, request.relaunch))
	}

	s.runtimeStatus(intent.ID, "Submitting runtime to Slurm")
	jobID, err := s.submitRuntimeScript(ctx, request.SSHHost, intent, prepared.script, jupyterToken, record.HostToken)
	if err != nil {
		if ambiguousSubmission(err) {
			s.runtimeStatus(intent.ID, "Runtime submission outcome is unresolved")
			return nil, err
		}
		s.runtimeStatus(intent.ID, "Runtime submission failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(auth, intent, request.relaunch))
	}
	s.runtimeStatus(intent.ID, "Runtime submitted to Slurm")
	var created *Runtime
	cancelSubmitted := false
	err = s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[intent.ID]
		if runtime == nil {
			return errors.New("submitted runtime disappeared from state")
		}
		runtime.JobID = jobID
		if runtime.State == "SUBMITTING" {
			runtime.State = "QUEUED"
		}
		// A record that reached a terminal state while this submission was in
		// flight is not this job's owner. Cancel the job rather than leave an
		// allocation running for a card that has already finished without it.
		cancelSubmitted = runtime.State == "STOPPING" || terminalRuntime(runtime.State)
		runtime.UpdatedAt = s.now()
		if err := store.save(current); err != nil {
			return fmt.Errorf("persist submitted job %s: %w", jobID, err)
		}
		created = detached(runtime)
		return nil
	})
	if err != nil {
		s.runtimeStatus(intent.ID, "Runtime submission could not be saved")
		_, cancelErr := s.Runner.Run(ctx, request.SSHHost, nil, "scancel", jobID)
		if cancelErr != nil {
			return nil, fmt.Errorf("%w; compensation scancel failed: %v", err, cancelErr)
		}
		return nil, fmt.Errorf("%w; job was cancelled", err)
	}
	if created != nil && created.State == "QUEUED" {
		s.runtimeStatus(intent.ID, "Runtime is queued")
	}
	if cancelSubmitted {
		// Stop may win while sbatch is still in flight and before a job ID is
		// visible. Once submission returns, cancel that exact job before Create
		// can return; do not wait for a later poll to uphold the stop intent.
		cancelCtx, cancel := context.WithTimeout(context.Background(), s.Runner.EffectiveTimeout())
		_, cancelErr := s.Runner.Run(cancelCtx, request.SSHHost, nil, "scancel", jobID)
		cancel()
		diagnostic := ""
		if cancelErr != nil {
			diagnostic = cancelErr.Error()
		}
		err = s.Store.withLock(func(store Store, current *state) error {
			runtime := current.Runtimes[intent.ID]
			if runtime == nil {
				return nil
			}
			if runtime.JobID == jobID && (runtime.State == "STOPPING" || terminalRuntime(runtime.State)) {
				runtime.Error, runtime.UpdatedAt = diagnostic, s.now()
				if err := store.save(current); err != nil {
					return err
				}
			}
			// A concurrent terminal update wins both persistence and the Create
			// response; cancellation diagnostics may never revive stale state.
			created = detached(runtime)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return created, nil
}

// Start submits a new allocation under a finished runtime's own identity and
// settings, replacing its record rather than adding one beside it.
func (s Service) Start(ctx context.Context, id string) (*Runtime, error) {
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	runtime, err := s.GetCached(id)
	if err != nil {
		return nil, err
	}
	if runtime.Owner != auth.Principal {
		return nil, errOwnerMismatch
	}
	if !terminalRuntime(runtime.State) {
		return nil, errRuntimeRunning
	}
	// The record naming this tunnel is about to be replaced.
	if runtime.Tunnel.ID != "" {
		if err := s.compensateAllocationTunnel(auth, *runtime); err != nil {
			return nil, err
		}
	}
	s.Logs.Forget(id)
	return s.Create(ctx, CreateRequest{
		ID: id, relaunch: true, SSHHost: runtime.SSHHost, Account: runtime.Account,
		Partition: runtime.Partition, RootFolder: runtime.RootFolder, Resources: runtime.Resources,
	})
}

func (s Service) Stop(ctx context.Context, id string) (*Runtime, error) {
	if !idPattern.MatchString(id) {
		return nil, errInvalidRuntimeID
	}
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var snapshot Runtime
	if err := s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[id]
		if runtime == nil {
			return errRuntimeNotFound
		}
		if runtime.Owner != auth.Principal {
			return errOwnerMismatch
		}
		if !terminalRuntime(runtime.State) {
			runtime.State, runtime.Error, runtime.UpdatedAt = "STOPPING", "", s.now()
			if err := store.save(current); err != nil {
				return err
			}
		}
		snapshot = *runtime
		return nil
	}); err != nil {
		return nil, err
	}
	s.runtimeStatus(id, "Stopping runtime")
	managementErr := s.compensateAllocationTunnel(auth, snapshot)
	candidate := snapshot
	if reconcile(snapshot.State) {
		s.runtimeStatus(id, "Requesting scheduler cancellation")
		// Stop observes the scheduler through the same batched round the
		// background refresher uses, so a stop and a refresh can never disagree
		// about what the scheduler said.
		stopCtx, cancel := context.WithTimeout(context.Background(), s.Runner.EffectiveTimeout())
		candidate = s.reconcileSnapshots(stopCtx, []Runtime{snapshot})[0]
		cancel()
		if candidate.Error != "" {
			s.runtimeStatus(id, "Runtime stop is pending")
		}
	}
	var result *Runtime
	err = s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[id]
		if runtime == nil {
			return errRuntimeNotFound
		}
		changed := mergeReconciled(runtime, &snapshot, &candidate, s.now())
		if managementErr == nil && runtime.Generation == snapshot.Generation && runtime.Tunnel.ID == snapshot.Tunnel.ID {
			runtime.Tunnel = TunnelMetadata{}
			runtime.UpdatedAt = s.now()
			changed = true
		}
		if changed {
			if err := store.save(current); err != nil {
				return err
			}
		}
		result = detached(runtime)
		return nil
	})
	if err == nil && result != nil && result.State == "STOPPED" {
		s.runtimeStatus(id, "Runtime stopped")
	}
	return result, errors.Join(managementErr, err)
}

// Delete removes an allocation the owner is finished with. Stop is the only
// path that releases the job, tunnel, and credentials in the right order, so a
// live allocation is stopped first and a record is only dropped once the
// scheduler has confirmed the job is gone.
func (s Service) Delete(ctx context.Context, id string) (*Runtime, error) {
	stopped, err := s.Stop(ctx, id)
	if err != nil {
		return nil, err
	}
	if stopped == nil || !terminalRuntime(stopped.State) {
		return nil, apierr.New("runtime_not_stopped", "runtime is still stopping; delete it once the scheduler has released the job", http.StatusConflict)
	}
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var deleted *Runtime
	if err := s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[id]
		if runtime == nil {
			return errRuntimeNotFound
		}
		if runtime.Owner != auth.Principal {
			return errOwnerMismatch
		}
		if !terminalRuntime(runtime.State) {
			return apierr.New("runtime_not_stopped", "runtime is no longer stopped", http.StatusConflict)
		}
		deleted = detached(runtime)
		delete(current.Runtimes, id)
		return store.save(current)
	}); err != nil {
		return nil, err
	}
	s.Logs.Forget(id)
	return deleted, s.Credentials.Delete(id, deleted.Generation)
}

func (s Service) prepareRuntime(ctx context.Context, request CreateRequest) (*preparedRuntime, error) {
	request, err := assignRuntimeID(request)
	if err != nil {
		return nil, err
	}
	s.runtimeStatus(request.ID, "Preparing runtime")
	return s.prepareRuntimeAfterContract(ctx, request)
}

func (s Service) prepareRuntimeAfterContract(ctx context.Context, request CreateRequest) (_ *preparedRuntime, resultErr error) {
	defer func() {
		if resultErr != nil {
			s.runtimeStatus(request.ID, "Runtime preparation failed")
		}
	}()
	resource, err := s.Discover(ctx, request.SSHHost)
	if err != nil {
		return nil, fmt.Errorf("discover runtime resource: %w", err)
	}
	if request.Account != "" && !slices.Contains(resource.Accounts, request.Account) {
		return nil, apierr.New("invalid_account", "SLURM account was not discovered for this host", 400)
	}
	if err := validatePartitionResources(resource.Partitions, request.Partition, request.Resources); err != nil {
		return nil, err
	}
	cfg := s.effectiveConfig()
	privateRoot := pathpkg.Join(resource.HomeDir, cfg.RuntimeBase, request.ID)
	if !safeRemotePath(privateRoot) {
		return nil, errors.New("resolved private runtime path is unsafe")
	}
	workspaceRoot, err := s.resolveWorkspaceRoot(ctx, request.SSHHost, resource.HomeDir, request.RootFolder)
	if err != nil {
		return nil, err
	}
	if err := validateWorkspacePrivateLayout(resource.HomeDir, workspaceRoot, privateRoot, request.ID, cfg.RuntimeBase, request.RootFolder); err != nil {
		return nil, err
	}
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: request.ID, SSHHost: request.SSHHost, Account: request.Account, Partition: request.Partition, RootFolder: request.RootFolder, Resources: request.Resources},
		PrivateRoot: privateRoot, WorkspaceRoot: workspaceRoot, HomeDir: resource.HomeDir,
	}
	s.runtimeStatus(request.ID, "Runtime preparation complete")
	linkspan := resolveRemoteExecutable(cfg.LinkspanPath, resource.HomeDir)
	return &preparedRuntime{request: request, runtime: runtime, script: buildScript(runtime, linkspan), linkspan: linkspan}, nil
}

func assignRuntimeID(request CreateRequest) (CreateRequest, error) {
	if err := validateCreate(&request); err != nil {
		return request, err
	}
	if request.ID == "" {
		if request.IdempotencyKey != "" {
			sum := sha256.Sum256([]byte(request.IdempotencyKey))
			request.ID = "rt-" + hex.EncodeToString(sum[:6])
		} else {
			var random [6]byte
			if _, err := rand.Read(random[:]); err != nil {
				return request, err
			}
			request.ID = "rt-" + hex.EncodeToString(random[:])
		}
	}
	if !idPattern.MatchString(request.ID) {
		return request, apierr.New("invalid_runtime_id", "runtime ID must match rt-[a-f0-9]{12}", 400)
	}
	return request, nil
}

func sameCreateRequest(runtime *Runtime, request CreateRequest) bool {
	return runtime.SSHHost == request.SSHHost && runtime.Account == request.Account && runtime.Partition == request.Partition && runtime.RootFolder == request.RootFolder && runtime.Resources == request.Resources
}

// Returns the persisted inventory without scheduler or endpoint I/O, so a read
// answers immediately and reconciliation catches up behind it.
func (s Service) ListCached() ([]Runtime, error) {
	var result []Runtime
	err := s.Store.withLock(func(_ Store, current *state) error {
		result = sortedRuntimeCopies(current)
		return nil
	})
	return result, err
}

// ReconcileAll refreshes every active runtime and conditionally merges the
// result, so concurrent create/stop updates cannot be overwritten by stale I/O.
func (s Service) ReconcileAll(ctx context.Context) error {
	snapshots, err := s.ListCached()
	if err != nil {
		return err
	}
	candidates := s.reconcileSnapshots(ctx, snapshots)
	// A canceled refresh has no authoritative result. Do not even enter the
	// merge lock: the persisted inventory must remain byte-for-byte unchanged.
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.withLock(func(store Store, current *state) error {
		changed := false
		for i := range snapshots {
			runtime := current.Runtimes[snapshots[i].ID]
			if mergeReconciled(runtime, &snapshots[i], &candidates[i], s.now()) {
				changed = true
			}
		}
		if changed {
			return store.save(current)
		}
		return nil
	})
}

func (s Service) GetCached(id string) (*Runtime, error) {
	if !idPattern.MatchString(id) {
		return nil, errInvalidRuntimeID
	}
	var result *Runtime
	err := s.Store.withLock(func(_ Store, current *state) error {
		runtime := current.Runtimes[id]
		if runtime == nil {
			return errRuntimeNotFound
		}
		result = detached(runtime)
		return nil
	})
	return result, err
}

func terminalRuntime(state string) bool {
	return state == "STOPPED" || state == "FAILED"
}

func reconcile(state string) bool {
	return state == "SUBMITTING" || state == "QUEUED" || state == "STARTING" || state == "READY" || state == "STOPPING"
}

func setRuntimeNode(runtime *Runtime, value string) error {
	value = strings.TrimSpace(value)
	if value == "" || value == "(null)" || value == "None assigned" {
		return nil
	}
	if !nodePattern.MatchString(value) {
		return fmt.Errorf("invalid compute node %q", value)
	}
	runtime.Node = value
	return nil
}

// abandonSubmitIntent undoes a runtime that will never reach the scheduler:
// preparing its host failed, or submitting it conclusively did. A stop that
// arrived meanwhile keeps its own outcome, and a relaunch keeps its card.
func (s Service) abandonSubmitIntent(auth authn.TunnelAuthorization, intent Runtime, relaunched bool) error {
	compensateErr := s.compensateAllocationTunnel(auth, intent)
	stateErr := s.Store.withLock(func(store Store, current *state) error {
		currentRuntime := current.Runtimes[intent.ID]
		if currentRuntime == nil || currentRuntime.Generation != intent.Generation || currentRuntime.JobName != intent.JobName || currentRuntime.JobID != "" {
			return nil
		}
		switch currentRuntime.State {
		case "SUBMITTING":
			if !relaunched {
				delete(current.Runtimes, intent.ID)
				break
			}
			currentRuntime.State = "FAILED"
			currentRuntime.Tunnel = TunnelMetadata{}
			currentRuntime.Error = boundedOptionalRuntimeError(compensateErr)
			currentRuntime.UpdatedAt = s.now()
		case "STOPPING":
			currentRuntime.State = "STOPPED"
			currentRuntime.Tunnel = TunnelMetadata{}
			currentRuntime.Error = boundedOptionalRuntimeError(compensateErr)
			currentRuntime.UpdatedAt = s.now()
		default:
			return nil
		}
		return store.save(current)
	})
	return errors.Join(compensateErr, stateErr)
}
