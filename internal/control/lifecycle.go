package control

import (
	"context"
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
	reused, err := s.reusableRuntime(request, auth.Principal)
	if err != nil || reused != nil {
		return reused, err
	}
	prepared, err := s.prepareRuntime(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := s.validateForCreate(ctx, request, prepared.script); err != nil {
		return nil, err
	}

	var intent Runtime
	var record devtunnel.Record
	var jupyterToken string
	idempotent, tunnelCreated := false, false
	err = s.Store.withLock(func(store Store, current *state) error {
		existing := current.Runtimes[request.ID]
		if existing != nil {
			if existing.Owner != auth.Principal {
				return errOwnerMismatch
			}
			if request.IdempotencyKey != "" && sameCreateRequest(existing, request) {
				intent = *existing
				idempotent = true
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
			return fmt.Errorf("persist submit intent: %w", err)
		}
		return nil
	})
	if err != nil {
		if tunnelCreated {
			return nil, errors.Join(err, s.releaseAllocationTunnel(auth, intent.ID, intent.Generation, intent.Tunnel))
		}
		return nil, err
	}
	if idempotent {
		return &intent, nil
	}

	// Installing the interpreter and the binary a first-time host lacks takes
	// minutes. The runtime is already durable, so the reader watching it sees
	// the preparation rather than a request that says nothing until it ends.
	if err := s.provisionRuntime(ctx, request.SSHHost, intent, prepared.home, prepared.linkspan); err != nil {
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
	created, superseded, err := s.recordSubmittedJob(intent.ID, jobID)
	if err != nil {
		s.runtimeStatus(intent.ID, "Runtime submission could not be saved")
		return nil, s.cancelUnsavedJob(ctx, request.SSHHost, jobID, err)
	}
	if created.State == "QUEUED" {
		s.runtimeStatus(intent.ID, "Runtime is queued")
	}
	if !superseded {
		return created, nil
	}
	replaced, err := s.cancelSupersededJob(request.SSHHost, intent.ID, jobID)
	if err != nil {
		return nil, err
	}
	if replaced != nil {
		created = replaced
	}
	return created, nil
}

// reusableRuntime is the runtime an idempotency key already created, and only
// when the same request created it.
func (s Service) reusableRuntime(request CreateRequest, principal authn.Principal) (*Runtime, error) {
	if request.IdempotencyKey == "" {
		return nil, nil
	}
	var existing *Runtime
	err := s.Store.withLock(func(_ Store, current *state) error {
		runtime := current.Runtimes[request.ID]
		if runtime == nil {
			return nil
		}
		if runtime.Owner != principal {
			return errOwnerMismatch
		}
		if !sameCreateRequest(runtime, request) {
			return apierr.New("idempotency_conflict", "idempotency key was already used for another request", 409)
		}
		existing = detached(runtime)
		return nil
	})
	return existing, err
}

func (s Service) validateForCreate(ctx context.Context, request CreateRequest, script string) error {
	s.runtimeStatus(request.ID, "Validating runtime with Slurm")
	checked, err := s.validateScript(ctx, request.SSHHost, script)
	if err == nil && !checked.passed {
		err = apierr.New("slurm_validation_failed", validationMessage(checked), 400)
	}
	if err != nil {
		s.runtimeStatus(request.ID, "Slurm validation failed")
		return err
	}
	s.runtimeStatus(request.ID, "Slurm validation passed")
	return nil
}

// recordSubmittedJob attaches the job to its durable record, and reports a record
// that moved on without it: that job goes rather than runs on.
func (s Service) recordSubmittedJob(runtimeID, jobID string) (*Runtime, bool, error) {
	var created *Runtime
	superseded := false
	err := s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[runtimeID]
		if runtime == nil {
			return errors.New("submitted runtime disappeared from state")
		}
		runtime.JobID = jobID
		if runtime.State == "SUBMITTING" {
			runtime.State = "QUEUED"
		}
		superseded = runtime.State != "QUEUED"
		runtime.UpdatedAt = s.now()
		if err := store.save(current); err != nil {
			return fmt.Errorf("persist submitted job %s: %w", jobID, err)
		}
		created = detached(runtime)
		return nil
	})
	return created, superseded, err
}

// cancelUnsavedJob gives back a job no record now names.
func (s Service) cancelUnsavedJob(ctx context.Context, host, jobID string, saveErr error) error {
	if _, err := s.Runner.Run(ctx, host, nil, "scancel", jobID); err != nil {
		return fmt.Errorf("%w; compensation scancel failed: %v", saveErr, err)
	}
	return fmt.Errorf("%w; job was cancelled", saveErr)
}

// cancelSupersededJob cancels a job its record has already moved past. Stop may
// win while sbatch is in flight, before a job ID exists, so the cancellation
// happens before Create returns rather than at a later poll.
func (s Service) cancelSupersededJob(host, runtimeID, jobID string) (*Runtime, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Runner.EffectiveTimeout())
	_, cancelErr := s.Runner.Run(ctx, host, nil, "scancel", jobID)
	cancel()
	diagnostic := ""
	if cancelErr != nil {
		diagnostic = cancelErr.Error()
	}
	var result *Runtime
	err := s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[runtimeID]
		if runtime == nil {
			return nil
		}
		if runtime.JobID == jobID && runtime.State != "QUEUED" {
			runtime.Error, runtime.UpdatedAt = diagnostic, s.now()
			if err := store.save(current); err != nil {
				return err
			}
		}
		// A concurrent terminal update wins both persistence and the response:
		// cancellation diagnostics never revive stale state.
		result = detached(runtime)
		return nil
	})
	return result, err
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
		if err := s.releaseAllocationTunnel(auth, runtime.ID, runtime.Generation, runtime.Tunnel); err != nil {
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
	managementErr := s.releaseAllocationTunnel(auth, snapshot.ID, snapshot.Generation, snapshot.Tunnel)
	candidate := snapshot
	var narration []string
	if reconcile(snapshot.State) {
		s.runtimeStatus(id, "Requesting scheduler cancellation")
		// Stop observes the scheduler through the refresher's own batched round,
		// so the two can never disagree about what it said.
		stopCtx, cancel := context.WithTimeout(context.Background(), s.Runner.EffectiveTimeout())
		candidates, lines := s.reconcileSnapshots(stopCtx, []Runtime{snapshot})
		cancel()
		candidate, narration = candidates[0], lines[0]
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
		s.narrateReconciled(runtime, &snapshot, narration)
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

// Delete removes an allocation the owner is finished with. Stop is the only path
// that releases job, tunnel and credentials in the right order, so a live
// allocation is stopped first and dropped only once the job is confirmed gone.
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

func (s Service) prepareRuntime(ctx context.Context, request CreateRequest) (_ *preparedRuntime, resultErr error) {
	request, err := assignRuntimeID(request)
	if err != nil {
		return nil, err
	}
	s.runtimeStatus(request.ID, "Preparing runtime")
	defer func() {
		if resultErr != nil {
			status := "Runtime preparation failed"
			if apierr.For(resultErr).Code == "ssh_authentication_required" {
				status = "Interactive SSH login required"
			}
			s.runtimeStatus(request.ID, status)
		}
	}()
	resource, err := s.Discover(ctx, request.SSHHost)
	if err != nil {
		return nil, fmt.Errorf("discover runtime resource: %w", err)
	}
	if request.Account != "" && !slices.Contains(resource.Accounts, request.Account) {
		return nil, apierr.New("invalid_account", "Slurm account was not discovered for this host", 400)
	}
	if err := validatePartitionResources(resource.Partitions, request.Partition, request.Resources); err != nil {
		return nil, err
	}
	privateRoot := pathpkg.Join(resource.HomeDir, defaultRuntimeBase, request.ID)
	if !safeRemotePath(privateRoot) {
		return nil, errors.New("resolved private runtime path is unsafe")
	}
	workspaceRoot, err := s.resolveWorkspaceRoot(ctx, request.SSHHost, resource.HomeDir, request.RootFolder)
	if err != nil {
		return nil, err
	}
	if err := validateWorkspacePrivateLayout(resource.HomeDir, workspaceRoot, privateRoot, request.ID, request.RootFolder); err != nil {
		return nil, err
	}
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: request.ID, SSHHost: request.SSHHost, Account: request.Account, Partition: request.Partition, RootFolder: request.RootFolder, Resources: request.Resources},
		PrivateRoot:     privateRoot, WorkspaceRoot: workspaceRoot,
	}
	s.runtimeStatus(request.ID, "Runtime preparation complete")
	linkspan := resolveRemoteExecutable(s.effectiveConfig().LinkspanPath, resource.HomeDir)
	return &preparedRuntime{request: request, runtime: runtime, script: buildScript(runtime, linkspan), home: resource.HomeDir, linkspan: linkspan}, nil
}

func assignRuntimeID(request CreateRequest) (CreateRequest, error) {
	if err := validateCreate(&request); err != nil {
		return request, err
	}
	if request.ID == "" {
		sum := sha256.Sum256([]byte(request.IdempotencyKey))
		request.ID = "rt-" + hex.EncodeToString(sum[:6])
	}
	if !idPattern.MatchString(request.ID) {
		return request, apierr.New("invalid_runtime_id", "runtime ID must match rt-[a-f0-9]{12}", 400)
	}
	return request, nil
}

func sameCreateRequest(runtime *Runtime, request CreateRequest) bool {
	return runtime.SSHHost == request.SSHHost && runtime.Account == request.Account && runtime.Partition == request.Partition && runtime.RootFolder == request.RootFolder && runtime.Resources == request.Resources
}

// ListCached returns the persisted inventory without scheduler or endpoint I/O,
// so a read answers immediately and reconciliation catches up behind it.
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
	candidates, narration := s.reconcileSnapshots(ctx, snapshots)
	// A canceled refresh has no authoritative result, so it must not even enter
	// the merge lock.
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.withLock(func(store Store, current *state) error {
		changed := false
		for i := range snapshots {
			runtime := current.Runtimes[snapshots[i].ID]
			s.narrateReconciled(runtime, &snapshots[i], narration[i])
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

func setRuntimeNode(runtime *Runtime, value string) {
	value = strings.TrimSpace(value)
	if value == "" || value == "(null)" || value == "None assigned" || !nodePattern.MatchString(value) {
		return
	}
	runtime.Node = value
}

// abandonSubmitIntent undoes a runtime that will never reach the scheduler. A
// stop that arrived meanwhile keeps its outcome, and a relaunch keeps its card.
func (s Service) abandonSubmitIntent(auth authn.TunnelAuthorization, intent Runtime, relaunched bool) error {
	compensateErr := s.releaseAllocationTunnel(auth, intent.ID, intent.Generation, intent.Tunnel)
	stateErr := s.Store.withLock(func(store Store, current *state) error {
		currentRuntime := current.Runtimes[intent.ID]
		if currentRuntime == nil || currentRuntime.Generation != intent.Generation || currentRuntime.JobName != intent.JobName || currentRuntime.JobID != "" {
			return nil
		}
		next := ""
		switch {
		case currentRuntime.State == "SUBMITTING" && !relaunched:
			delete(current.Runtimes, intent.ID)
		case currentRuntime.State == "SUBMITTING":
			next = "FAILED"
		case currentRuntime.State == "STOPPING":
			next = "STOPPED"
		default:
			return nil
		}
		if next != "" {
			currentRuntime.State, currentRuntime.Tunnel = next, TunnelMetadata{}
			currentRuntime.Error, currentRuntime.UpdatedAt = boundedOptionalRuntimeError(compensateErr), s.now()
		}
		return store.save(current)
	})
	return errors.Join(compensateErr, stateErr)
}
