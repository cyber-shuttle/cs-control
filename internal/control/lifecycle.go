// The session state machine.
// create persists a durable record first, then provisions and submits, so a poller sees progress as it happens.
// A conclusive submission failure compensates through abandonSubmitIntent; an ambiguous one stays durable.
//
//	assignSessionID, sameCreateRequest, terminalSession, reconcilable, setSessionNode, buildSubmitIntent
//	backgroundInterval, refreshTimeout
//	sessionRefresher, newSessionRefresher
//	tick
//	Trigger
//	Close
//	Service
//	validate, create
//	claimCreateSlot, persistSubmitIntent
//	reusableSession, validateForCreate, recordSubmittedJob, scancelWithOwnTimeout, cancelUnsavedJob, cancelSupersededJob
//	start, stop, forgetSessionBuffers, forgetUnpersistedBuffers, delete
//	prepareSession, resolveWorkspaceRoot
//	loadSessions, reconcileAll, loadSession, abandonSubmitIntent
package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	pathpkg "path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

func assignSessionID(request createRequest) (createRequest, error) {
	if err := validateCreate(&request); err != nil {
		return request, err
	}
	if request.ID == "" {
		sum := sha256.Sum256([]byte(request.IdempotencyKey))
		request.ID = "s-" + hex.EncodeToString(sum[:6])
	}
	if !idPattern.MatchString(request.ID) {
		return request, apierr.New("invalid_session_id", "session ID must match s-[a-f0-9]{12}", http.StatusBadRequest)
	}
	return request, nil
}

func sameCreateRequest(session *Session, request createRequest) bool {
	return session.SSHHost == request.SSHHost && session.Account == request.Account && session.Partition == request.Partition && session.RootFolder == request.RootFolder && session.Resources == request.Resources
}

func terminalSession(state string) bool {
	return state == "STOPPED" || state == "FAILED"
}

func reconcilable(state string) bool {
	return state == "SUBMITTING" || state == "QUEUED" || state == "STARTING" || state == "READY" || state == "STOPPING"
}

func setSessionNode(session *Session, value string) {
	value = strings.TrimSpace(value)
	if value == "" || value == "(null)" || value == "None assigned" || !sshconfig.SafeName(value, 256) {
		return
	}
	session.Node = value
}

func buildSubmitIntent(prepared preparedSession, previous *Session, now time.Time) (Session, int) {
	intent := prepared.session
	intent.State, intent.CreatedAt, intent.UpdatedAt = "SUBMITTING", now, now
	nextSeq := 1
	if previous != nil {
		intent.CreatedAt = previous.CreatedAt
		nextSeq = previous.Seq + 1
	}
	return intent, nextSeq
}

const (
	backgroundInterval = 30 * time.Second
	refreshTimeout     = 60 * time.Second
)

type sessionRefresher struct {
	reconcile func(context.Context) error
	interval  time.Duration
	timeout   time.Duration
	ctx       context.Context
	cancel    context.CancelFunc

	mu        sync.Mutex
	running   bool
	completed time.Time
	wg        sync.WaitGroup
}

func newSessionRefresher(reconcile func(context.Context) error, interval, background time.Duration) *sessionRefresher {
	ctx, cancel := context.WithCancel(context.Background())
	refresher := &sessionRefresher{reconcile: reconcile, interval: interval, timeout: refreshTimeout, ctx: ctx, cancel: cancel}
	refresher.wg.Add(1)
	go refresher.tick(background)
	return refresher
}

func (r *sessionRefresher) tick(every time.Duration) {
	defer r.wg.Done()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.Trigger()
		}
	}
}

func (r *sessionRefresher) Trigger() {
	r.mu.Lock()
	switch {
	case r.ctx.Err() != nil, r.running, time.Since(r.completed) < r.interval:
		r.mu.Unlock()
		return
	}
	r.running = true
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
		defer cancel()
		if err := r.reconcile(ctx); err != nil {
			log.Printf("session reconciliation failed: %v", err)
		}
		r.mu.Lock()
		r.running, r.completed = false, time.Now()
		r.mu.Unlock()
	}()
}

func (r *sessionRefresher) Close() {
	r.cancel()
	r.wg.Wait()
}

func (s Service) validate(ctx context.Context, request createRequest) (*validationResult, error) {
	request, err := assignSessionID(request)
	if err != nil {
		return nil, err
	}
	defer s.forgetUnpersistedBuffers(request.ID)
	prepared, err := s.prepareSession(ctx, request)
	if err != nil {
		return nil, err
	}
	result, err := s.validateScript(ctx, prepared.session.SSHHost, prepared.script)
	if err != nil {
		return nil, err
	}
	return buildValidationResult(prepared, result), nil
}

func (s Service) create(ctx context.Context, request createRequest) (_ *Session, resultErr error) {
	var err error
	request, err = assignSessionID(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			s.forgetUnpersistedBuffers(request.ID)
		}
	}()
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	reused, err := s.reusableSession(request, auth.Principal)
	if err != nil || reused != nil {
		return reused, err
	}
	prepared, err := s.prepareSession(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := s.validateForCreate(ctx, request, prepared.script); err != nil {
		return nil, err
	}

	idempotent, previous, err := s.claimCreateSlot(request, auth.Principal)
	if err != nil {
		return nil, err
	}
	if idempotent != nil {
		return idempotent, nil
	}

	intent, nextSeq := buildSubmitIntent(*prepared, previous, s.now())
	record, jupyterToken, err := s.createSessionTunnel(ctx, &intent, auth, nextSeq)
	if err != nil {
		return nil, err
	}
	prepared.script = buildScript(intent, prepared.linkspan)
	if err := s.persistSubmitIntent(request.ID, previous, intent); err != nil {
		return nil, errors.Join(err, s.releaseSessionTunnel(auth, intent.ID, intent.Seq, intent.Tunnel))
	}

	if err := s.provisionSession(ctx, request.SSHHost, intent, prepared.home, prepared.linkspan); err != nil {
		s.sessionStatus(intent.ID, "Session environment preparation failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(auth, intent, request.relaunch))
	}

	s.sessionStatus(intent.ID, "Submitting session to Slurm")
	jobID, err := s.submitSessionScript(ctx, request.SSHHost, intent, prepared.script, jupyterToken, record.HostToken)
	if err != nil {
		if ambiguousSubmission(err) {
			s.sessionStatus(intent.ID, "Session submission outcome is unresolved")
			return nil, err
		}
		s.sessionStatus(intent.ID, "Session submission failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(auth, intent, request.relaunch))
	}
	s.sessionStatus(intent.ID, "Session submitted to Slurm")
	created, superseded, err := s.recordSubmittedJob(intent.ID, jobID)
	if err != nil {
		s.sessionStatus(intent.ID, "Session submission could not be saved")
		return nil, s.cancelUnsavedJob(request.SSHHost, jobID, err)
	}
	if created.State == "QUEUED" {
		s.sessionStatus(intent.ID, "Session is queued")
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

func (s Service) claimCreateSlot(request createRequest, principal authn.Principal) (idempotent, previous *Session, err error) {
	err = s.Store.withLock(func(current *state) error {
		existing := current.Sessions[request.ID]
		if existing == nil {
			return nil
		}
		if existing.Owner != principal {
			return errOwnerMismatch
		}
		if request.IdempotencyKey != "" {
			if !sameCreateRequest(existing, request) {
				return errIdempotencyConflict
			}
			snapshot := *existing
			idempotent = &snapshot
			return nil
		}
		if !request.relaunch {
			return apierr.New("session_exists", "session ID already exists", http.StatusConflict)
		}
		if !terminalSession(existing.State) {
			return errSessionRunning
		}
		snapshot := *existing
		previous = &snapshot
		return nil
	})
	return idempotent, previous, err
}

func (s Service) persistSubmitIntent(id string, previous *Session, intent Session) error {
	return s.Store.withLock(func(current *state) error {
		existing := current.Sessions[id]
		same := existing == nil && previous == nil
		if existing != nil && previous != nil {
			same = existing.UpdatedAt.Equal(previous.UpdatedAt) && existing.State == previous.State && existing.Owner == previous.Owner
		}
		if !same {
			return apierr.New("session_exists", "session ID already exists", http.StatusConflict)
		}
		current.Sessions[intent.ID] = &intent
		if err := s.Store.save(current); err != nil {
			return fmt.Errorf("persist submit intent: %w", err)
		}
		return nil
	})
}

func (s Service) reusableSession(request createRequest, principal authn.Principal) (*Session, error) {
	if request.IdempotencyKey == "" {
		return nil, nil
	}
	var existing *Session
	err := s.Store.withLock(func(current *state) error {
		session := current.Sessions[request.ID]
		if session == nil {
			return nil
		}
		if session.Owner != principal {
			return errOwnerMismatch
		}
		if !sameCreateRequest(session, request) {
			return errIdempotencyConflict
		}
		existing = detached(session)
		return nil
	})
	return existing, err
}

func (s Service) validateForCreate(ctx context.Context, request createRequest, script string) error {
	s.sessionStatus(request.ID, "Validating session with Slurm")
	checked, err := s.validateScript(ctx, request.SSHHost, script)
	if err == nil && !checked.passed {
		err = apierr.New("slurm_validation_failed", validationMessage(checked), http.StatusBadRequest)
	}
	if err != nil {
		s.sessionStatus(request.ID, "Slurm validation failed")
		return err
	}
	s.sessionStatus(request.ID, "Slurm validation passed")
	return nil
}

func (s Service) recordSubmittedJob(sessionID, jobID string) (*Session, bool, error) {
	var created *Session
	superseded := false
	err := s.Store.withLock(func(current *state) error {
		session := current.Sessions[sessionID]
		if session == nil {
			return errors.New("submitted session disappeared from state")
		}
		session.JobID = jobID
		if session.State == "SUBMITTING" {
			session.State = "QUEUED"
		}
		superseded = session.State != "QUEUED"
		session.UpdatedAt = s.now()
		if err := s.Store.save(current); err != nil {
			return fmt.Errorf("persist submitted job %s: %w", jobID, err)
		}
		created = detached(session)
		return nil
	})
	return created, superseded, err
}

func (s Service) scancelWithOwnTimeout(host, jobID string) error {
	ctx, cancel := s.ownTimeout()
	defer cancel()
	_, err := s.Runner.Run(ctx, host, nil, "scancel", jobID)
	return err
}

func (s Service) cancelUnsavedJob(host, jobID string, saveErr error) error {
	if err := s.scancelWithOwnTimeout(host, jobID); err != nil {
		return fmt.Errorf("%w; compensation scancel failed: %w", saveErr, err)
	}
	return fmt.Errorf("%w; job was cancelled", saveErr)
}

func (s Service) cancelSupersededJob(host, sessionID, jobID string) (*Session, error) {
	diagnostic := ""
	if cancelErr := s.scancelWithOwnTimeout(host, jobID); cancelErr != nil {
		diagnostic = boundedSessionError(cancelErr)
	}
	var result *Session
	err := s.Store.withLock(func(current *state) error {
		session := current.Sessions[sessionID]
		if session == nil {
			return nil
		}
		if session.JobID == jobID && session.State != "QUEUED" {
			session.Error, session.UpdatedAt = diagnostic, s.now()
			if err := s.Store.save(current); err != nil {
				return err
			}
		}
		result = detached(session)
		return nil
	})
	return result, err
}

func (s Service) start(ctx context.Context, id string) (*Session, error) {
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	session, err := s.loadSession(id)
	if err != nil {
		return nil, err
	}
	if session.Owner != auth.Principal {
		return nil, errOwnerMismatch
	}
	if !terminalSession(session.State) {
		return nil, errSessionRunning
	}
	if session.Tunnel.ID != "" {
		if err := s.releaseSessionTunnel(auth, session.ID, session.Seq, session.Tunnel); err != nil {
			return nil, err
		}
	}
	if err := s.freezeRun(session); err != nil {
		return nil, err
	}
	return s.create(ctx, createRequest{
		ID: id, relaunch: true, SSHHost: session.SSHHost, Account: session.Account,
		Partition: session.Partition, RootFolder: session.RootFolder, Resources: session.Resources,
	})
}

func (s Service) stop(ctx context.Context, id string) (*Session, error) {
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var snapshot Session
	var alreadyStopped bool
	if err := s.Store.withLock(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		if session.Owner != auth.Principal {
			return errOwnerMismatch
		}
		alreadyStopped = terminalSession(session.State)
		if !alreadyStopped {
			session.State, session.Error, session.UpdatedAt = "STOPPING", "", s.now()
			if err := s.Store.save(current); err != nil {
				return err
			}
		}
		snapshot = *session
		return nil
	}); err != nil {
		return nil, err
	}
	if !alreadyStopped {
		s.sessionStatus(id, "Stopping session")
	}
	managementErr := s.releaseSessionTunnel(auth, snapshot.ID, snapshot.Seq, snapshot.Tunnel)
	candidate := snapshot
	var narration []string
	if reconcilable(snapshot.State) {
		s.sessionStatus(id, "Requesting scheduler cancellation")
		stopCtx, cancel := s.ownTimeout()
		candidates, lines := s.reconcileSnapshots(stopCtx, []Session{snapshot})
		cancel()
		candidate, narration = candidates[0], lines[0]
		if candidate.Error != "" {
			s.sessionStatus(id, "Session stop is pending")
		}
	}
	var result *Session
	err = s.Store.withLock(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		s.narrateReconciled(session, &snapshot, narration)
		changed := mergeReconciled(session, &snapshot, &candidate, s.now())
		if session.Seq == snapshot.Seq && session.Tunnel.ID == snapshot.Tunnel.ID {
			if managementErr != nil {
				session.Error = boundedSessionError(managementErr)
				session.UpdatedAt = s.now()
				changed = true
			} else if snapshot.Tunnel.ID != "" {
				session.Tunnel = tunnelMetadata{}
				session.UpdatedAt = s.now()
				changed = true
			}
		}
		if session.State == "STOPPED" && !alreadyStopped {
			s.sessionStatus(id, "Session stopped")
		}
		frozen, freezeErr := s.freezeIfTerminal(current, session)
		if frozen {
			changed = true
		}
		if changed {
			if err := s.Store.save(current); err != nil {
				return err
			}
		}
		result = detached(session)
		return freezeErr
	})
	return result, err
}

func (s Service) forgetSessionBuffers(id string) {
	s.Logs.Forget(id)
	s.Metrics.Forget(id)
}

func (s Service) forgetUnpersistedBuffers(id string) {
	if _, err := s.loadSession(id); errors.Is(err, errSessionNotFound) {
		s.forgetSessionBuffers(id)
	}
}

func (s Service) delete(ctx context.Context, id string) (*Session, error) {
	stopped, err := s.stop(ctx, id)
	if err != nil {
		return nil, err
	}
	if stopped == nil || !terminalSession(stopped.State) {
		return nil, apierr.New("session_not_stopped", "session is still stopping; delete it once the scheduler has released the job", http.StatusConflict)
	}
	auth, err := authn.TunnelAuthorizationFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var deleted *Session
	if err := s.Store.withLock(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		if session.Owner != auth.Principal {
			return errOwnerMismatch
		}
		if !terminalSession(session.State) {
			return apierr.New("session_not_stopped", "session is no longer stopped", http.StatusConflict)
		}
		deleted = detached(session)
		delete(current.Sessions, id)
		return s.Store.save(current)
	}); err != nil {
		return nil, err
	}
	return deleted, nil
}

func (s Service) prepareSession(ctx context.Context, request createRequest) (_ *preparedSession, resultErr error) {
	request, err := assignSessionID(request)
	if err != nil {
		return nil, err
	}
	s.sessionStatus(request.ID, "Preparing session")
	defer func() {
		if resultErr != nil {
			status := "Session preparation failed"
			if apierr.For(resultErr).Code == "ssh_authentication_required" {
				status = "Interactive SSH login required"
			}
			s.sessionStatus(request.ID, status)
		}
	}()
	resource, err := s.discover(ctx, request.SSHHost)
	if err != nil {
		return nil, fmt.Errorf("discover session resource: %w", err)
	}
	if request.Account != "" && !slices.Contains(resource.Accounts, request.Account) {
		return nil, apierr.New("invalid_account", "Slurm account was not discovered for this host", http.StatusBadRequest)
	}
	if err := validatePartitionResources(resource.Partitions, request.Partition, request.Resources); err != nil {
		return nil, err
	}
	privateRoot := pathpkg.Join(resource.HomeDir, defaultSessionBase, request.ID)
	if !safeRemotePath(privateRoot) {
		return nil, errors.New("resolved private session path is unsafe")
	}
	workspaceRoot, err := s.resolveWorkspaceRoot(ctx, request.SSHHost, resource.HomeDir, request.RootFolder)
	if err != nil {
		return nil, err
	}
	if err := validateWorkspacePrivateLayout(resource.HomeDir, workspaceRoot, privateRoot, request.ID, request.RootFolder); err != nil {
		return nil, err
	}
	session := Session{
		sessionResponse: sessionResponse{ID: request.ID, SSHHost: request.SSHHost, Account: request.Account, Partition: request.Partition, RootFolder: request.RootFolder, Resources: request.Resources},
		PrivateRoot:     privateRoot, WorkspaceRoot: workspaceRoot,
	}
	s.sessionStatus(request.ID, "Session preparation complete")
	linkspan := resolveRemoteExecutable(s.linkspanPath(), resource.HomeDir)
	return &preparedSession{session: session, script: buildScript(session, linkspan), home: resource.HomeDir, linkspan: linkspan}, nil
}

func (s Service) resolveWorkspaceRoot(ctx context.Context, alias, home, expression string) (string, error) {
	if !validWorkspaceExpression(expression) || !safeRemotePath(home) {
		return "", invalidRootFolder("workspace expression is invalid")
	}
	base, suffix := home, ""
	switch {
	case homeRootExpression(expression):
	case strings.HasPrefix(expression, "/"):
		base = expression
	case strings.HasPrefix(expression, "~/"):
		suffix = strings.TrimPrefix(expression, "~/")
	case workspaceVar.MatchString(expression):
		match := workspaceVar.FindStringSubmatch(expression)
		name := match[1]
		if name == "" {
			name = match[2]
		}
		suffix = match[3]
		if name != "HOME" {
			output, err := s.Runner.Run(ctx, alias, nil, "printenv", name)
			if err != nil {
				return "", invalidRootFolder("workspace environment variable " + name + " is unavailable")
			}
			base, err = oneRemotePath(output)
			if err != nil {
				return "", invalidRootFolder("workspace environment variable " + name + " must contain one absolute safe path")
			}
		}
	default:
		suffix = expression
	}
	resolved := base
	if suffix != "" {
		resolved = pathpkg.Join(base, suffix)
	}
	if !safeRemotePath(resolved) {
		return "", invalidRootFolder("workspace resolves to an unsafe path")
	}
	return resolved, nil
}

func (s Service) loadSessions() ([]Session, error) {
	var result []Session
	err := s.Store.withLock(func(current *state) error {
		result = sortedSessionCopies(current)
		return nil
	})
	return result, err
}

func (s Service) reconcileAll(ctx context.Context) error {
	snapshots, err := s.loadSessions()
	if err != nil {
		return err
	}
	candidates, narration := s.reconcileSnapshots(ctx, snapshots)
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.withLock(func(current *state) error {
		changed := false
		for i := range snapshots {
			session := current.Sessions[snapshots[i].ID]
			s.narrateReconciled(session, &snapshots[i], narration[i])
			if !mergeReconciled(session, &snapshots[i], &candidates[i], s.now()) {
				continue
			}
			changed = true
			_, _ = s.freezeIfTerminal(current, session)
		}
		if changed {
			return s.Store.save(current)
		}
		return nil
	})
}

func (s Service) loadSession(id string) (*Session, error) {
	var result *Session
	err := s.Store.withLock(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		result = detached(session)
		return nil
	})
	return result, err
}

func (s Service) abandonSubmitIntent(auth authn.TunnelAuthorization, intent Session, relaunched bool) error {
	compensateErr := s.releaseSessionTunnel(auth, intent.ID, intent.Seq, intent.Tunnel)
	deleted := false
	stateErr := s.Store.withLock(func(current *state) error {
		currentSession := current.Sessions[intent.ID]
		if currentSession == nil || currentSession.Seq != intent.Seq || currentSession.JobName != intent.JobName || currentSession.JobID != "" {
			return nil
		}
		next := ""
		switch {
		case currentSession.State == "SUBMITTING" && !relaunched:
			delete(current.Sessions, intent.ID)
			deleted = true
		case currentSession.State == "SUBMITTING":
			next = "FAILED"
		case currentSession.State == "STOPPING":
			next = "STOPPED"
		default:
			return nil
		}
		if next != "" {
			currentSession.State, currentSession.Tunnel = next, tunnelMetadata{}
			sessionError := ""
			if compensateErr != nil {
				sessionError = boundedSessionError(compensateErr)
			}
			currentSession.Error, currentSession.UpdatedAt = sessionError, s.now()
		}
		return s.Store.save(current)
	})
	if stateErr == nil && deleted {
		s.forgetSessionBuffers(intent.ID)
	}
	return errors.Join(compensateErr, stateErr)
}
