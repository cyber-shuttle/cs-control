// The session state machine.
// Creation is serialized across processes before tunnel side effects, then persists intent before provisioning.
// A conclusive submission failure compensates through abandonSubmitIntent; an ambiguous one stays durable.
// A stop proceeds locally without a usable link: releaseTunnel skips Dev Tunnels when the token is
// empty and leaves the tunnel to its own expiry.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/security"
	"github.com/cyber-shuttle/cs-control/internal/slurm"
)

func assignSessionID(request createRequest, principal security.Principal) (createRequest, error) {
	if err := validateCreate(&request); err != nil {
		return request, err
	}
	if request.ID == "" {
		sum := sha256.Sum256([]byte(security.PrincipalDirName(principal) + "\x00" + request.IdempotencyKey))
		request.ID = "s-" + hex.EncodeToString(sum[:6])
	}
	if !idPattern.MatchString(request.ID) {
		return request, security.New("invalid_session_id", "session ID must match s-[a-f0-9]{12}", http.StatusBadRequest)
	}
	return request, nil
}

func sameCreateRequest(session *Session, request createRequest) bool {
	return session.SSHHost == request.SSHHost && session.Account == request.Account && session.Partition == request.Partition && session.RootFolder == request.RootFolder && session.Resources == request.Resources
}

func (s Service) create(ctx context.Context, request createRequest) (*Session, error) {
	session, _, err := s.createStatus(ctx, request)
	return session, err
}

func (s Service) createStatus(ctx context.Context, request createRequest) (_ *Session, created bool, resultErr error) {
	principal, err := security.PrincipalFromContext(ctx)
	if err != nil {
		return nil, false, err
	}
	request, err = assignSessionID(request, principal)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if resultErr != nil {
			s.forgetUnpersistedBuffers(request.ID)
		}
	}()
	sum := sha256.Sum256([]byte(request.ID))
	slot := int(sum[0]) % len(createLocks)
	lock := &createLocks[slot]
	lock.Lock()
	defer lock.Unlock()
	var result *Session
	resultErr = security.WithFileLock(filepath.Join(s.store.Dir, fmt.Sprintf(".session-create-%02x.lock", slot)), func() error {
		result, err = s.createSerialized(ctx, request, principal, &created)
		return err
	})
	return result, created, resultErr
}

func (s Service) createSerialized(ctx context.Context, request createRequest, principal security.Principal, wasCreated *bool) (*Session, error) {
	reused, err := s.reusableSession(request, principal)
	if err != nil || reused != nil {
		return reused, err
	}
	credential, err := s.tunnelCredentials.Credential(ctx, principal)
	if err != nil {
		return nil, err
	}
	prepared, err := s.prepareSession(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := s.validateForCreate(ctx, request, prepared.script); err != nil {
		return nil, err
	}

	idempotent, previous, err := s.claimCreateSlot(request, principal)
	if err != nil {
		return nil, err
	}
	if idempotent != nil {
		return idempotent, nil
	}
	*wasCreated = true
	operationCtx, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()

	intent := prepared.session
	intent.State, intent.CreatedAt = "SUBMITTING", s.utcNow()
	intent.UpdatedAt = intent.CreatedAt
	nextSeq := 1
	if previous != nil {
		intent.CreatedAt = previous.CreatedAt
		nextSeq = previous.Seq + 1
	}
	record, jupyterToken, err := s.createSessionTunnel(operationCtx, &intent, principal, credential, nextSeq)
	if err != nil {
		return nil, err
	}
	prepared.script = buildScript(intent, prepared.linkspan)
	if err := s.persistSubmitIntent(request.ID, previous, intent); err != nil {
		return nil, errors.Join(err, s.releaseTunnel(credential, intent.ID, intent.Seq, intent.Tunnel))
	}
	if err := s.provisionSession(request.SSHHost, intent, prepared.home, prepared.linkspan); err != nil {
		s.sessionStatus(intent.ID, "Session environment preparation failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(credential, intent, request.relaunch))
	}

	s.sessionStatus(intent.ID, "Submitting session to Slurm")
	jobID, err := s.submitSessionScript(operationCtx, request.SSHHost, intent, prepared.script, jupyterToken, record.HostToken)
	if err != nil {
		if slurm.AmbiguousSubmission(err) {
			s.sessionStatus(intent.ID, "Session submission outcome is unresolved")
			return nil, err
		}
		s.sessionStatus(intent.ID, "Session submission failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(credential, intent, request.relaunch))
	}
	s.sessionStatus(intent.ID, "Session submitted to Slurm")
	created, superseded, err := s.recordSubmittedJob(intent.ID, jobID)
	if err != nil {
		s.sessionStatus(intent.ID, "Session submission could not be saved")
		if cancelErr := s.scancelWithOwnTimeout(request.SSHHost, jobID); cancelErr != nil {
			return nil, fmt.Errorf("%w; compensation scancel failed: %w", err, cancelErr)
		}
		return nil, fmt.Errorf("%w; job was cancelled", err)
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

func (s Service) claimCreateSlot(request createRequest, principal security.Principal) (idempotent, previous *Session, err error) {
	err = s.store.locked(func(current *state) error {
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
			idempotent = detached(existing)
			return nil
		}
		if !request.relaunch {
			return security.New("session_exists", "session ID already exists", http.StatusConflict)
		}
		if !terminalSession(existing.State) {
			return errSessionRunning
		}
		previous = detached(existing)
		return nil
	})
	return idempotent, previous, err
}

func (s Service) persistSubmitIntent(id string, previous *Session, intent Session) error {
	return s.store.locked(func(current *state) error {
		existing := current.Sessions[id]
		same := existing == nil && previous == nil
		if existing != nil && previous != nil {
			same = existing.UpdatedAt.Equal(previous.UpdatedAt) && existing.State == previous.State && existing.Owner == previous.Owner
		}
		if !same {
			return security.New("session_exists", "session ID already exists", http.StatusConflict)
		}
		current.Sessions[intent.ID] = &intent
		if err := s.store.save(current); err != nil {
			return fmt.Errorf("persist submit intent: %w", err)
		}
		return nil
	})
}

func (s Service) reusableSession(request createRequest, principal security.Principal) (*Session, error) {
	if request.IdempotencyKey == "" {
		return nil, nil
	}
	var existing *Session
	err := s.store.locked(func(current *state) error {
		session := current.Sessions[request.ID]
		if session != nil && session.Owner != principal {
			return errOwnerMismatch
		}
		if session == nil {
			return nil
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
	checked, err := slurm.Check(ctx, s.runner, request.SSHHost, script)
	if err == nil && !checked.Passed {
		err = security.New("slurm_validation_failed", validationMessage(checked), http.StatusBadRequest)
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
	err := s.store.locked(func(current *state) error {
		session := current.Sessions[sessionID]
		if session == nil {
			return errors.New("submitted session disappeared from state")
		}
		session.JobID = jobID
		if session.State == "SUBMITTING" {
			session.State = "QUEUED"
		}
		superseded = session.State != "QUEUED"
		session.UpdatedAt = s.utcNow()
		if err := s.store.save(current); err != nil {
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
	_, err := s.runner.Run(ctx, host, nil, "scancel", jobID)
	return err
}

func (s Service) cancelSupersededJob(host, sessionID, jobID string) (*Session, error) {
	diagnostic := ""
	if cancelErr := s.scancelWithOwnTimeout(host, jobID); cancelErr != nil {
		diagnostic = boundedSessionError(cancelErr)
	}
	var result *Session
	err := s.store.locked(func(current *state) error {
		session := current.Sessions[sessionID]
		if session == nil {
			return nil
		}
		if session.JobID == jobID && session.State != "QUEUED" {
			session.Error, session.UpdatedAt = diagnostic, s.utcNow()
			if err := s.store.save(current); err != nil {
				return err
			}
		}
		result = detached(session)
		return nil
	})
	return result, err
}

func (s Service) start(ctx context.Context, id string) (*Session, error) {
	principal, err := security.PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	session, err := s.loadSession(id)
	if err != nil {
		return nil, err
	}
	if session.Owner != principal {
		return nil, errOwnerMismatch
	}
	if !terminalSession(session.State) {
		return nil, errSessionRunning
	}
	if session.Tunnel.ID != "" {
		credential, err := s.tunnelCredentials.Credential(ctx, principal)
		if err != nil {
			return nil, err
		}
		if err := s.releaseTunnel(credential, session.ID, session.Seq, session.Tunnel); err != nil {
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
	principal, err := security.PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	operationCtx, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	var snapshot Session
	var alreadyStopped bool
	if err := s.store.locked(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		if session.Owner != principal {
			return errOwnerMismatch
		}
		alreadyStopped = terminalSession(session.State)
		if !alreadyStopped {
			session.State, session.Error, session.UpdatedAt = "STOPPING", "", s.utcNow()
			if err := s.store.save(current); err != nil {
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
	credential, _ := s.tunnelCredentials.Credential(operationCtx, principal)
	managementErr := s.releaseTunnel(credential, snapshot.ID, snapshot.Seq, snapshot.Tunnel)
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
	err = s.store.locked(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		s.narrateReconciled(session, &snapshot, narration)
		changed := mergeReconciled(session, &snapshot, &candidate, s.utcNow())
		if session.Seq == snapshot.Seq && session.Tunnel.ID == snapshot.Tunnel.ID {
			if managementErr != nil {
				session.Error = boundedSessionError(managementErr)
				session.UpdatedAt = s.utcNow()
				changed = true
			} else if snapshot.Tunnel.ID != "" {
				session.Tunnel = tunnelMetadata{}
				session.UpdatedAt = s.utcNow()
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
			if err := s.store.save(current); err != nil {
				return err
			}
		}
		result = detached(session)
		return freezeErr
	})
	return result, err
}

func (s Service) forgetSessionBuffers(id string) {
	s.logs.forget(id)
	s.metrics.forget(id)
}

func (s Service) forgetUnpersistedBuffers(id string) {
	if _, err := s.loadSession(id); errors.Is(err, errSessionNotFound) {
		s.forgetSessionBuffers(id)
	}
}

func (s Service) delete(ctx context.Context, id string) (*Session, error) {
	principal, err := security.PrincipalFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var deleted *Session
	if err := s.store.locked(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		if session.Owner != principal {
			return errOwnerMismatch
		}
		if !terminalSession(session.State) {
			return security.New("session_not_stopped", "stop the session before deleting it", http.StatusConflict)
		}
		deleted = detached(session)
		delete(current.Sessions, id)
		return s.store.save(current)
	}); err != nil {
		return nil, err
	}
	s.forgetSessionBuffers(id)
	return deleted, deleteCapability(s.capabilityDir, deleted.ID, deleted.Seq)
}

func (s Service) abandonSubmitIntent(credential devtunnel.Credential, intent Session, relaunched bool) error {
	compensateErr := s.releaseTunnel(credential, intent.ID, intent.Seq, intent.Tunnel)
	deleted := false
	stateErr := s.store.locked(func(current *state) error {
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
			currentSession.Error, currentSession.UpdatedAt = sessionError, s.utcNow()
		}
		return s.store.save(current)
	})
	if stateErr == nil && deleted {
		s.forgetSessionBuffers(intent.ID)
	}
	return errors.Join(compensateErr, stateErr)
}
