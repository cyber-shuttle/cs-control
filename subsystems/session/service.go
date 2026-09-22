// Package session owns session orchestration and its HTTP surface. RunnerProvider supplies principal-scoped
// SSH execution, while TunnelCredentials supplies linked Dev Tunnels credentials; sessions owns the resulting
// state, tunnel, telemetry, and run lifecycles. Every handler scopes Service to the authenticated principal before
// invoking those flows.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

const maxSessionError = 4096

var (
	idPattern         = regexp.MustCompile(`^s-[a-f0-9]{12}$`)
	remotePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	workspaceVar      = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})(?:/(.*))?$`)
	workspaceSegment  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	createLocks       [64]sync.Mutex
)

type gres struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type partition struct {
	Name     string `json:"name"`
	CPUCount int    `json:"cpuCount"`
	MemoryMB int    `json:"memoryMb"`
	GRES     []gres `json:"gres"`
}

type resource struct {
	Host       string      `json:"host"`
	Accounts   []string    `json:"accounts"`
	Partitions []partition `json:"partitions"`
	HomeDir    string      `json:"homeDir"`
}

type resources struct {
	Cores       int    `json:"cores"`
	MemoryMB    int    `json:"memoryMb"`
	WallMinutes int    `json:"wallMinutes"`
	GPUType     string `json:"gpuType,omitempty"`
	GPUCount    int    `json:"gpuCount,omitempty"`
}

type createRequest struct {
	ID             string `json:"-"`
	relaunch       bool
	IdempotencyKey string    `json:"idempotencyKey,omitempty"`
	SSHHost        string    `json:"sshHost"`
	Account        string    `json:"account,omitempty"`
	Partition      string    `json:"partition"`
	RootFolder     string    `json:"rootFolder"`
	Resources      resources `json:"resources"`
}

type tunnelMetadata struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"clusterId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type sessionResponse struct {
	ID         string    `json:"id"`
	Seq        int       `json:"seq"`
	State      string    `json:"state"`
	SSHHost    string    `json:"sshHost"`
	Account    string    `json:"account,omitempty"`
	Partition  string    `json:"partition"`
	RootFolder string    `json:"rootFolder"`
	Resources  resources `json:"resources"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Session struct {
	sessionResponse
	Owner         security.Principal `json:"owner"`
	Tunnel        tunnelMetadata     `json:"tunnel"`
	JobID         string             `json:"jobId,omitempty"`
	JobName       string             `json:"jobName"`
	Node          string             `json:"node,omitempty"`
	PrivateRoot   string             `json:"privateRoot"`
	WorkspaceRoot string             `json:"workspaceRoot"`
}

type sessionList struct {
	Sessions []sessionResponse `json:"sessions"`
	Logs     []sessionLogTail  `json:"logs"`
}

type sessionAccessResponse struct {
	SessionID string               `json:"sessionId"`
	Seq       int                  `json:"seq"`
	ExpiresAt time.Time            `json:"expiresAt"`
	Jupyter   sessionJupyterAccess `json:"jupyter"`
}

type sessionJupyterAccess struct {
	URI   string `json:"uri"`
	Token string `json:"token"`
}

type validationResult struct {
	SessionID string `json:"sessionId"`
	Script    string `json:"script"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
}

type state struct {
	Sessions map[string]*Session
	Runs     []runRecord
}

const DefaultLinkspanPath = "$HOME/.cybershuttle/bin/linkspan"

const defaultSessionBase = ".cybershuttle/sessions"

const (
	minCores    = 2
	minMemoryMB = 4096
)

type RunnerProvider interface {
	Runner(principal security.Principal) ssh.Runner
}

type TunnelManager interface {
	Create(context.Context, devtunnel.CreateRequest) (devtunnel.Record, error)
	Get(context.Context, devtunnel.GetRequest) (devtunnel.Record, error)
	Delete(context.Context, devtunnel.DeleteRequest) error
}

type Service struct {
	runner             ssh.Runner
	runners            RunnerProvider
	store              Store
	linkspanExecutable string
	logs               *sessionLogs
	metrics            *sessionMetrics
	tunnelManager      TunnelManager
	tunnelCredentials  TunnelCredentials
	capabilityDir      string
	tunnelTimeout      time.Duration
	hostPreparations   *sync.Map
	now                func() time.Time
	runtime            *sessionRuntime
}

type sessionRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup

	refreshMu        sync.Mutex
	refreshing       bool
	refreshCompleted time.Time
	statsInFlight    atomic.Bool
}

func newSessionRuntime() *sessionRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &sessionRuntime{ctx: ctx, cancel: cancel}
}

func (r *sessionRuntime) begin() (context.Context, func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return nil, nil, false
	}
	r.wg.Add(1)
	ctx, cancel := context.WithCancel(r.ctx)
	return ctx, func() { cancel(); r.wg.Done() }, true
}

func (r *sessionRuntime) start(run func(context.Context)) bool {
	ctx, done, ok := r.begin()
	if !ok {
		return false
	}
	go func() {
		defer done()
		run(ctx)
	}()
	return true
}

// every runs fn on interval until ctx ends.
func every(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}

func (r *sessionRuntime) close() {
	r.mu.Lock()
	r.closing = true
	r.cancel()
	r.mu.Unlock()
	r.wg.Wait()
}

func (s Service) beginOperation() (context.Context, func(), error) {
	operationCtx, done, ok := s.runtime.begin()
	if !ok {
		return nil, nil, errServiceStopping
	}
	return operationCtx, done, nil
}

func NewService(
	runners RunnerProvider,
	store Store,
	linkspanPath string,
	tunnelManager TunnelManager,
	tunnelCredentials TunnelCredentials,
	capabilityDir string,
	tunnelTimeout time.Duration,
) *Service {
	if !safeRemoteExecutable(linkspanPath) {
		linkspanPath = DefaultLinkspanPath
	}
	service := &Service{
		runners: runners, store: store, linkspanExecutable: linkspanPath, logs: newSessionLogs(), metrics: newSessionMetrics(),
		tunnelManager: tunnelManager, tunnelCredentials: tunnelCredentials, capabilityDir: capabilityDir,
		tunnelTimeout: tunnelTimeout, hostPreparations: &sync.Map{}, now: time.Now, runtime: newSessionRuntime(),
	}
	service.runtime.start(func(ctx context.Context) {
		every(ctx, backgroundInterval, func(context.Context) { service.triggerRefresh() })
	})
	service.runtime.start(func(ctx context.Context) { every(ctx, metricSampleInterval, service.sampleAndAccount) })
	return service
}

func terminalSession(state string) bool {
	return state == "STOPPED" || state == "FAILED"
}

func reconcilable(state string) bool {
	return state == "SUBMITTING" || state == "QUEUED" || state == "STARTING" || state == "READY" || state == "STOPPING"
}

func jobName(id string, seq int) string { return "cs-" + id + "-" + strconv.Itoa(seq) }

func boundedSessionError(err error) string {
	return security.TruncateUTF8(strings.ToValidUTF8(err.Error(), "�"), maxSessionError)
}

func detached(session *Session) *Session {
	value := *session
	return &value
}

func (s Service) forPrincipal(principal security.Principal) Service {
	scoped := s
	scoped.runner = s.runners.Runner(principal)
	return scoped
}

var (
	errSessionNotFound     = security.New("session_not_found", "session not found", http.StatusNotFound)
	errOwnerMismatch       = security.New("session_owner_mismatch", "session is owned by another principal", http.StatusForbidden)
	errSessionRunning      = security.New("session_running", "session is still running; stop it before running it again", http.StatusConflict)
	errIdempotencyConflict = security.New("idempotency_conflict", "idempotency key was already used for another request", http.StatusConflict)
	errServiceStopping     = security.New("session_provisioning_failed", "The session service is stopping.", http.StatusServiceUnavailable)
)

func (s Service) utcNow() time.Time { return s.now().UTC() }

func (s Service) ownTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.runtime.ctx, s.runner.EffectiveTimeout())
}

func (s Service) Close() { s.runtime.close() }

func routedSessionID(request *http.Request) (string, error) {
	id := request.PathValue("id")
	if !idPattern.MatchString(id) {
		return "", router.ErrNotFound
	}
	return id, nil
}

// caller and owned are the two session handler shapes: one answers from the principal-scoped service, the other
// answers from it for the routed session that principal owns.
func caller[T any](s Service, produce func(Service, *http.Request) (T, error)) http.HandlerFunc {
	return security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (T, error) {
		return produce(s.forPrincipal(principal), request)
	})
}

func owned[T any](s Service, produce func(Service, context.Context, *Session) (T, error)) http.HandlerFunc {
	return caller(s, func(service Service, request *http.Request) (T, error) {
		var zero T
		principal, err := security.PrincipalFromContext(request.Context())
		if err != nil {
			return zero, err
		}
		id, err := routedSessionID(request)
		if err != nil {
			return zero, err
		}
		session, err := service.loadSession(id)
		if err != nil {
			return zero, err
		}
		if session.Owner != principal {
			return zero, errOwnerMismatch
		}
		return produce(service, request.Context(), session)
	})
}

func sessionAction(act func(Service, context.Context, string) (*Session, error)) func(Service, *http.Request) (sessionResponse, error) {
	return func(service Service, request *http.Request) (sessionResponse, error) {
		id, err := routedSessionID(request)
		if err != nil {
			return sessionResponse{}, err
		}
		session, err := act(service, request.Context(), id)
		if err != nil {
			return sessionResponse{}, err
		}
		return session.sessionResponse, nil
	}
}

func ifNoneMatch(raw, current string) bool {
	for validator := range strings.SplitSeq(raw, ",") {
		validator = strings.TrimSpace(validator)
		if validator == "*" || strings.TrimPrefix(validator, "W/") == current {
			return true
		}
	}
	return false
}

func (s Service) createSession(writer http.ResponseWriter, request *http.Request) {
	principal, err := security.PrincipalFromContext(request.Context())
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	var create createRequest
	if err := security.DecodeJSON(request, &create); err != nil {
		security.WriteError(writer, err)
		return
	}
	session, created, err := s.forPrincipal(principal).createStatus(request.Context(), create)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		writer.Header().Set("Location", "/api/v1/sessions/"+session.ID)
	}
	security.WriteJSON(writer, status, session.sessionResponse)
}

func (s Service) listSessions(writer http.ResponseWriter, request *http.Request) {
	principal, err := security.PrincipalFromContext(request.Context())
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	sessions, err := s.loadSessions()
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	responses := make([]sessionResponse, 0, len(sessions))
	tails := make([]sessionLogTail, 0, len(sessions))
	for _, session := range sessions {
		if session.Owner != principal {
			continue
		}
		responses = append(responses, session.sessionResponse)
		if tail, ok := s.logs.tail(session.ID); ok {
			tails = append(tails, tail)
		}
	}
	body, err := json.Marshal(sessionList{Sessions: responses, Logs: tails})
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("ETag", etag)
	if ifNoneMatch(request.Header.Get("If-None-Match"), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	security.WriteJSONBytes(writer, http.StatusOK, body)
}

func (s Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/ssh/hosts/{alias}/slurm": {http.MethodGet: caller(s, func(service Service, request *http.Request) (resource, error) {
			return service.discover(request.Context(), request.PathValue("alias"))
		})},
		"/api/v1/sessions": {http.MethodGet: s.listSessions, http.MethodPost: s.createSession},
		"/api/v1/sessions/validate": {http.MethodPost: caller(s, func(service Service, request *http.Request) (*validationResult, error) {
			var create createRequest
			if err := security.DecodeJSON(request, &create); err != nil {
				return nil, err
			}
			return service.validate(request.Context(), create)
		})},
		"/api/v1/sessions/{id}": {http.MethodGet: owned(s, func(_ Service, _ context.Context, session *Session) (sessionResponse, error) {
			return session.sessionResponse, nil
		}), http.MethodDelete: security.NoContentAsPrincipal(func(_ security.Principal, request *http.Request) error {
			id, err := routedSessionID(request)
			if err != nil {
				return err
			}
			_, err = s.delete(request.Context(), id)
			return err
		})},
		"/api/v1/sessions/{id}/start": {http.MethodPost: caller(s, sessionAction(Service.start))},
		"/api/v1/sessions/{id}/stop":  {http.MethodPost: caller(s, sessionAction(Service.stop))},
		"/api/v1/sessions/{id}/access": {http.MethodGet: owned(s, func(service Service, ctx context.Context, session *Session) (*sessionAccessResponse, error) {
			return service.sessionAccess(ctx, *session)
		})},
		"/api/v1/sessions/{id}/metrics": {http.MethodGet: owned(s, func(service Service, _ context.Context, session *Session) (sessionSeries, error) {
			return sessionSeries{SessionID: session.ID, Samples: service.metrics.samples(session.ID)}, nil
		})},
	}
}
