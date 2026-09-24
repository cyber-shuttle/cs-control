// Package session owns session orchestration and its HTTP surface. RunnerProvider supplies principal-scoped
// SSH execution, while TunnelCredentials supplies linked Dev Tunnels credentials; sessions owns the resulting
// state, tunnel, telemetry, and run lifecycles. Every exported operation takes the acting principal explicitly and
// checks ownership itself, so it is usable without HTTP; Routes are one-line adapters over those operations.
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
	ID             string    `json:"-"`
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
	Launcher   string    `json:"launcher"`
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

type linkAccess struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type attachResponse struct {
	Session sessionResponse `json:"session"`
	Link    linkAccess      `json:"link"`
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

const (
	launcherPlane  = "cs-plane"
	launcherClient = "client"
)

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

type Config struct {
	Runners           RunnerProvider
	Store             Store
	LinkspanPath      string
	TunnelManager     TunnelManager
	TunnelCredentials TunnelCredentials
	CapabilityDir     string
	PublicURL         string
	TunnelTimeout     time.Duration
	Origins           security.Origins
}

type Service struct {
	Config
	runner           ssh.Runner
	logs             *sessionLogs
	metrics          *sessionMetrics
	links            *sync.Map
	transport        *http.Transport
	hostPreparations *sync.Map
	now              func() time.Time
	runtime          *sessionRuntime
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

func NewService(config Config) *Service {
	if !safeRemoteExecutable(config.LinkspanPath) {
		config.LinkspanPath = DefaultLinkspanPath
	}
	service := &Service{
		Config: config, logs: newSessionLogs(), metrics: newSessionMetrics(), links: &sync.Map{},
		hostPreparations: &sync.Map{}, now: time.Now, runtime: newSessionRuntime(),
	}
	service.transport = newSessionTransport(service.dialHost)
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
	scoped.runner = s.Runners.Runner(principal)
	return scoped
}

var (
	errSessionNotFound     = security.New("session_not_found", "session not found", http.StatusNotFound)
	errOwnerMismatch       = security.New("session_owner_mismatch", "session is owned by another principal", http.StatusForbidden)
	errSessionRunning      = security.New("session_running", "session is still running; stop it before running it again", http.StatusConflict)
	errIdempotencyConflict = security.New("idempotency_conflict", "idempotency key was already used for another request", http.StatusConflict)
	errServiceStopping     = security.New("service_stopping", "The session service is stopping.", http.StatusServiceUnavailable)
	errSessionHasHistory   = security.New("session_has_history", "session already has a run history", http.StatusConflict)
)

func (s Service) utcNow() time.Time { return s.now().UTC() }

func (s Service) ownTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.runtime.ctx, s.runner.EffectiveTimeout())
}

func (s Service) Close() { s.runtime.close() }

func ifNoneMatch(raw, current string) bool {
	for validator := range strings.SplitSeq(raw, ",") {
		validator = strings.TrimSpace(validator)
		if validator == "*" || strings.TrimPrefix(validator, "W/") == current {
			return true
		}
	}
	return false
}

func (s Service) Get(principal security.Principal, id string) (*Session, error) {
	session, err := s.loadSession(id)
	if err == nil && session.Owner != principal {
		return nil, errOwnerMismatch
	}
	return session, err
}

func (s Service) List(principal security.Principal) (sessionList, error) {
	sessions, err := s.sessionsOf(principal)
	list := sessionList{Sessions: make([]sessionResponse, 0, len(sessions)), Logs: []sessionLogTail{}}
	for _, session := range sessions {
		list.Sessions = append(list.Sessions, session.sessionResponse)
		if tail, ok := s.logs.tail(session.ID); ok {
			list.Logs = append(list.Logs, tail)
		}
	}
	return list, err
}

func (s Service) Discover(ctx context.Context, principal security.Principal, alias string) (resource, error) {
	return s.forPrincipal(principal).discover(ctx, alias)
}

func (s Service) Metrics(principal security.Principal, id string) (sessionSeries, error) {
	session, err := s.Get(principal, id)
	if err != nil {
		return sessionSeries{}, err
	}
	return sessionSeries{SessionID: session.ID, Samples: s.metrics.samples(session.ID)}, nil
}

func view(session *Session, err error) (sessionResponse, error) {
	if err != nil {
		return sessionResponse{}, err
	}
	return session.sessionResponse, nil
}

func decoded[T any](request *http.Request) (T, error) {
	var body T
	return body, security.DecodeJSON(request, &body)
}

func (s Service) defineSession(writer http.ResponseWriter, request *http.Request) {
	principal, err := security.PrincipalFromContext(request.Context())
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	body, err := decoded[createRequest](request)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	session, isNew, err := s.Define(principal, body)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	status := http.StatusOK
	if isNew {
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
	list, err := s.List(principal)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	body, err := json.Marshal(list)
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

type runList struct {
	Runs []Run `json:"runs"`
}

func (s Service) Routes() router.Routes {
	id := func(request *http.Request) string { return request.PathValue("id") }
	return router.Routes{
		"/api/v1/hosts/{alias}/slurm": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (resource, error) {
			return s.Discover(request.Context(), principal, request.PathValue("alias"))
		})},
		"/api/v1/sessions": {http.MethodGet: s.listSessions, http.MethodPost: s.defineSession},
		"/api/v1/sessions/validate": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*validationResult, error) {
			body, err := decoded[createRequest](request)
			if err != nil {
				return nil, err
			}
			return s.Validate(request.Context(), principal, body)
		})},
		"/api/v1/sessions/{id}": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (sessionResponse, error) {
				return view(s.Get(principal, id(request)))
			}),
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, request *http.Request) error {
				_, err := s.Delete(principal, id(request))
				return err
			}),
		},
		"/api/v1/sessions/{id}/start": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (sessionResponse, error) {
			return view(s.Start(request.Context(), principal, id(request)))
		})},
		"/api/v1/sessions/{id}/attach": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*attachResponse, error) {
			return s.Attach(request.Context(), principal, id(request))
		})},
		"/api/v1/sessions/{id}/stop": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (sessionResponse, error) {
			return view(s.Stop(principal, id(request)))
		})},
		"/api/v1/sessions/{id}/runs": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (sessionResponse, error) {
			body, err := decoded[sessionHistory](request)
			if err != nil {
				return sessionResponse{}, err
			}
			return view(s.AdoptRuns(principal, id(request), body))
		})},
		"/api/v1/sessions/{id}/access": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*sessionAccessResponse, error) {
			return s.Access(principal, id(request))
		})},
		"/api/v1/sessions/{id}/ssh": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*sshAccessResponse, error) {
			body, err := decoded[struct {
				PublicKey string `json:"publicKey"`
			}](request)
			if err != nil {
				return nil, err
			}
			return s.StartSSH(request.Context(), principal, id(request), body.PublicKey)
		})},
		"/api/v1/sessions/{id}/metrics": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (sessionSeries, error) {
			return s.Metrics(principal, id(request))
		})},
		"/api/v1/telemetry": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (runList, error) {
			runs, err := s.Runs(principal)
			return runList{Runs: runs}, err
		})},
	}
}
