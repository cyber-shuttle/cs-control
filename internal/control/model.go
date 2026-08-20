// Package control is the runtime domain: the allocation state machine, its
// durable store, scheduler reconciliation, Slurm discovery, the batch script,
// the generation credential store, the bounded runtime log, and the HTTP
// surface that serves them.
//
// Everything it needs from outside is a composed subsystem it never reaches
// past: sshexec runs remote commands, sshconfig reads ~/.ssh/config, devtunnel
// owns the Dev Tunnels API, authn owns identity, gateway serves the SSH
// authentication socket, and safeio, httpx, wsjson, proc and apierr hold the
// primitives they share.
package control

import (
	"regexp"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const (
	stateVersion           = 5
	maxRuntimeError        = 4096
	controlPortDescription = "cybershuttle-control"
	jupyterPortDescription = "cybershuttle-jupyter"
	tunnelCleanupGrace     = 15 * time.Minute
)

var (
	namePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	idPattern         = regexp.MustCompile(`^rt-[a-f0-9]{12}$`)
	jobPattern        = regexp.MustCompile(`^[0-9]+$`)
	nodePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)
	remotePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	workspaceVar      = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})(?:/(.*))?$`)
	workspaceSegment  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

type GRES struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Partition struct {
	Name     string `json:"name"`
	CPUCount int    `json:"cpuCount"`
	MemoryMB int    `json:"memoryMb"`
	GRES     []GRES `json:"gres"`
}

type Resource struct {
	Host       string      `json:"host"`
	Accounts   []string    `json:"accounts"`
	Partitions []Partition `json:"partitions"`
	HomeDir    string      `json:"homeDir"`
}

type Resources struct {
	Cores       int    `json:"cores"`
	MemoryMB    int    `json:"memoryMb"`
	WallMinutes int    `json:"wallMinutes"`
	GPUType     string `json:"gpuType,omitempty"`
	GPUCount    int    `json:"gpuCount,omitempty"`
}

type CreateRequest struct {
	ID             string    `json:"-"`
	IdempotencyKey string    `json:"idempotencyKey,omitempty"`
	SSHHost        string    `json:"sshHost"`
	Account        string    `json:"account,omitempty"`
	Partition      string    `json:"partition"`
	RootFolder     string    `json:"rootFolder"`
	Resources      Resources `json:"resources"`
}

type TunnelMetadata struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"clusterId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RuntimeResponse is the narrow allocation state exposed to browser clients.
// Runtime embeds it, so a field is public exactly when it is declared here and
// the two shapes cannot drift apart.
type RuntimeResponse struct {
	ID         string    `json:"id"`
	Generation string    `json:"generation"`
	State      string    `json:"state"`
	SSHHost    string    `json:"sshHost"`
	Account    string    `json:"account,omitempty"`
	Partition  string    `json:"partition"`
	RootFolder string    `json:"rootFolder"`
	Resources  Resources `json:"resources"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Runtime struct {
	RuntimeResponse
	Owner         authn.Principal `json:"owner"`
	Tunnel        TunnelMetadata  `json:"tunnel"`
	JobID         string          `json:"jobId,omitempty"`
	JobName       string          `json:"jobName"`
	Node          string          `json:"node,omitempty"`
	PrivateRoot   string          `json:"privateRoot"`
	WorkspaceRoot string          `json:"workspaceRoot"`
}

type RuntimeList struct {
	Runtimes   []RuntimeResponse `json:"runtimes"`
	Refreshing bool              `json:"refreshing"`
	Logs       []RuntimeLogTail  `json:"logs"`
}

func RuntimeResponseFrom(runtime Runtime) RuntimeResponse { return runtime.RuntimeResponse }

func publicRuntimes(runtimes []Runtime) []RuntimeResponse {
	result := make([]RuntimeResponse, len(runtimes))
	for index := range runtimes {
		result[index] = RuntimeResponseFrom(runtimes[index])
	}
	return result
}

type RuntimeAccessResponse struct {
	RuntimeID  string               `json:"runtimeId"`
	Generation string               `json:"generation"`
	ExpiresAt  time.Time            `json:"expiresAt"`
	Jupyter    RuntimeJupyterAccess `json:"jupyter"`
}

type RuntimeJupyterAccess struct {
	URI   string `json:"uri"`
	Token string `json:"token"`
}

type ValidationResult struct {
	RuntimeID string `json:"runtimeId"`
	Script    string `json:"script"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
}

type preparedRuntime struct {
	request CreateRequest
	runtime Runtime
	script  string
}

type commandResult struct {
	stdout string
	stderr string
	passed bool
}

type state struct {
	Version  int                 `json:"version"`
	Runtimes map[string]*Runtime `json:"runtimes"`
}

type Config struct {
	LinkspanPath string
	RuntimeBase  string
}

type Store struct {
	Dir      string
	saveHook func(*state) error
}

type Service struct {
	Runner      sshexec.Runner
	Store       Store
	Config      Config
	Logs        *RuntimeLogs
	Tunnels     devtunnel.Manager
	Credentials CredentialStore
	Now         func() time.Time
}

func (s Service) SSHConfig() sshconfig.Config { return s.Runner.Hosts }

func (s Service) effectiveConfig() Config {
	cfg := s.Config
	if !safeRemoteExecutable(cfg.LinkspanPath) {
		cfg.LinkspanPath = "/usr/local/bin/linkspan"
	}
	if cfg.RuntimeBase == "" {
		cfg.RuntimeBase = ".cybershuttle/runtimes"
	}
	return cfg
}

var (
	errRuntimeNotFound  = apierr.New("runtime_not_found", "runtime not found", 404)
	errOwnerMismatch    = apierr.New("runtime_owner_mismatch", "runtime is owned by another principal", 403)
	errInvalidRuntimeID = apierr.New("invalid_runtime_id", "invalid runtime ID", 400)
	errRouteNotFound    = apierr.New("not_found", "route not found", 404)
	errMethodNotAllowed = apierr.New("method_not_allowed", "method not allowed", 405)
)

const restartRecoveryAttempts = 4

var restartRecoveryDelay = 50 * time.Millisecond

// Everything that answers a caller returns one of these, so no response shares
// memory with the state the lock protects.
func detached(runtime *Runtime) *Runtime {
	value := *runtime
	return &value
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
