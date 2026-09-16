// Package control is the session domain: the state machine, its store, reconciliation, discovery, and HTTP surface.
// It reaches outside only through composed subsystems it never bypasses.
// sshexec runs remote commands, sshconfig reads host config, devtunnel owns tunnels, authn owns identity.
//
//	gres, partition, resource
//	resources, createRequest, tunnelMetadata, sessionResponse, Session
//	sessionList, publicSessions
//	sessionAccessResponse, sessionJupyterAccess, validationResult, preparedSession, commandResult, state
//	Config, Store, Service
//	hostConfigDirName, detached
//	addHostRequest
//	hostTest
//	addHost
//	updateHostRequest
//	updateHost
//	removeHost
//	testHost
package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const (
	stateVersion           = 7
	maxSessionError        = 4096
	controlPortDescription = "cybershuttle-control"
	jupyterPortDescription = "cybershuttle-jupyter"
	tunnelCleanupGrace     = 15 * time.Minute
)

var (
	idPattern         = regexp.MustCompile(`^s-[a-f0-9]{12}$`)
	jobPattern        = regexp.MustCompile(`^[0-9]+$`)
	remotePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	workspaceVar      = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})(?:/(.*))?$`)
	workspaceSegment  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
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
	Owner         authn.Principal `json:"owner"`
	Tunnel        tunnelMetadata  `json:"tunnel"`
	JobID         string          `json:"jobId,omitempty"`
	JobName       string          `json:"jobName"`
	Node          string          `json:"node,omitempty"`
	PrivateRoot   string          `json:"privateRoot"`
	WorkspaceRoot string          `json:"workspaceRoot"`
}

type sessionList struct {
	Sessions []sessionResponse `json:"sessions"`
	Logs     []sessionLogTail  `json:"logs"`
}

func publicSessions(sessions []Session) []sessionResponse {
	result := make([]sessionResponse, len(sessions))
	for index := range sessions {
		result[index] = sessions[index].sessionResponse
	}
	return result
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

type preparedSession struct {
	session  Session
	script   string
	home     string
	linkspan string
}

type commandResult struct {
	stdout string
	stderr string
	passed bool
}

type state struct {
	Version  int                 `json:"version"`
	Sessions map[string]*Session `json:"sessions"`
	Runs     []runRecord         `json:"runs,omitempty"`
}

const DefaultLinkspanPath = "$HOME/.cybershuttle/bin/linkspan"

const defaultSessionBase = ".cybershuttle/sessions"

const (
	minCores    = 2
	minMemoryMB = 4096
)

type Config struct {
	LinkspanPath string
	HostsDir     string
}

type Store struct {
	Dir string
}

type Service struct {
	Runner           sshexec.Runner
	Store            Store
	Config           Config
	Logs             *sessionLogs
	Metrics          *sessionMetrics
	Tunnels          devtunnel.Manager
	Credentials      credentialstore.Store
	HostPreparations *sync.Map
	Now              func() time.Time
}

func hostConfigDirName(principal authn.Principal) string {
	sum := sha256.Sum256([]byte(principal.Subject + "\x00" + principal.Tenant))
	return hex.EncodeToString(sum[:16])
}

func detached(session *Session) *Session {
	value := *session
	return &value
}

func (s Service) sshConfig() sshconfig.Config { return s.Runner.Hosts }

func (s Service) forPrincipal(principal authn.Principal) Service {
	scoped := s
	scoped.Runner.Hosts = sshconfig.Config{UserPath: s.hostConfigPath(principal)}
	return scoped
}

func (s Service) hostConfigPath(principal authn.Principal) string {
	if s.Config.HostsDir == "" {
		return os.DevNull
	}
	return filepath.Join(s.Config.HostsDir, hostConfigDirName(principal), "config")
}

func (s Service) linkspanPath() string {
	if !safeRemoteExecutable(s.Config.LinkspanPath) {
		return DefaultLinkspanPath
	}
	return s.Config.LinkspanPath
}

type addHostRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type hostTest struct {
	Host    string `json:"host"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (s Service) addHost(request addHostRequest) (sshconfig.Host, error) {
	host, err := sshconfig.ParseCommand(strings.TrimSpace(request.Name), request.Command)
	if err != nil {
		return sshconfig.Host{}, err
	}
	if err := s.sshConfig().Add(host); err != nil {
		return sshconfig.Host{}, err
	}
	host.Managed = true
	return host, nil
}

type updateHostRequest struct {
	Command string `json:"command"`
}

func (s Service) updateHost(alias string, request updateHostRequest) (sshconfig.Host, error) {
	host, err := sshconfig.ParseCommand(alias, request.Command)
	if err != nil {
		return sshconfig.Host{}, err
	}
	if err := s.sshConfig().Update(host); err != nil {
		return sshconfig.Host{}, err
	}
	host.Managed = true
	return host, nil
}

func (s Service) removeHost(alias string) (sshconfig.Host, error) {
	if err := s.sshConfig().Remove(alias); err != nil {
		return sshconfig.Host{}, err
	}
	return sshconfig.Host{Name: alias, ExtraDirectives: []string{}}, nil
}

func (s Service) testHost(ctx context.Context, alias string) (hostTest, error) {
	if !sshconfig.ValidAlias(alias) {
		return hostTest{}, sshconfig.ErrInvalidAlias
	}
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	if _, err := s.Runner.Run(ctx, alias, nil, "true"); err != nil {
		var classified *apierr.APIError
		if errors.As(err, &classified) && classified.Code == "ssh_authentication_required" {
			return hostTest{Host: alias, Message: "The host answered but wants an interactive login. Authenticate it first."}, nil
		}
		if ctx.Err() != nil {
			return hostTest{Host: alias, Message: "The host did not answer in time."}, nil
		}
		return hostTest{Host: alias, Message: strings.TrimSpace(err.Error())}, nil
	}
	return hostTest{Host: alias, OK: true, Message: "Connected."}, nil
}

var (
	errSessionNotFound     = apierr.New("session_not_found", "session not found", http.StatusNotFound)
	errOwnerMismatch       = apierr.New("session_owner_mismatch", "session is owned by another principal", http.StatusForbidden)
	errSessionRunning      = apierr.New("session_running", "session is still running; stop it before running it again", http.StatusConflict)
	errIdempotencyConflict = apierr.New("idempotency_conflict", "idempotency key was already used for another request", http.StatusConflict)
	errRouteNotFound       = apierr.New("not_found", "route not found", http.StatusNotFound)
	errMethodNotAllowed    = apierr.New("method_not_allowed", "method not allowed", http.StatusMethodNotAllowed)
)

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Store) withLock(fn func(*state) error) error {
	if s.Dir == "" {
		return errors.New("state directory is required")
	}
	return safeio.WithFileLock(filepath.Join(s.Dir, ".lock"), func() error {
		current, err := s.load()
		if err != nil {
			return err
		}
		return fn(current)
	})
}

func (s Store) load() (*state, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &state{Version: stateVersion, Sessions: map[string]*Session{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if current.Version != stateVersion || current.Sessions == nil {
		return nil, errors.New("unsupported state file")
	}
	return &current, nil
}

func (s Store) save(current *state) error {
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	return safeio.ReplaceFile(filepath.Join(s.Dir, "state.json"), append(data, '\n'))
}
