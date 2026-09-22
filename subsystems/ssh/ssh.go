// Package ssh owns principal-scoped SSH hosts, keys, rendered configuration, live probes, and authentication. The
// database stores host and key metadata while private keys and generated configs remain protected files. Host/key
// mutations coordinate database, config, and file effects as compensated flows; OpenSSH execution and
// control-master mechanics remain in internal/ssh.
package ssh

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/db"
	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/security"
	internalssh "github.com/cyber-shuttle/cs-control/internal/ssh"
	"github.com/gorilla/websocket"
)

type Service struct {
	Store   Store
	Configs internalssh.Configurations
	Control *internalssh.ControlManager
}

type addHostRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	Key     string `json:"key"`
}

type updateHostRequest struct {
	Command string `json:"command"`
	Key     string `json:"key"`
}

type hostTest struct {
	Host    string `json:"host"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func NewService(database *db.DB, configs internalssh.Configurations, control *internalssh.ControlManager) (*Service, error) {
	if database == nil || configs.Dir == "" || control == nil {
		return nil, errors.New("SSH service dependencies are required")
	}
	if err := security.EnsurePrivateDir(configs.Dir); err != nil {
		return nil, err
	}
	service := &Service{
		Store:   Store{Database: database, PrincipalDir: configs.Dir},
		Configs: configs,
		Control: control,
	}
	if err := service.Store.recoverSSHChanges(); err != nil {
		return nil, err
	}
	if err := service.Store.reconcileConfigs(); err != nil {
		return nil, err
	}
	return service, nil
}

func hostWithCredential(alias, command, key string) (hostEntry, error) {
	host, err := parseCommand(alias, command)
	if err != nil {
		return host, err
	}
	host.Key, host.Managed = key, true
	return host, nil
}

func (s Service) addHost(principal security.Principal, request addHostRequest) (hostEntry, error) {
	host, err := hostWithCredential(strings.TrimSpace(request.Name), request.Command, request.Key)
	if err != nil {
		return hostEntry{}, err
	}
	return s.Store.addHost(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), host)
}

func (s Service) updateHost(principal security.Principal, alias string, request updateHostRequest) (hostEntry, error) {
	host, err := hostWithCredential(alias, request.Command, request.Key)
	if err != nil {
		return hostEntry{}, err
	}
	return s.Store.updateHost(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), host)
}

func (s Service) removeHost(principal security.Principal, alias string) error {
	if !internalssh.ValidAlias(alias) {
		return internalssh.ErrInvalidAlias
	}
	return s.Store.deleteHost(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), alias)
}

func (s Service) testHost(ctx context.Context, principal security.Principal, alias string) (hostTest, error) {
	runner := s.Configs.Runner(principal)
	ctx, cancel := context.WithTimeout(ctx, runner.EffectiveTimeout())
	defer cancel()
	if _, err := runner.Run(ctx, alias, nil, "true"); err != nil {
		if security.For(err).Code == "ssh_authentication_required" {
			return hostTest{Host: alias, Message: "The host answered but wants an interactive login. Authenticate it first."}, nil
		}
		if ctx.Err() != nil {
			return hostTest{Host: alias, Message: "The host did not answer in time."}, nil
		}
		return hostTest{Host: alias, Message: "The SSH connection failed."}, nil
	}
	return hostTest{Host: alias, OK: true, Message: "Connected."}, nil
}

func (s Service) sshRoutes() router.Routes {
	return router.Routes{
		"/api/v1/ssh/hosts": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (hostList, error) {
				hosts, err := s.Store.loadHosts(security.PrincipalDirName(principal))
				return hostList{Hosts: hosts}, err
			}),
			http.MethodPost: security.CreatedAsPrincipal(func(host hostEntry) string { return "/api/v1/ssh/hosts/" + url.PathEscape(host.Name) }, func(principal security.Principal, request *http.Request) (hostEntry, error) {
				var body addHostRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return hostEntry{}, err
				}
				return s.addHost(principal, body)
			}),
		},
		"/api/v1/ssh/hosts/{alias}": {
			http.MethodPut: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (hostEntry, error) {
				var body updateHostRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return hostEntry{}, err
				}
				return s.updateHost(principal, request.PathValue("alias"), body)
			}),
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, request *http.Request) error {
				return s.removeHost(principal, request.PathValue("alias"))
			}),
		},
		"/api/v1/ssh/hosts/{alias}/test": {
			http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (hostTest, error) {
				return s.testHost(request.Context(), principal, request.PathValue("alias"))
			}),
		},
		"/api/v1/ssh/hosts/{alias}/auth": {
			http.MethodGet: func(writer http.ResponseWriter, request *http.Request) {
				principal, err := security.PrincipalFromContext(request.Context())
				if err != nil {
					security.WriteError(writer, err)
					return
				}
				if !websocket.IsWebSocketUpgrade(request) {
					security.WriteError(writer, security.New("upgrade_required", "SSH authentication requires a WebSocket", http.StatusUpgradeRequired))
					return
				}
				s.Control.ServeWebSocket(writer, request, request.PathValue("alias"), s.Configs.Runner(principal))
			},
		},
	}
}

func (s Service) Routes() router.Routes {
	routes := s.sshRoutes()
	maps.Copy(routes, s.keyRoutes())
	return routes
}
