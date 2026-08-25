package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/gorilla/websocket"
)

const maxRequestBody = 64 << 10

func ValidateLoopbackListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("csctl serve v1 only listens on an explicit loopback address")
	}
	return nil
}

type HTTPAPI struct {
	Service   Service
	Auth      SSHAuthRoute
	Refresher *RuntimeRefresher
	routes    *http.ServeMux
}

// SSHAuthRoute serves the interactive SSH authentication WebSocket. The router
// names the shape it needs so the runtime domain does not depend on the gateway
// that supplies it.
type SSHAuthRoute interface {
	ServeWebSocket(writer http.ResponseWriter, request *http.Request, alias string)
}

// The only place a control route refuses a method, so 405 is produced once.
func route(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		handler, ok := handlers[request.Method]
		if !ok {
			httpx.WriteError(writer, errMethodNotAllowed)
			return
		}
		handler(writer, request)
	}
}

func requireUpgrade(message string, serve http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !websocket.IsWebSocketUpgrade(request) {
			httpx.WriteError(writer, apierr.New("upgrade_required", message, http.StatusUpgradeRequired))
			return
		}
		serve(writer, request)
	}
}

func NewHTTPHandler(service Service, auth SSHAuthRoute) *HTTPAPI {
	api := &HTTPAPI{Service: service, Auth: auth, Refresher: NewRuntimeRefresher(service)}
	api.routes = api.mux()
	return api
}

// Patterns carry no method, so a literal segment always outranks a wildcard one
// and every method refusal lands in route.
func (a *HTTPAPI) mux() *http.ServeMux {
	mux := http.NewServeMux()
	for pattern, handlers := range map[string]map[string]http.HandlerFunc{
		"/api/v1/ssh":                  {http.MethodGet: answer(http.StatusOK, a.listHosts), http.MethodPost: answer(http.StatusCreated, a.addHost)},
		"/api/v1/ssh/{alias}":          {http.MethodDelete: answer(http.StatusOK, a.removeHost)},
		"/api/v1/ssh/{alias}/auth":     {http.MethodGet: requireUpgrade("SSH authentication requires a WebSocket", a.sshAuth)},
		"/api/v1/ssh/{alias}/slurm":    {http.MethodGet: answer(http.StatusOK, a.discoverSlurm)},
		"/api/v1/ssh/{alias}/test":     {http.MethodPost: answer(http.StatusOK, a.testHost)},
		"/api/v1/runtimes":             {http.MethodGet: answer(http.StatusOK, a.listRuntimes), http.MethodPost: answer(http.StatusCreated, a.createRuntime)},
		"/api/v1/runtimes/script":      {http.MethodPost: answer(http.StatusOK, a.runtimeScript)},
		"/api/v1/runtimes/validate":    {http.MethodPost: answer(http.StatusOK, a.validateRuntime)},
		"/api/v1/runtimes/{id}":        {http.MethodGet: answer(http.StatusOK, a.getRuntime), http.MethodDelete: answer(http.StatusOK, a.deleteRuntime)},
		"/api/v1/runtimes/{id}/start":  {http.MethodPost: answer(http.StatusOK, a.startRuntime)},
		"/api/v1/runtimes/{id}/stop":   {http.MethodPost: answer(http.StatusOK, a.stopRuntime)},
		"/api/v1/runtimes/{id}/access": {http.MethodGet: answer(http.StatusOK, a.runtimeAccess)},
	} {
		mux.Handle(pattern, route(handlers))
	}
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(writer, errRouteNotFound)
	})
	return mux
}

func (a *HTTPAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	a.routes.ServeHTTP(writer, request)
}

func (a *HTTPAPI) Close() { a.Refresher.Close() }

// answer adapts a route that produces a value or a refusal, so writing one or
// the other exists once rather than in every handler.
func answer[T any](status int, produce func(*http.Request) (T, error)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		value, err := produce(request)
		if err != nil {
			httpx.WriteError(writer, err)
			return
		}
		httpx.WriteJSON(writer, status, value)
	}
}

func (a *HTTPAPI) listHosts(*http.Request) (sshconfig.HostList, error) {
	hosts, err := a.Service.SSHConfig().List()
	return sshconfig.HostList{Hosts: hosts}, err
}

func (a *HTTPAPI) addHost(request *http.Request) (sshconfig.Host, error) {
	var add AddHostRequest
	if err := decodeJSON(request, &add); err != nil {
		return sshconfig.Host{}, err
	}
	return a.Service.AddHost(add)
}

func (a *HTTPAPI) removeHost(request *http.Request) (sshconfig.Host, error) {
	return a.Service.RemoveHost(request.PathValue("alias"))
}

func (a *HTTPAPI) testHost(request *http.Request) (HostTest, error) {
	return a.Service.TestHost(request.Context(), request.PathValue("alias"))
}

func (a *HTTPAPI) sshAuth(writer http.ResponseWriter, request *http.Request) {
	if a.Auth == nil {
		httpx.WriteError(writer, apierr.New("ssh_authentication_unavailable", "SSH authentication is unavailable", http.StatusServiceUnavailable))
		return
	}
	a.Auth.ServeWebSocket(writer, request, request.PathValue("alias"))
}

// Abandoning the request cancels this context, which terminates the remote
// process group, so there is no cancellation protocol to speak.
func (a *HTTPAPI) discoverSlurm(request *http.Request) (Resource, error) {
	return a.Service.Discover(request.Context(), request.PathValue("alias"))
}

func (a *HTTPAPI) runtimeScript(request *http.Request) (*RuntimeScript, error) {
	var create CreateRequest
	if err := decodeJSON(request, &create); err != nil {
		return nil, err
	}
	return a.Service.Script(request.Context(), create)
}

func (a *HTTPAPI) validateRuntime(request *http.Request) (*ValidationResult, error) {
	var create CreateRequest
	if err := decodeJSON(request, &create); err != nil {
		return nil, err
	}
	return a.Service.Validate(request.Context(), create)
}

// Answers from persisted state and starts a reconciliation for the next poll to
// collect, so a caller never waits on SSH. Tails are filtered to the same owned
// set as the runtimes: a tail is as private as the runtime that produced it.
func (a *HTTPAPI) listRuntimes(request *http.Request) (RuntimeList, error) {
	runtimes, err := a.Service.ListCached()
	if err != nil {
		return RuntimeList{}, err
	}
	principal, err := requestPrincipal(request)
	if err != nil {
		return RuntimeList{}, err
	}
	owned := runtimesOwnedBy(runtimes, principal)
	return RuntimeList{
		Runtimes:   publicRuntimes(owned),
		Refreshing: a.Refresher.Trigger(),
		Logs:       a.Service.ownedRuntimeTails(owned),
	}, nil
}

func (a *HTTPAPI) createRuntime(request *http.Request) (RuntimeResponse, error) {
	var create CreateRequest
	if err := decodeJSON(request, &create); err != nil {
		return RuntimeResponse{}, err
	}
	runtime, err := a.Service.Create(request.Context(), create)
	if err != nil {
		return RuntimeResponse{}, err
	}
	return RuntimeResponseFrom(*runtime), nil
}

func routedRuntimeID(request *http.Request) (string, error) {
	id := request.PathValue("id")
	if !idPattern.MatchString(id) {
		return "", errRouteNotFound
	}
	return id, nil
}

func (a *HTTPAPI) ownedRuntimeFromRoute(request *http.Request) (*Runtime, error) {
	id, err := routedRuntimeID(request)
	if err != nil {
		return nil, err
	}
	return a.ownedRuntime(request, id)
}

func (a *HTTPAPI) getRuntime(request *http.Request) (RuntimeResponse, error) {
	runtime, err := a.ownedRuntimeFromRoute(request)
	if err != nil {
		return RuntimeResponse{}, err
	}
	a.Refresher.Trigger()
	return RuntimeResponseFrom(*runtime), nil
}

func (a *HTTPAPI) startRuntime(request *http.Request) (RuntimeResponse, error) {
	return a.runtimeAction(request, a.Service.Start)
}

func (a *HTTPAPI) stopRuntime(request *http.Request) (RuntimeResponse, error) {
	return a.runtimeAction(request, a.Service.Stop)
}

func (a *HTTPAPI) deleteRuntime(request *http.Request) (RuntimeResponse, error) {
	return a.runtimeAction(request, a.Service.Delete)
}

// Start, stop, and delete are the same route shape: name a runtime, act on it,
// answer with what it became.
func (a *HTTPAPI) runtimeAction(request *http.Request, act func(context.Context, string) (*Runtime, error)) (RuntimeResponse, error) {
	id, err := routedRuntimeID(request)
	if err != nil {
		return RuntimeResponse{}, err
	}
	runtime, err := act(request.Context(), id)
	if err != nil {
		return RuntimeResponse{}, err
	}
	return RuntimeResponseFrom(*runtime), nil
}

func (a *HTTPAPI) runtimeAccess(request *http.Request) (*RuntimeAccessResponse, error) {
	runtime, err := a.ownedRuntimeFromRoute(request)
	if err != nil {
		return nil, err
	}
	return a.Service.RuntimeAccess(request.Context(), *runtime)
}

func requestPrincipal(request *http.Request) (authn.Principal, error) {
	principal, ok := authn.PrincipalFromContext(request.Context())
	if !ok || !authn.ValidIdentityValue(principal.Subject) || !authn.ValidIdentityValue(principal.Tenant) {
		return authn.Principal{}, apierr.New("oauth_principal_required", "validated OAuth principal is required", http.StatusUnauthorized)
	}
	return principal, nil
}

func runtimesOwnedBy(runtimes []Runtime, principal authn.Principal) []Runtime {
	owned := make([]Runtime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime.Owner == principal {
			owned = append(owned, runtime)
		}
	}
	return owned
}

func (a *HTTPAPI) ownedRuntime(request *http.Request, id string) (*Runtime, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return nil, err
	}
	runtime, err := a.Service.GetCached(id)
	if err != nil {
		return nil, err
	}
	if runtime.Owner != principal {
		return nil, errOwnerMismatch
	}
	return runtime, nil
}

func decodeJSON(request *http.Request, target any) error {
	if request.Body == nil {
		return apierr.New("invalid_json", "request body is required", 400)
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxRequestBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return apierr.New("invalid_json", "request body is invalid", 400)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apierr.New("invalid_json", "request body contains trailing data", 400)
	}
	return nil
}
