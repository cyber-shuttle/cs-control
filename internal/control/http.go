// The HTTP surface: one *http.ServeMux built once at construction.
// A handler resolves the caller's own Service through forPrincipal, never touching sshconfig directly.
// Ownership is checked against the validated principal the OAuth boundary put in the request context.
//
//	maxRequestBody, sshAuthRoute
//	route, requireUpgrade, writeOrError, answer, caller, requestPrincipal, sessionsOwnedBy, decodeJSON, routedSessionID
//	httpAPI
//	listHosts, decodeAndCall, addHost, updateHost, listKeys, addKey
//	validateSession
//	createSession
//	sessionAction
//	NewHTTPHandler, ValidateLoopbackListen
package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/gorilla/websocket"
)

const maxRequestBody = 64 << 10

type sshAuthRoute interface {
	ServeWebSocket(writer http.ResponseWriter, request *http.Request, alias string, runner sshexec.Runner)
}

func route(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		handler, ok := handlers[request.Method]
		if !ok {
			apierr.WriteError(writer, errMethodNotAllowed)
			return
		}
		handler(writer, request)
	}
}

func requireUpgrade(message string, serve http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !websocket.IsWebSocketUpgrade(request) {
			apierr.WriteError(writer, apierr.New("upgrade_required", message, http.StatusUpgradeRequired))
			return
		}
		serve(writer, request)
	}
}

func writeOrError[T any](writer http.ResponseWriter, status int, value T, err error) {
	if err != nil {
		apierr.WriteError(writer, err)
		return
	}
	apierr.WriteJSON(writer, status, value)
}

func answer[T any](produce func(*http.Request) (T, error)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		value, err := produce(request)
		writeOrError(writer, http.StatusOK, value, err)
	}
}

func caller[T any](a *httpAPI, status int, produce func(Service, *http.Request) (T, error)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		service, err := a.callerService(request)
		var value T
		if err == nil {
			value, err = produce(service, request)
		}
		writeOrError(writer, status, value, err)
	}
}

func requestPrincipal(request *http.Request) (authn.Principal, error) {
	return authn.PrincipalFromContext(request.Context())
}

func sessionsOwnedBy(sessions []Session, principal authn.Principal) []Session {
	owned := make([]Session, 0, len(sessions))
	for _, session := range sessions {
		if session.Owner == principal {
			owned = append(owned, session)
		}
	}
	return owned
}

func decodeJSON(request *http.Request, target any) error {
	if err := apierr.DecodeStrict(io.LimitReader(request.Body, maxRequestBody+1), target); err != nil {
		return apierr.New("invalid_json", "request body is invalid", http.StatusBadRequest)
	}
	return nil
}

func routedSessionID(request *http.Request) (string, error) {
	id := request.PathValue("id")
	if !idPattern.MatchString(id) {
		return "", errRouteNotFound
	}
	return id, nil
}

type httpAPI struct {
	Service   Service
	Auth      sshAuthRoute
	Refresher *sessionRefresher
	Sampler   *sessionSampler
	routes    *http.ServeMux
}

func (a *httpAPI) callerService(request *http.Request) (Service, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return Service{}, err
	}
	return a.Service.forPrincipal(principal), nil
}

func (a *httpAPI) ownedSession(request *http.Request, id string) (*Session, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return nil, err
	}
	session, err := a.Service.loadSession(id)
	if err != nil {
		return nil, err
	}
	if session.Owner != principal {
		return nil, errOwnerMismatch
	}
	return session, nil
}

func (a *httpAPI) ownedSessionFromRoute(request *http.Request) (*Session, error) {
	id, err := routedSessionID(request)
	if err != nil {
		return nil, err
	}
	return a.ownedSession(request, id)
}

func listHosts(service Service, _ *http.Request) (sshconfig.HostList, error) {
	hosts, err := service.sshConfig().List()
	if hosts == nil {
		hosts = []sshconfig.Host{}
	}
	return sshconfig.HostList{Hosts: hosts}, err
}

func decodeAndCall[Req, Res any](request *http.Request, call func(Req) (Res, error)) (Res, error) {
	var body Req
	if err := decodeJSON(request, &body); err != nil {
		var zero Res
		return zero, err
	}
	return call(body)
}

func addHost(service Service, request *http.Request) (sshconfig.Host, error) {
	return decodeAndCall(request, service.addHost)
}

func updateHost(service Service, request *http.Request) (sshconfig.Host, error) {
	alias := request.PathValue("alias")
	return decodeAndCall(request, func(update updateHostRequest) (sshconfig.Host, error) {
		return service.updateHost(alias, update)
	})
}

func listKeys(service Service, _ *http.Request) (sshconfig.KeyList, error) {
	keys, err := service.sshConfig().ListKeys()
	return sshconfig.KeyList{Keys: keys}, err
}

func addKey(service Service, request *http.Request) (sshconfig.Key, error) {
	return decodeAndCall(request, service.addKey)
}

func (a *httpAPI) sshAuth(writer http.ResponseWriter, request *http.Request) {
	service, err := a.callerService(request)
	if err != nil {
		apierr.WriteError(writer, err)
		return
	}
	a.Auth.ServeWebSocket(writer, request, request.PathValue("alias"), service.Runner)
}

func validateSession(service Service, request *http.Request) (*validationResult, error) {
	return decodeAndCall(request, func(create createRequest) (*validationResult, error) {
		return service.validate(request.Context(), create)
	})
}

func (a *httpAPI) ownedSessionList(request *http.Request) ([]byte, error) {
	sessions, err := a.Service.loadSessions()
	if err != nil {
		return nil, err
	}
	principal, err := requestPrincipal(request)
	if err != nil {
		return nil, err
	}
	owned := sessionsOwnedBy(sessions, principal)
	a.Refresher.Trigger()
	return json.Marshal(sessionList{Sessions: public(owned, func(session Session) sessionResponse { return session.sessionResponse }), Logs: a.Service.ownedSessionTails(owned)})
}

func (a *httpAPI) listSessions(writer http.ResponseWriter, request *http.Request) {
	body, err := a.ownedSessionList(request)
	if err != nil {
		apierr.WriteError(writer, err)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("ETag", etag)
	if request.Header.Get("If-None-Match") == etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	apierr.WriteJSONBytes(writer, http.StatusOK, body)
}

func createSession(service Service, request *http.Request) (sessionResponse, error) {
	return decodeAndCall(request, func(create createRequest) (sessionResponse, error) {
		session, err := service.create(request.Context(), create)
		if err != nil {
			return sessionResponse{}, err
		}
		return session.sessionResponse, nil
	})
}

func (a *httpAPI) getSession(request *http.Request) (sessionResponse, error) {
	session, err := a.ownedSessionFromRoute(request)
	if err != nil {
		return sessionResponse{}, err
	}
	a.Refresher.Trigger()
	return session.sessionResponse, nil
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

func (a *httpAPI) listRuns(request *http.Request) (runList, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return runList{}, err
	}
	runs, err := a.Service.listRuns(principal)
	if err != nil {
		return runList{}, err
	}
	return runList{Runs: public(runs, func(run runRecord) runResponse { return run.runResponse })}, nil
}

func (a *httpAPI) getSessionMetrics(request *http.Request) (sessionSeries, error) {
	session, err := a.ownedSessionFromRoute(request)
	if err != nil {
		return sessionSeries{}, err
	}
	return sessionSeries{SessionID: session.ID, Samples: a.Service.Metrics.Series(session.ID)}, nil
}

func (a *httpAPI) sessionAccess(request *http.Request) (*sessionAccessResponse, error) {
	session, err := a.ownedSessionFromRoute(request)
	if err != nil {
		return nil, err
	}
	return a.Service.sessionAccess(request.Context(), *session)
}

func (a *httpAPI) mux() *http.ServeMux {
	mux := http.NewServeMux()
	for pattern, handlers := range map[string]map[string]http.HandlerFunc{
		"/api/v1/ssh": {http.MethodGet: caller(a, http.StatusOK, listHosts), http.MethodPost: caller(a, http.StatusCreated, addHost)},
		"/api/v1/ssh/{alias}": {http.MethodPut: caller(a, http.StatusOK, updateHost), http.MethodDelete: caller(a, http.StatusOK, func(service Service, request *http.Request) (sshconfig.Host, error) {
			return service.removeHost(request.PathValue("alias"))
		})},
		"/api/v1/keys": {http.MethodGet: caller(a, http.StatusOK, listKeys), http.MethodPost: caller(a, http.StatusCreated, addKey)},
		"/api/v1/keys/{name}": {http.MethodDelete: caller(a, http.StatusOK, func(service Service, request *http.Request) (sshconfig.Key, error) {
			name := request.PathValue("name")
			return sshconfig.Key{Name: name}, service.sshConfig().RemoveKey(name)
		})},
		"/api/v1/ssh/{alias}/auth": {http.MethodGet: requireUpgrade("SSH authentication requires a WebSocket", a.sshAuth)},
		"/api/v1/ssh/{alias}/slurm": {http.MethodGet: caller(a, http.StatusOK, func(service Service, request *http.Request) (resource, error) {
			return service.discover(request.Context(), request.PathValue("alias"))
		})},
		"/api/v1/ssh/{alias}/test": {http.MethodPost: caller(a, http.StatusOK, func(service Service, request *http.Request) (hostTest, error) {
			return service.testHost(request.Context(), request.PathValue("alias"))
		})},
		"/api/v1/sessions":                  {http.MethodGet: a.listSessions, http.MethodPost: caller(a, http.StatusCreated, createSession)},
		"/api/v1/sessions/validate":         {http.MethodPost: caller(a, http.StatusOK, validateSession)},
		"/api/v1/sessions/history":          {http.MethodGet: answer(a.listRuns)},
		"/api/v1/sessions/{id}":             {http.MethodGet: answer(a.getSession), http.MethodDelete: caller(a, http.StatusOK, sessionAction(Service.delete))},
		"/api/v1/sessions/{id}/start":       {http.MethodPost: caller(a, http.StatusOK, sessionAction(Service.start))},
		"/api/v1/sessions/{id}/stop":        {http.MethodPost: caller(a, http.StatusOK, sessionAction(Service.stop))},
		"/api/v1/sessions/{id}/access":      {http.MethodGet: answer(a.sessionAccess)},
		"/api/v1/sessions/{id}/metrics":     {http.MethodGet: answer(a.getSessionMetrics)},
		"/api/v1/tunnel/link":               {http.MethodGet: caller(a, http.StatusOK, getTunnelLink), http.MethodDelete: caller(a, http.StatusOK, deleteTunnelLink)},
		"/api/v1/tunnel/link/start":         {http.MethodPost: caller(a, http.StatusOK, startTunnelLink)},
		"/api/v1/tunnel/link/poll/{handle}": {http.MethodPost: caller(a, http.StatusOK, pollTunnelLink)},
	} {
		mux.Handle(pattern, route(handlers))
	}
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		apierr.WriteError(writer, errRouteNotFound)
	})
	return mux
}

func (a *httpAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	a.routes.ServeHTTP(writer, request)
}

func (a *httpAPI) Close() {
	a.Refresher.Close()
	a.Sampler.Close()
}

func NewHTTPHandler(service Service, auth sshAuthRoute) *httpAPI {
	refresher := newSessionRefresher(service.reconcileAll, time.Second, backgroundInterval)
	api := &httpAPI{Service: service, Auth: auth, Refresher: refresher, Sampler: newSessionSampler(service)}
	api.routes = api.mux()
	return api
}

func ValidateLoopbackListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("csctl serve only listens on an explicit loopback address")
	}
	return nil
}
