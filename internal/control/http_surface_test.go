// The HTTP surface's own tests: every route the mux must dispatch, and the shared strict JSON body decoding.
//
//	Test*
package control

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestHTTPRouteSurfaceRetainsRequiredControlOperations(t *testing.T) {
	configDir := t.TempDir()
	service := Service{
		Store: Store{Dir: t.TempDir()}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics(),
		Runner: sshexec.Runner{Hosts: sshconfig.Config{UserPath: filepath.Join(configDir, "user_ssh_config")}},
	}
	api := NewHTTPHandler(service, noopAuth{})
	t.Cleanup(api.Close)

	// Every route is reached with a tunnel-authorized caller and an otherwise empty service, so the
	// status below is what an unknown session or unmanaged host alias produces, not a routing failure.
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodPost, "/api/v1/sessions/validate", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/sessions", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/sessions", http.StatusOK},
		{http.MethodGet, "/api/v1/sessions/s-012345abcdef", http.StatusNotFound},
		{http.MethodDelete, "/api/v1/sessions/s-012345abcdef", http.StatusNotFound},
		{http.MethodGet, "/api/v1/sessions/s-012345abcdef/access", http.StatusNotFound},
		{http.MethodGet, "/api/v1/sessions/s-012345abcdef/metrics", http.StatusNotFound},
		{http.MethodGet, "/api/v1/sessions/history", http.StatusOK},
		{http.MethodPost, "/api/v1/sessions/s-012345abcdef/start", http.StatusNotFound},
		{http.MethodPost, "/api/v1/sessions/s-012345abcdef/stop", http.StatusNotFound},
		{http.MethodGet, "/api/v1/ssh", http.StatusOK},
		{http.MethodPost, "/api/v1/ssh", http.StatusBadRequest},
		{http.MethodPut, "/api/v1/ssh/delta", http.StatusBadRequest},
		{http.MethodDelete, "/api/v1/ssh/delta", http.StatusConflict},
		{http.MethodPost, "/api/v1/ssh/delta/test", http.StatusOK},
		{http.MethodGet, "/api/v1/ssh/delta/auth", http.StatusUpgradeRequired},
		{http.MethodGet, "/api/v1/ssh/delta/slurm", http.StatusNotFound},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil).WithContext(testTunnelContext())
			response := httptest.NewRecorder()
			api.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("route %s %s = %d, want %d: %s", test.method, test.path, response.Code, test.status, response.Body.String())
			}
			if strings.Contains(response.Body.String(), `"code":"not_found"`) {
				t.Fatalf("retained route %s %s was not dispatched: %d %s", test.method, test.path, response.Code, response.Body.String())
			}
			if cookies := response.Header().Values("Set-Cookie"); len(cookies) != 0 {
				t.Fatalf("route %s %s emitted cookies: %q", test.method, test.path, cookies)
			}
		})
	}
}

func TestRequestBodiesRefuseUnknownFieldsTrailingDataAndOversizeBodies(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	refused := map[string]string{
		"an unknown field": `{"name":"a","surprise":1}`,
		"trailing data":    `{"name":"a"}{}`,
		"over 64 KiB":      `{"name":"` + strings.Repeat("a", maxRequestBody) + `"}`,
	}
	for what, body := range refused {
		var target payload
		err := decodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &target)

		var api *apierr.APIError
		if !errors.As(err, &api) || api.Code != "invalid_json" || api.Status != 400 {
			t.Errorf("%s was accepted; got %v, want 400 invalid_json", what, err)
		}
	}

	var target payload
	if err := decodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`)), &target); err != nil || target.Name != "a" {
		t.Errorf("a well-formed body was refused: %v", err)
	}
}
