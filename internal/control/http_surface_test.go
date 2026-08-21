package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestHTTPRouteSurfaceRetainsOnlyRequiredControlOperations(t *testing.T) {
	configDir := t.TempDir()
	systemConfig := filepath.Join(configDir, "ssh_config")
	if err := os.WriteFile(systemConfig, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	service := Service{
		Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs(),
		Runner: sshexec.Runner{Hosts: sshconfig.Config{UserPath: filepath.Join(configDir, "user_ssh_config"), SystemPath: systemConfig}},
	}
	api := NewHTTPHandler(service, nil)
	t.Cleanup(api.Close)

	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/runtimes/validate"},
		{http.MethodPost, "/api/v1/runtimes"},
		{http.MethodGet, "/api/v1/runtimes"},
		{http.MethodGet, "/api/v1/runtimes/rt-012345abcdef/access"},
		{http.MethodPost, "/api/v1/runtimes/rt-012345abcdef/stop"},
		{http.MethodGet, "/api/v1/ssh"},
		{http.MethodPost, "/api/v1/ssh"},
		{http.MethodDelete, "/api/v1/ssh/delta"},
		{http.MethodPost, "/api/v1/ssh/delta/test"},
		{http.MethodGet, "/api/v1/ssh/delta/auth"},
		{http.MethodGet, "/api/v1/ssh/delta/slurm"},
	} {
		t.Run("retained "+test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			api.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if strings.Contains(response.Body.String(), `"code":"not_found"`) {
				t.Fatalf("retained route %s %s was not dispatched: %d %s", test.method, test.path, response.Code, response.Body.String())
			}
			// This API is bearer-only: no route may start a browser session.
			if cookies := response.Header().Values("Set-Cookie"); len(cookies) != 0 {
				t.Fatalf("route %s %s emitted cookies: %q", test.method, test.path, cookies)
			}
		})
	}
}
