// The registry merges methods on one path, refuses duplicate registrations, and owns JSON 404/405 responses.
package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestRegistryUnionsRoutesAndRefusesAmbiguity(t *testing.T) {
	get := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	post := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusCreated) })
	registry, err := New(
		Routes{"/api/v1/example": {http.MethodGet: get}},
		Routes{"/api/v1/example": {http.MethodPost: post}},
	)
	testutil.Check(t, err)

	for method, status := range map[string]int{http.MethodGet: http.StatusNoContent, http.MethodPost: http.StatusCreated} {
		response := testutil.Serve(registry, httptest.NewRequest(method, "/api/v1/example", nil))
		testutil.Equal(t, response.Code, status, method+" status")
	}
	for _, test := range []struct {
		method string
		path   string
		status int
		code   string
	}{
		{http.MethodDelete, "/api/v1/example", http.StatusMethodNotAllowed, `"code":"method_not_allowed"`},
		{http.MethodGet, "/api/v1/missing", http.StatusNotFound, `"code":"not_found"`},
	} {
		response := testutil.Serve(registry, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
			t.Fatalf("%s %s = %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}

	if _, err := New(Routes{"/api/v1/example": {http.MethodGet: get}}, Routes{"/api/v1/example": {http.MethodGet: get}}); err == nil {
		t.Fatal("duplicate method and path registration was accepted")
	}
}
