// Package router owns the process-wide HTTP route registry. Subsystems publish route tables; New unions them,
// refuses duplicate method and path pairs, and serves the result through one mux. The same registry supplies matched
// methods to dispatch and CORS, keeping Allow and preflight behavior aligned with the actual API surface.
package router

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/security"
)

type Routes map[string]map[string]http.HandlerFunc

type Registry struct {
	mux    *http.ServeMux
	routes Routes
}

var ErrNotFound = security.New("not_found", "route not found", http.StatusNotFound)

// MethodNotAllowed answers 405 with the sorted Allow header, for dispatch and preflight alike.
func MethodNotAllowed(writer http.ResponseWriter, methods []string) {
	writer.Header().Set("Allow", strings.Join(methods, ", "))
	security.WriteError(writer, security.New("method_not_allowed", "method not allowed", http.StatusMethodNotAllowed))
}

func New(tables ...Routes) (*Registry, error) {
	registry := &Registry{mux: http.NewServeMux(), routes: Routes{}}
	for _, table := range tables {
		for pattern, handlers := range table {
			registered := registry.routes[pattern]
			if registered == nil {
				registered = map[string]http.HandlerFunc{}
				registry.routes[pattern] = registered
				registry.mux.Handle(pattern, route(registered))
			}
			for method, handler := range handlers {
				if _, exists := registered[method]; exists {
					return nil, fmt.Errorf("route %s %s is registered twice", method, pattern)
				}
				registered[method] = handler
			}
		}
	}
	registry.mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		security.WriteError(writer, ErrNotFound)
	})
	return registry, nil
}

func (r *Registry) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	r.mux.ServeHTTP(writer, request)
}

func (r *Registry) Methods(request *http.Request) ([]string, bool) {
	_, pattern := r.mux.Handler(request)
	handlers := r.routes[pattern]
	return slices.Sorted(maps.Keys(handlers)), handlers != nil
}

func route(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		handler := handlers[request.Method]
		if handler == nil {
			MethodNotAllowed(writer, slices.Sorted(maps.Keys(handlers)))
			return
		}
		handler(writer, request)
	}
}
