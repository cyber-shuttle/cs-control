// Package telemetry owns the read-only run-history route. Session lifecycle remains the sole producer and
// persistence owner of runs; this package only answers the caller's own.
package telemetry

import (
	"net/http"

	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/subsystems/session"
)

type Service struct {
	Sessions *session.Service
}

type list struct {
	Runs []session.Run `json:"runs"`
}

func (s Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/telemetry": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (list, error) {
				runs, err := s.Sessions.ListRuns(principal)
				return list{Runs: runs}, err
			}),
		},
	}
}
