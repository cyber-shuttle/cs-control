// The Dev Tunnels link routes: behind the boundary, the caller's principal is already known, so these are thin
// compositions over Service.TunnelLinks that answer the shapes docs/API.md's "Dev Tunnels link" section names.
//
//	startLinkRequest, pendingLink
//	getTunnelLink
//	startTunnelLink
//	pollTunnelLink
//	deleteTunnelLink
package control

import (
	"net/http"

	"github.com/cyber-shuttle/cs-control/internal/authn"
)

type startLinkRequest struct {
	Provider string `json:"provider"`
}

type pendingLink struct {
	Status          string `json:"status"`
	IntervalSeconds int64  `json:"intervalSeconds"`
}

func getTunnelLink(service Service, request *http.Request) (authn.TunnelLinkStatus, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return authn.TunnelLinkStatus{}, err
	}
	return service.TunnelLinks.Status(principal)
}

func startTunnelLink(service Service, request *http.Request) (authn.TunnelLinkStart, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return authn.TunnelLinkStart{}, err
	}
	var start startLinkRequest
	if err := decodeJSON(request, &start); err != nil {
		return authn.TunnelLinkStart{}, err
	}
	return service.TunnelLinks.Start(request.Context(), principal, start.Provider)
}

func pollTunnelLink(service Service, request *http.Request) (any, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return nil, err
	}
	poll, err := service.TunnelLinks.Poll(request.Context(), principal, request.PathValue("handle"))
	if err != nil || !poll.Pending {
		return poll.Status, err
	}
	return pendingLink{Status: "pending", IntervalSeconds: poll.IntervalSeconds}, nil
}

func deleteTunnelLink(service Service, request *http.Request) (authn.TunnelLinkStatus, error) {
	principal, err := requestPrincipal(request)
	if err != nil {
		return authn.TunnelLinkStatus{}, err
	}
	return authn.TunnelLinkStatus{}, service.TunnelLinks.Delete(principal)
}
