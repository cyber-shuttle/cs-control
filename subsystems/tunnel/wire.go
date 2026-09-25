// The JSON shapes this package's routes read and write, kept in this file alone so clients generate their
// TypeScript types from it with tygo; every other type here is internal.

package tunnel

import "time"

type TunnelLinkStatus struct {
	Linked   bool      `json:"linked"`
	Provider string    `json:"provider,omitempty"`
	Account  string    `json:"account,omitempty"`
	LinkedAt time.Time `json:"linkedAt,omitzero"`
}

type TunnelLinkStart struct {
	Handle           string `json:"handle"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
}

type TunnelLinkPoll struct {
	Status           string `json:"status"`
	IntervalSeconds  int64  `json:"intervalSeconds,omitempty"`
	TunnelLinkStatus `tstype:",extends"`
}

type StartLinkRequest struct {
	Provider string `json:"provider"`
}
