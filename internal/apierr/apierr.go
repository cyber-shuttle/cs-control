// Package apierr carries the single error shape every subsystem reports and
// the HTTP layer renders. It depends on nothing so any subsystem may use it.
package apierr

import "errors"

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string { return e.Message }

func New(code, message string, status int) error {
	return &APIError{Code: code, Message: message, Status: status}
}

type Envelope struct {
	Error *APIError `json:"error"`
}

// For unwraps err to the APIError a subsystem reported, or reports an opaque
// internal error so no subsystem can leak an unclassified message as a 200.
func For(err error) *APIError {
	var result *APIError
	if errors.As(err, &result) {
		return result
	}
	return &APIError{Code: "internal_error", Message: err.Error(), Status: 500}
}
