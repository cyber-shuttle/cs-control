// Package apierr carries the single error shape every subsystem reports and the HTTP layer renders.
// For defaults to an opaque 500, so an unclassified failure never leaks its own message to a client.
//
//	APIError
//	New, Envelope, For, TruncateUTF8
package apierr

import (
	"errors"
	"unicode/utf8"
)

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

func For(err error) *APIError {
	var result *APIError
	if errors.As(err, &result) {
		return result
	}
	return &APIError{Code: "internal_error", Message: "internal error", Status: 500}
}

func TruncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
