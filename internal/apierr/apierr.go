// Package apierr carries the single error shape every subsystem reports and writes it over HTTP.
// For defaults to an opaque 500, so an unclassified failure never leaks its own message to a client.
// Redact is the one place a caller turns a wrapped external error into a bounded, secret-free message.
//
//	maxRedactedError
//	APIError
//	New, Envelope, For, TruncateUTF8, Redact
//	WriteJSONBytes, WriteJSON, WriteError, DecodeStrict
package apierr

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"
)

const maxRedactedError = 2048

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

func Redact(operation string, err error, secrets ...string) error {
	message := operation + ": " + err.Error()
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return errors.New(TruncateUTF8(message, maxRedactedError))
}

func WriteJSONBytes(writer http.ResponseWriter, status int, body []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func WriteJSON(writer http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		return
	}
	WriteJSONBytes(writer, status, body)
}

func WriteError(writer http.ResponseWriter, err error) {
	var api *APIError
	if !errors.As(err, &api) {
		log.Printf("unclassified error: %v", err)
		api = For(err)
	}
	WriteJSON(writer, api.Status, Envelope{Error: api})
}

func DecodeStrict(r io.Reader, target any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}
