// Package security enforces process-wide rules for authenticated identity, guarded HTTP, validated external
// names, and protected local files. Subsystems retain their domain types and compose these mechanisms instead of
// duplicating checks. Classified errors preserve the wire contract; unclassified errors remain opaque, and Redact
// bounds any external failure a caller elects to preserve.
package security

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxCredentialBytes = 16 << 10
	maxRedactedError   = 2048
	maxRequestBody     = 64 << 10
)

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

type Envelope struct {
	Error *APIError `json:"error"`
}

func (e *APIError) Error() string { return e.Message }

func New(code, message string, status int) error {
	return &APIError{Code: code, Message: message, Status: status}
}

func For(err error) *APIError {
	if result, ok := errors.AsType[*APIError](err); ok {
		return result
	}
	return &APIError{Code: "internal_error", Message: "internal error", Status: 500}
}

func DecodeBase64URL(encoded string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return decoded, err == nil && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func ValidCredential(value string) bool {
	return value != "" && len(value) <= MaxCredentialBytes && utf8.ValidString(value) &&
		!strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
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
	if _, ok := errors.AsType[*APIError](err); !ok {
		log.Print("request failed with an unclassified error")
	}
	api := For(err)
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

func asPrincipal[T any](produce func(Principal, *http.Request) (T, error), write func(http.ResponseWriter, T)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, err := PrincipalFromContext(request.Context())
		if err != nil {
			WriteError(writer, err)
			return
		}
		value, err := produce(principal, request)
		if err != nil {
			WriteError(writer, err)
			return
		}
		write(writer, value)
	}
}

// AnswerAsPrincipal, CreatedAsPrincipal and NoContentAsPrincipal are the three handler shapes every subsystem uses:
// a JSON answer, a 201 with Location, and a bodiless 204.
func AnswerAsPrincipal[T any](status int, produce func(Principal, *http.Request) (T, error)) http.HandlerFunc {
	return asPrincipal(produce, func(writer http.ResponseWriter, value T) { WriteJSON(writer, status, value) })
}

func CreatedAsPrincipal[T any](location func(T) string, produce func(Principal, *http.Request) (T, error)) http.HandlerFunc {
	return asPrincipal(produce, func(writer http.ResponseWriter, value T) {
		writer.Header().Set("Location", location(value))
		WriteJSON(writer, http.StatusCreated, value)
	})
}

func NoContentAsPrincipal(act func(Principal, *http.Request) error) http.HandlerFunc {
	return asPrincipal(func(principal Principal, request *http.Request) (struct{}, error) {
		return struct{}{}, act(principal, request)
	},
		func(writer http.ResponseWriter, _ struct{}) { writer.WriteHeader(http.StatusNoContent) })
}

func DecodeJSON(request *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBody+1))
	if err != nil || len(data) > maxRequestBody || DecodeStrict(bytes.NewReader(data), target) != nil {
		return New("invalid_json", "request body is invalid", http.StatusBadRequest)
	}
	return nil
}
