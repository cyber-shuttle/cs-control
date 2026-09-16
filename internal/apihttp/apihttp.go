// Package apihttp holds the inbound-HTTP primitives every control request and response shares.
// It depends only on apierr, so any layer can render a response without pulling in an outbound client.
//
//	WriteJSONBytes, WriteJSON, WriteError, DecodeStrict
package apihttp

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
)

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
	var api *apierr.APIError
	if !errors.As(err, &api) {
		log.Printf("unclassified error: %v", err)
		api = apierr.For(err)
	}
	WriteJSON(writer, api.Status, apierr.Envelope{Error: api})
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
