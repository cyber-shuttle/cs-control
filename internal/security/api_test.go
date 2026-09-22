// API errors hide unclassified details, preserve classified failures, and redact bounded UTF-8 text. Request
// decoding rejects unknown fields, trailing data, and oversized bodies while accepting one strict JSON value.
// The truncation case straddles a multi-byte rune at the boundary.
package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUnclassifiedErrorDoesNotCarryItsOwnText(t *testing.T) {
	leaky := errors.New("open /home/u/.cybershuttle/state.json: permission denied")

	api := For(leaky)

	if api.Status != 500 || api.Code != "internal_error" {
		t.Fatalf("got %d %s, want 500 internal_error", api.Status, api.Code)
	}
	if strings.Contains(api.Message, "state.json") {
		t.Errorf("an unclassified error reached the client as its own text: %q", api.Message)
	}

	classified := For(New("invalid_json", "body is not JSON", 400))
	if classified.Code != "invalid_json" || classified.Message != "body is not JSON" || classified.Status != 400 {
		t.Errorf("a subsystem's classified error was rewritten: %+v", classified)
	}
}

func TestRedactTruncatesWithoutSplittingARuneAndHidesSecrets(t *testing.T) {
	filler := strings.Repeat("a", maxRedactedError-len(": ")-1)
	err := Redact("", errors.New(filler+"€"))
	if !utf8.ValidString(err.Error()) {
		t.Fatalf("truncated error message split a rune: %q", err.Error())
	}

	secret := Redact("op", errors.New("token abc123 rejected"), "abc123")
	if strings.Contains(secret.Error(), "abc123") {
		t.Errorf("Redact leaked a secret it was given: %q", secret.Error())
	}
}

func TestRequestBodiesRefuseUnknownFieldsTrailingDataAndOversizeBodies(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	refused := map[string]string{
		"an unknown field":                     `{"name":"a","surprise":1}`,
		"trailing data":                        `{"name":"a"}{}`,
		"over 64 KiB":                          `{"name":"` + strings.Repeat("a", 64<<10) + `"}`,
		"valid JSON plus oversized whitespace": `{"name":"a"}` + strings.Repeat(" ", 64<<10),
	}
	for what, body := range refused {
		var target payload
		err := DecodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &target)

		if api, ok := errors.AsType[*APIError](err); !ok || api.Code != "invalid_json" || api.Status != 400 {
			t.Errorf("%s was accepted; got %v, want 400 invalid_json", what, err)
		}
	}

	var target payload
	if err := DecodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`)), &target); err != nil || target.Name != "a" {
		t.Errorf("a well-formed body was refused: %v", err)
	}
}
