// Tests that For hides an unclassified error's own text, and passes a classified error through unchanged.
// Tests that Redact truncates without splitting a rune and never leaks a secret it was given.
//
//	TestUnclassifiedErrorDoesNotCarryItsOwnText
//	TestRedactTruncatesWithoutSplittingARuneAndHidesSecrets
package apierr

import (
	"errors"
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
	// Place a multi-byte rune straddling the truncation boundary, one byte before it.
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
