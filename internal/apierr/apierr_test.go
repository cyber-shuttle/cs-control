// Tests that For hides an unclassified error's own text, and passes a classified error through unchanged.
//
//	TestUnclassifiedErrorDoesNotCarryItsOwnText
package apierr

import (
	"errors"
	"strings"
	"testing"
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
