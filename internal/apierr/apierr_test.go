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
}

func TestClassifiedErrorKeepsItsCodeAndMessage(t *testing.T) {
	api := For(New("invalid_json", "body is not JSON", 400))

	if api.Code != "invalid_json" || api.Message != "body is not JSON" || api.Status != 400 {
		t.Errorf("a subsystem's classified error was rewritten: %+v", api)
	}
}
