package main

import (
	"context"
	"testing"
)

func TestHelpCommandsExitSuccessfully(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"help"},
		{"resource", "--help"},
		{"resource", "discover", "--help"},
		{"runtime", "--help"},
		{"runtime", "create", "--help"},
		{"runtime", "list", "--help"},
		{"runtime", "get", "--help"},
		{"runtime", "stop", "--help"},
	} {
		if err := run(context.Background(), args); err != nil {
			t.Errorf("run(%q) returned %v", args, err)
		}
	}
}

func TestGetAndStopRejectUnknownOrMisplacedFlags(t *testing.T) {
	for _, args := range [][]string{
		{"runtime", "get", "--unknown", "rt-012345abcdef"},
		{"runtime", "stop", "--unknown", "rt-012345abcdef"},
		{"runtime", "get", "rt-012345abcdef", "--json"},
		{"runtime", "stop", "rt-012345abcdef", "extra"},
	} {
		if err := run(context.Background(), args); err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", args)
		}
	}
}
