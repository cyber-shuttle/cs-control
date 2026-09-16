// Tests that ParseCommand and the managed-block edits touch only what they own.
//
//	TestParseCommandCarriesTheConnectionAndRefusesTheRest, TestAddAndRemoveTouchOnlyTheManagedBlock
//	TestUpdateRewritesOneManagedEntryInPlace
package sshconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestParseCommandCarriesTheConnectionAndRefusesTheRest(t *testing.T) {
	host, err := ParseCommand("delta", "ssh -p 2222 -i ~/.ssh/id_ed25519 -J bastion -o StrictHostKeyChecking=accept-new me@login.example.edu")
	testutil.Check(t, err)
	if host.Hostname != "login.example.edu" || host.User != "me" || host.Port != 2222 || host.IdentityFile != "~/.ssh/id_ed25519" {
		t.Fatalf("connection not carried: %+v", host)
	}
	if strings.Join(host.ExtraDirectives, ",") != "ProxyJump bastion,StrictHostKeyChecking accept-new" {
		t.Fatalf("directives not carried: %+v", host.ExtraDirectives)
	}
	for _, command := range []string{
		"ssh -o ProxyCommand=nc\\ evil\\ 22 host",
		"ssh -o LocalCommand=id host",
		"ssh host uptime",
		"ssh -D 1080 host",
		"ssh",
	} {
		if _, err := ParseCommand("delta", command); err == nil {
			t.Fatalf("accepted %q", command)
		}
	}
	if _, err := ParseCommand("bad alias", "ssh host"); !errors.Is(err, ErrInvalidAlias) {
		t.Fatalf("alias not validated: %v", err)
	}
}

func TestAddAndRemoveTouchOnlyTheManagedBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	const mine = "Host mine\n  HostName mine.example.edu\n"
	testutil.Check(t, os.WriteFile(path, []byte(mine), 0o600))
	config := Config{UserPath: path}
	added, err := ParseCommand("delta", "ssh me@login.example.edu")
	testutil.Check(t, err)
	testutil.Check(t, config.Add(added))
	if err := config.Add(added); err == nil {
		t.Fatal("a configured alias was overwritten")
	}
	hosts, err := config.List()
	testutil.Check(t, err)
	state := map[string]bool{}
	for _, host := range hosts {
		state[host.Name] = host.Managed
	}
	if len(hosts) != 2 || !state["delta"] || state["mine"] {
		t.Fatalf("managed state is wrong: %+v", hosts)
	}
	if err := config.Remove("mine"); err == nil {
		t.Fatal("removed an unmanaged host")
	}
	testutil.Check(t, config.Remove("delta"))
	data, err := os.ReadFile(path)
	testutil.Check(t, err)
	if !strings.HasPrefix(string(data), mine) || strings.Contains(string(data), "login.example.edu") {
		t.Fatalf("file lost the user's own entry or kept the removed one:\n%s", data)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config is not private: %v %v", info.Mode(), err)
	}
}

func TestUpdateRewritesOneManagedEntryInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	config := Config{UserPath: path}
	for _, command := range []struct{ alias, command string }{
		{"delta", "ssh me@login.example.edu"},
		{"anvil", "ssh me@anvil.example.edu"},
	} {
		host, err := ParseCommand(command.alias, command.command)
		testutil.Check(t, err)
		testutil.Check(t, config.Add(host))
	}
	edited, err := ParseCommand("delta", "ssh -p 2222 -i ~/.ssh/id_ed25519 -J bastion you@login2.example.edu")
	testutil.Check(t, err)
	testutil.Check(t, config.Update(edited))
	hosts, err := config.List()
	testutil.Check(t, err)
	byName := map[string]Host{}
	for _, host := range hosts {
		byName[host.Name] = host
	}
	if len(hosts) != 2 {
		t.Fatalf("an edit changed the entry count: %+v", hosts)
	}
	if got := byName["delta"]; got.Hostname != "login2.example.edu" || got.User != "you" || got.Port != 2222 || !got.Managed {
		t.Fatalf("delta was not rewritten: %+v", got)
	}
	if got := byName["anvil"]; got.Hostname != "anvil.example.edu" || got.User != "me" {
		t.Fatalf("editing one entry disturbed another: %+v", got)
	}
	if err := config.Update(Host{Name: "absent"}); err == nil {
		t.Fatal("updated an entry this package never wrote")
	}
}
