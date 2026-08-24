package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCommandCarriesTheConnectionAndRefusesTheRest(t *testing.T) {
	host, err := ParseCommand("delta", "ssh -p 2222 -i ~/.ssh/id_ed25519 -J bastion -o StrictHostKeyChecking=accept-new me@login.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	if host.Hostname != "login.example.edu" || host.User != "me" || host.Port != 2222 || host.IdentityFile != "~/.ssh/id_ed25519" {
		t.Fatalf("connection not carried: %+v", host)
	}
	if strings.Join(host.ExtraDirectives, ",") != "ProxyJump bastion,StrictHostKeyChecking accept-new" {
		t.Fatalf("directives not carried: %+v", host.ExtraDirectives)
	}
	// A pasted command must never become a local program or a second line.
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
	if _, err := ParseCommand("bad alias", "ssh host"); err != ErrInvalidAlias {
		t.Fatalf("alias not validated: %v", err)
	}
}

func TestAddAndRemoveTouchOnlyTheManagedBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	const mine = "Host mine\n  HostName mine.example.edu\n"
	if err := os.WriteFile(path, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{UserPath: path, SystemPath: filepath.Join(dir, "absent")}
	added, err := ParseCommand("delta", "ssh me@login.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Add(added); err != nil {
		t.Fatal(err)
	}
	if err := config.Add(added); err == nil {
		t.Fatal("a configured alias was overwritten")
	}
	hosts, err := config.List()
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]bool{}
	for _, host := range hosts {
		state[host.Name] = host.Managed
	}
	if len(hosts) != 2 || !state["delta"] || state["mine"] {
		t.Fatalf("managed state is wrong: %+v", hosts)
	}
	// The user's own entry is never rewritten, and never removable here.
	if err := config.Remove("mine"); err == nil {
		t.Fatal("removed an unmanaged host")
	}
	if err := config.Remove("delta"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), mine) || strings.Contains(string(data), "login.example.edu") {
		t.Fatalf("file lost the user's own entry or kept the removed one:\n%s", data)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config is not private: %v %v", info.Mode(), err)
	}
}
