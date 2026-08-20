package sshconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListMergesSystemUserAndIncludedHostsAndSkipsPatterns(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	includedDir := filepath.Join(dir, "shared")
	user := filepath.Join(sshDir, "config")
	included := filepath.Join(includedDir, "hosts")
	system := filepath.Join(dir, "ssh_config")
	for _, target := range []string{sshDir, includedDir} {
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A wildcard block is a pattern rather than a host and must not be listed.
	if err := os.WriteFile(user, []byte("Include "+included+"\nHost existing\n    HostName old.example\n    User alice\n    Port 2222\n    ProxyJump bastion\n\nHost *.wild\n    User nobody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(included, []byte("Host included\n    HostName included.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(system, []byte("Host system\n    HostName system.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hosts, err := Config{UserPath: user, SystemPath: system}.List()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(hosts))
	for _, host := range hosts {
		names = append(names, host.Name)
	}
	if len(names) != 3 || names[0] != "existing" || names[1] != "included" || names[2] != "system" {
		t.Fatalf("unexpected hosts: %#v", names)
	}
	if hosts[0].Hostname != "old.example" || hosts[0].User != "alice" || hosts[0].Port != 2222 {
		t.Fatalf("unexpected directives: %#v", hosts[0])
	}
	if len(hosts[0].ExtraDirectives) != 1 {
		t.Fatalf("unexpected extra directives: %#v", hosts[0].ExtraDirectives)
	}
}
