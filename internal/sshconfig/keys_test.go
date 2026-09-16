// Tests that stored login keys are validated, listed, assigned through the managed stanza, and unassigned on removal.
//
//	testKey
//	TestPutKeyRefusesWhatIsNotAPrivateKey, TestKeysAssignAndUnassignThroughTheManagedStanza
package sshconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	testutil.Check(t, err)
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(private, "me@laptop")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "me@laptop", []byte(passphrase))
	}
	testutil.Check(t, err)
	return pem.EncodeToMemory(block)
}

func TestPutKeyRefusesWhatIsNotAPrivateKey(t *testing.T) {
	config := Config{UserPath: filepath.Join(t.TempDir(), "config"), KeyDir: filepath.Join(t.TempDir(), "keys")}
	for name, body := range map[string]string{
		"a public key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB me@laptop\n",
		"prose":        "not a key",
	} {
		if _, err := config.PutKey("delta", []byte(body)); err == nil {
			t.Errorf("%s was stored as a private key", name)
		}
	}
	if _, err := config.PutKey("../escape", testKey(t, "")); err == nil {
		t.Error("a key name with a path component was accepted")
	}
	if _, err := config.PutKey("delta.pub", testKey(t, "")); err == nil {
		t.Error("a key name ending in .pub was accepted")
	}
	if entries, _ := os.ReadDir(config.KeyDir); len(entries) != 0 {
		t.Fatalf("a refused upload left files: %v", entries)
	}
}

func TestKeysAssignAndUnassignThroughTheManagedStanza(t *testing.T) {
	config := Config{UserPath: filepath.Join(t.TempDir(), "config"), KeyDir: filepath.Join(t.TempDir(), "keys")}
	stored, err := config.PutKey("delta-key", testKey(t, ""))
	testutil.Check(t, err)
	locked, err := config.PutKey("locked", testKey(t, "secret"))
	testutil.Check(t, err)
	if stored.Type != "ssh-ed25519" || !strings.HasPrefix(stored.Fingerprint, "SHA256:") || locked.Type != "ssh-ed25519" {
		t.Fatalf("stored keys were not described: %+v %+v", stored, locked)
	}
	if info, err := os.Stat(filepath.Join(config.KeyDir, "delta-key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stored key is not private: %v %v", info, err)
	}
	keys, err := config.ListKeys()
	testutil.Check(t, err)
	if len(keys) != 2 || keys[0].Name != "delta-key" || keys[1].Name != "locked" {
		t.Fatalf("stored keys were not listed: %+v", keys)
	}

	host, err := ParseCommand("delta", "ssh -o IdentitiesOnly=yes me@login.example.edu")
	testutil.Check(t, err)
	testutil.Check(t, config.Add(config.WithKey(host, "delta-key")))
	hosts, err := config.List()
	testutil.Check(t, err)
	if len(hosts) != 1 || hosts[0].Key != "delta-key" || hosts[0].IdentityFile != filepath.Join(config.KeyDir, "delta-key") {
		t.Fatalf("the key was not assigned: %+v", hosts)
	}
	if !slices.Equal(hosts[0].ExtraDirectives, []string{"IdentitiesOnly yes"}) {
		t.Fatalf("IdentitiesOnly is not stated exactly once: %+v", hosts[0].ExtraDirectives)
	}

	testutil.Check(t, config.RemoveKey("delta-key"))
	if err := config.RemoveKey("delta-key"); err == nil {
		t.Fatal("removing a missing key succeeded")
	}
	hosts, err = config.List()
	testutil.Check(t, err)
	if len(hosts) != 1 || hosts[0].Key != "" || hosts[0].IdentityFile != "" || len(hosts[0].ExtraDirectives) != 0 {
		t.Fatalf("removing the key left the host naming it: %+v", hosts)
	}
	data, err := os.ReadFile(config.UserPath)
	testutil.Check(t, err)
	if strings.Contains(string(data), "Identit") {
		t.Fatalf("stanza still carries identity lines:\n%s", data)
	}
}
