// SSH configuration tests cover command parsing, refusal, and the rendered stanza.
package ssh

import (
	"errors"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestParseCommandCarriesTheConnectionAndRefusesTheRest(t *testing.T) {
	host, err := parseCommand("delta", "ssh -p 2222 -J bastion -o StrictHostKeyChecking=accept-new me@login.example.edu")
	testutil.Check(t, err)
	if host.Hostname != "login.example.edu" || host.User != "me" || host.Port != 2222 {
		t.Fatalf("connection not carried: %+v", host)
	}
	if strings.Join(host.ExtraDirectives, ",") != "ProxyJump bastion,StrictHostKeyChecking accept-new" {
		t.Fatalf("directives not carried: %+v", host.ExtraDirectives)
	}
	host.Key = "delta-key"
	want := "Host delta\n    hostname login.example.edu\n    identitiesonly yes\n    identityfile /keys/delta-key\n    port 2222\n    proxyjump bastion\n    stricthostkeychecking accept-new\n    user me\n"
	if got := strings.Join(host.stanza("/keys/delta-key"), "\n"); got != want {
		t.Fatalf("stanza =\n%s\nwant\n%s", got, want)
	}
	for _, command := range []string{
		"ssh -o ProxyCommand=nc\\ evil\\ 22 host",
		"ssh -o LocalCommand=id host",
		"ssh -i ~/.ssh/id_ed25519 host",
		"ssh -o IdentityFile=/etc/ssh/key host",
		"ssh -o IdentityAgent=/tmp/agent host",
		"ssh host uptime",
		"ssh -D 1080 host",
		"ssh",
	} {
		if _, err := parseCommand("delta", command); err == nil {
			t.Fatalf("accepted %q", command)
		}
	}
	if _, err := parseCommand("bad alias", "ssh host"); !errors.Is(err, ssh.ErrInvalidAlias) {
		t.Fatalf("alias not validated: %v", err)
	}
}
