// The credential store's own file-level guarantees. Writes are atomic and mode 0600.
// It refuses anything partial, invalid, or reached through a symlink.
//
//	credential
//	Test*
package credentialstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func credential(connect, jupyterToken string) Credential {
	return Credential{ConnectToken: connect, JupyterToken: jupyterToken}
}

func TestCredentialStoreAtomicallyStoresGenerationSecretsMode0600(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "credentials")}
	const sessionID, generation = "s-123456789abc", "g-0123456789abcdef"
	first := credential("first-connect-token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	testutil.Check(t, store.Put(sessionID, generation, first))
	if got, err := store.Get(sessionID, generation); err != nil || got != first {
		t.Fatalf("Get = %#v, %v", got, err)
	}
	dirInfo, err := os.Stat(store.Dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v, %v", dirInfo.Mode(), err)
	}
	entries, err := os.ReadDir(store.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %#v, %v", entries, err)
	}
	fileInfo, err := os.Stat(filepath.Join(store.Dir, entries[0].Name()))
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, %v", fileInfo.Mode(), err)
	}
	replacement := credential("replacement-connect-token", strings.Repeat("B", 42)+"A")
	testutil.Check(t, store.Put(sessionID, generation, replacement))
	if got, err := store.Get(sessionID, generation); err != nil || got != replacement {
		t.Fatalf("replacement Get = %#v, %v", got, err)
	}
	testutil.Check(t, store.Delete(sessionID, generation))
	if _, err := store.Get(sessionID, generation); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestCredentialStoreRejectsPartialInvalidOrUnsafeRecords(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "credentials")}
	for name, candidate := range map[string]Credential{
		"missing connect":    {JupyterToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"short jupyterToken": {ConnectToken: "connect", JupyterToken: strings.Repeat("A", 42)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.Put("s-123456789abc", "g-0123456789abcdef", candidate); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
	testutil.Check(t, os.Mkdir(store.Dir, 0o700))
	path, _ := store.path("s-123456789abc", "g-0123456789abcdef")
	for _, raw := range []string{`{"connectToken":"connect"}`, `{"connectToken":"connect","jupyterToken":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":true}`, `{"connectToken":"connect","jupyterToken":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}{}`} {
		testutil.Check(t, os.WriteFile(path, []byte(raw), 0o600))
		if _, err := store.Get("s-123456789abc", "g-0123456789abcdef"); err == nil {
			t.Fatalf("invalid stored record accepted: %s", raw)
		}
	}
}

func TestCredentialStoreRefusesSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	foreign := filepath.Join(root, "foreign")
	testutil.Check(t, os.Mkdir(foreign, 0o755))
	dir := filepath.Join(root, "credentials")
	testutil.Check(t, os.Symlink(foreign, dir))
	store := Store{Dir: dir}
	const sessionID, generation = "s-123456789abc", "g-0123456789abcdef"
	if err := store.Put(sessionID, generation, credential("connect-token", strings.Repeat("A", 43))); err == nil {
		t.Fatal("Put wrote a credential into a symlinked directory")
	}
	if info, err := os.Stat(foreign); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target mode = %v, %v", info.Mode(), err)
	}
	if entries, err := os.ReadDir(foreign); err != nil || len(entries) != 0 {
		t.Fatalf("entries in symlink target = %#v, %v", entries, err)
	}
	if _, err := store.Get(sessionID, generation); err == nil {
		t.Fatal("Get read a credential from a symlinked directory")
	}
}

func TestCredentialStoreGetRefusesSymlinkedRecord(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "credentials")}
	const sessionID, generation = "s-123456789abc", "g-0123456789abcdef"
	testutil.Check(t, store.Put(sessionID, generation, credential("connect-token", strings.Repeat("A", 43))))
	path, _ := store.path(sessionID, generation)
	foreign := filepath.Join(t.TempDir(), "foreign.token")
	testutil.Check(t, os.WriteFile(foreign, []byte(`{"connectToken":"planted-token","jupyterToken":"`+strings.Repeat("A", 43)+`"}`), 0o644))
	testutil.Check(t, os.Remove(path))
	testutil.Check(t, os.Symlink(foreign, path))
	if got, err := store.Get(sessionID, generation); err == nil {
		t.Fatalf("Get followed a symlink to a foreign credential: %#v", got)
	}
}
