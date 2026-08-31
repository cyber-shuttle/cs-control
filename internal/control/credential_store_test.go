package control

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func credential(connect, capability string) GenerationCredential {
	return GenerationCredential{ConnectToken: connect, JupyterToken: capability}
}

func TestCredentialStoreAtomicallyStoresGenerationSecretsMode0600(t *testing.T) {
	store := CredentialStore{Dir: filepath.Join(t.TempDir(), "credentials")}
	const runtimeID, generation = "rt-123456789abc", "g-0123456789abcdef"
	first := credential("first-connect-token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err := store.Put(runtimeID, generation, first); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(runtimeID, generation); err != nil || got != first {
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
	if err := store.Put(runtimeID, generation, replacement); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(runtimeID, generation); err != nil || got != replacement {
		t.Fatalf("replacement Get = %#v, %v", got, err)
	}
	if err := store.Delete(runtimeID, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(runtimeID, generation); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestCredentialStoreRejectsPartialInvalidOrUnsafeRecords(t *testing.T) {
	store := CredentialStore{Dir: filepath.Join(t.TempDir(), "credentials")}
	for name, candidate := range map[string]GenerationCredential{
		"missing connect":    {JupyterToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"missing capability": {ConnectToken: "connect"},
		"short capability":   {ConnectToken: "connect", JupyterToken: strings.Repeat("A", 42)},
		"unsafe token":       {ConnectToken: "connect\nsecret", JupyterToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.Put("rt-123456789abc", "g-0123456789abcdef", candidate); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
	if err := os.Mkdir(store.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path, _ := store.path("rt-123456789abc", "g-0123456789abcdef")
	for _, raw := range []string{`{"connectToken":"connect"}`, `{"connectToken":"connect","controlCapability":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":true}`, `{"connectToken":"connect","controlCapability":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}{}`} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get("rt-123456789abc", "g-0123456789abcdef"); err == nil {
			t.Fatalf("invalid stored record accepted: %s", raw)
		}
	}
}
