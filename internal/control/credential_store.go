package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
)

const maxCredentialSize = 64 << 10

var generationPattern = regexp.MustCompile(`^g-[a-f0-9]{16}$`)

type GenerationCredential struct {
	ConnectToken string `json:"connectToken"`
	JupyterToken string `json:"jupyterToken"`
}

func validJupyterToken(token string) bool {
	if len(token) != 43 || strings.Contains(token, "=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(decoded) == 32
}

func validGenerationCredential(credential GenerationCredential) bool {
	return devtunnel.ValidToken(credential.ConnectToken) && validJupyterToken(credential.JupyterToken)
}

type CredentialStore struct {
	Dir string
}

func (s CredentialStore) Put(runtimeID, generation string, credential GenerationCredential) error {
	path, err := s.path(runtimeID, generation)
	if err != nil {
		return err
	}
	if !validGenerationCredential(credential) {
		return errors.New("generation credential is invalid")
	}
	encoded, err := json.Marshal(credential)
	if err != nil || len(encoded) > maxCredentialSize {
		return errors.New("encode generation credential")
	}
	dir, err := safeio.EnsurePrivateDir(s.Dir)
	if err != nil {
		return err
	}
	if _, err := safeio.StatPrivate(path, safeio.Regular, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Re-check the directory once the payload is durable: a swap between the
	// check above and the rename would commit the secret into a foreign one.
	return safeio.ReplaceFile(path, encoded, func() error {
		current, err := safeio.StatPrivate(s.Dir, safeio.Dir, 0o700)
		if err != nil || !os.SameFile(dir, current) {
			return errors.New("credential directory changed during write")
		}
		return nil
	})
}

func (s CredentialStore) Get(runtimeID, generation string) (GenerationCredential, error) {
	path, err := s.path(runtimeID, generation)
	if err != nil {
		return GenerationCredential{}, err
	}
	if _, err := safeio.StatPrivate(s.Dir, safeio.Dir, 0o700); err != nil {
		return GenerationCredential{}, err
	}
	before, err := safeio.StatPrivate(path, safeio.Regular, 0o600)
	if err != nil {
		return GenerationCredential{}, err
	}
	if before.Size() < 1 || before.Size() > maxCredentialSize {
		return GenerationCredential{}, errors.New("credential path is not a private regular file")
	}
	file, err := safeio.OpenNoFollow(path)
	if err != nil {
		return GenerationCredential{}, errors.New("open credential")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return GenerationCredential{}, errors.New("credential changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialSize+1))
	if err != nil || len(data) > maxCredentialSize {
		return GenerationCredential{}, errors.New("read credential")
	}
	var credential GenerationCredential
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return GenerationCredential{}, errors.New("stored credential is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validGenerationCredential(credential) {
		return GenerationCredential{}, errors.New("stored credential is invalid")
	}
	return credential, nil
}

func (s CredentialStore) Delete(runtimeID, generation string) error {
	path, err := s.path(runtimeID, generation)
	if err != nil {
		return err
	}
	if _, err := safeio.StatPrivate(s.Dir, safeio.Dir, 0o700); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if _, err := safeio.StatPrivate(path, safeio.Regular, 0o600); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		return errors.New("delete credential")
	}
	if err := safeio.SyncDir(s.Dir); err != nil {
		return errors.New("sync credential directory")
	}
	return nil
}

func (s CredentialStore) path(runtimeID, generation string) (string, error) {
	if !filepath.IsAbs(s.Dir) || !idPattern.MatchString(runtimeID) || !generationPattern.MatchString(generation) {
		return "", errors.New("credential store identity is invalid")
	}
	return filepath.Join(s.Dir, runtimeID+"-"+generation+".token"), nil
}
