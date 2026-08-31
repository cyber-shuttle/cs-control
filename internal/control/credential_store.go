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

var generationPattern = regexp.MustCompile(`^g-[a-f0-9]{16}$`)

// A stored credential is two bounded tokens; anything larger was not written here.
const maxCredentialSize = 64 << 10

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
	if err != nil {
		return errors.New("encode generation credential")
	}
	if err := safeio.EnsurePrivateDir(s.Dir); err != nil {
		return err
	}
	return safeio.ReplaceFile(path, encoded, nil)
}

func (s CredentialStore) Get(runtimeID, generation string) (GenerationCredential, error) {
	path, err := s.path(runtimeID, generation)
	if err != nil {
		return GenerationCredential{}, err
	}
	if err := safeio.PrivateDir(s.Dir); err != nil {
		return GenerationCredential{}, err
	}
	data, err := safeio.ReadPrivateFile(path, maxCredentialSize)
	if err != nil {
		return GenerationCredential{}, err
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
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
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
