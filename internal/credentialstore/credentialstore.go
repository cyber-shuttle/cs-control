// One seq's Dev Tunnel connect token and Jupyter identity token, held as one file per seq.
// It is never persisted anywhere else, and never returned except to the session's owner.
//
//	sessionIDPattern
//	maxCredentialSize
//	Credential
//	validJupyterToken
//	validCredential
//	Store
//	Put, Get, Delete, path
package credentialstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
)

var sessionIDPattern = regexp.MustCompile(`^s-[a-f0-9]{12}$`)

const maxCredentialSize = 64 << 10

type Credential struct {
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

func validCredential(credential Credential) bool {
	return devtunnel.ValidToken(credential.ConnectToken) && validJupyterToken(credential.JupyterToken)
}

type Store struct {
	Dir string
}

func (s Store) Put(sessionID string, seq int, credential Credential) error {
	location, err := s.path(sessionID, seq)
	if err != nil {
		return err
	}
	if !validCredential(credential) {
		return errors.New("seq credential is invalid")
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return errors.New("encode seq credential")
	}
	if err := safeio.EnsurePrivateDir(s.Dir); err != nil {
		return err
	}
	return safeio.ReplaceFile(location, encoded)
}

func (s Store) Get(sessionID string, seq int) (Credential, error) {
	location, err := s.path(sessionID, seq)
	if err != nil {
		return Credential{}, err
	}
	if err := safeio.PrivateDir(s.Dir); err != nil {
		return Credential{}, err
	}
	data, err := safeio.ReadPrivateFile(location, maxCredentialSize)
	if err != nil {
		return Credential{}, err
	}
	var credential Credential
	if err := apierr.DecodeStrict(bytes.NewReader(data), &credential); err != nil || !validCredential(credential) {
		return Credential{}, errors.New("stored credential is invalid")
	}
	return credential, nil
}

func (s Store) Delete(sessionID string, seq int) error {
	location, err := s.path(sessionID, seq)
	if err != nil {
		return err
	}
	if err := os.Remove(location); err != nil {
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

func (s Store) path(sessionID string, seq int) (string, error) {
	if !filepath.IsAbs(s.Dir) || !sessionIDPattern.MatchString(sessionID) || seq < 1 {
		return "", errors.New("credential store identity is invalid")
	}
	return filepath.Join(s.Dir, sessionID+"-"+strconv.Itoa(seq)+".token"), nil
}
