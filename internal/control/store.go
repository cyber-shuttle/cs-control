package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cyber-shuttle/cs-control/internal/safeio"
)

func (s Store) dir() (string, error) {
	if s.Dir != "" {
		return s.Dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cybershuttle", "control"), nil
}

func (s Store) withLock(fn func(Store, *state) error) error {
	dir, err := s.dir()
	if err != nil {
		return err
	}
	s.Dir = dir
	if _, err := safeio.EnsurePrivateDir(dir); err != nil {
		return err
	}
	return safeio.WithFileLock(filepath.Join(dir, ".lock"), func() error {
		current, err := s.load()
		if err != nil {
			return err
		}
		return fn(s, current)
	})
}

func (s Store) load() (*state, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &state{Version: stateVersion, Runtimes: map[string]*Runtime{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if current.Version != stateVersion || current.Runtimes == nil {
		return nil, errors.New("unsupported state file")
	}
	for id, runtime := range current.Runtimes {
		if err := validateStoredRuntime(id, runtime); err != nil {
			return nil, fmt.Errorf("invalid stored runtime %q: %w", id, err)
		}
	}
	return &current, nil
}

func (s Store) save(current *state) error {
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	return safeio.ReplaceFile(filepath.Join(s.Dir, "state.json"), append(data, '\n'), nil)
}
