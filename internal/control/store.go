package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cyber-shuttle/cs-control/internal/safeio"
)

func (s Store) withLock(fn func(Store, *state) error) error {
	if s.Dir == "" {
		return errors.New("state directory is required")
	}
	if err := safeio.EnsurePrivateDir(s.Dir); err != nil {
		return err
	}
	return safeio.WithFileLock(filepath.Join(s.Dir, ".lock"), func() error {
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
	return &current, nil
}

func (s Store) save(current *state) error {
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	return safeio.ReplaceFile(filepath.Join(s.Dir, "state.json"), append(data, '\n'), nil)
}
