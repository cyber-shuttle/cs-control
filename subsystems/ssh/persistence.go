// SSH host persistence coordinates SQL metadata with rendered per-principal config and protected key files. Host
// and key tables remain private to this subsystem; a process-wide database lock encloses each compensated flow, and
// only its metadata mutation runs in a transaction. Queries in query.sql are generated into query.sql.go by sqlc.
// The real OpenSSH config is never read or changed.
package ssh

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/security"
)

//go:embed schema.sql
var Schema string

const (
	maxSSHConfigBytes = 64 << 20
	identitiesOnly    = "IdentitiesOnly yes"
)

var background = context.Background()

func hostNotFound(alias string) error {
	return security.New("ssh_host_not_found", "\""+alias+"\" is not configured", http.StatusNotFound)
}

func hostsIn(queries *Queries, principal string) ([]hostEntry, error) {
	rows, err := queries.ListHosts(background, principal)
	if err != nil {
		return nil, err
	}
	hosts := make([]hostEntry, 0, len(rows))
	for _, row := range rows {
		host, err := db.DecodePayload(row.Payload, func(h hostEntry) bool { return h.Name == row.Host }, "SSH host "+row.Host)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func replaceHost(queries *Queries, principal string, host hostEntry) error {
	payload, err := json.Marshal(host)
	if err != nil {
		return err
	}
	rows, err := queries.UpdateHost(background, UpdateHostParams{Payload: string(payload), Principal: principal, Host: host.Name})
	if err == nil && rows == 0 {
		return hostNotFound(host.Name)
	}
	return err
}

func renderConfig(hosts []hostEntry) []byte {
	sorted := slices.SortedFunc(slices.Values(hosts), func(a, b hostEntry) int { return strings.Compare(a.Name, b.Name) })
	var lines []string
	for _, host := range sorted {
		lines = append(lines, host.stanza()...)
	}
	return []byte(strings.Join(lines, "\n"))
}

func withSSHCredential(host hostEntry, name, path string) hostEntry {
	host.Key = name
	host.IdentityFile = ""
	host.ExtraDirectives = slices.DeleteFunc(slices.Clone(host.ExtraDirectives), func(directive string) bool {
		fields := strings.Fields(directive)
		return len(fields) != 0 && strings.EqualFold(fields[0], "IdentitiesOnly")
	})
	if name != "" {
		host.IdentityFile = path
		host.ExtraDirectives = append(host.ExtraDirectives, identitiesOnly)
	}
	return host
}

type Store struct {
	Database     *db.DB
	PrincipalDir string
}

func (s Store) locked(fn func(*Queries) error) error {
	return s.Database.Locked(func(database *sql.DB) error { return fn(New(database)) })
}

func (s Store) loadHosts(principal string) ([]hostEntry, error) {
	var hosts []hostEntry
	return hosts, s.locked(func(queries *Queries) error {
		var err error
		hosts, err = hostsIn(queries, principal)
		return err
	})
}

// reconcileConfigs rerenders every principal's config, including directories with no rows left, from committed hosts.
func (s Store) reconcileConfigs() error {
	return s.locked(func(queries *Queries) error {
		principals, err := queries.ListHostPrincipals(background)
		if err != nil {
			return err
		}
		entries, err := os.ReadDir(s.PrincipalDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type().IsDir() && security.SafeName(entry.Name(), 128) {
				principals = append(principals, entry.Name())
			}
		}
		slices.Sort(principals)
		for _, principal := range slices.Compact(principals) {
			hosts, err := hostsIn(queries, principal)
			if err != nil {
				return err
			}
			principalDir := filepath.Join(s.PrincipalDir, principal)
			if err := security.EnsurePrivateDir(principalDir); err != nil {
				return err
			}
			if err := security.ReplaceFile(filepath.Join(principalDir, "config"), renderConfig(hosts)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s Store) mutateHosts(principal, path string, mutate func(*Queries) error, stage func() (func(bool) error, error)) error {
	return s.locked(func(*Queries) error {
		previous, readErr := security.ReadPrivateFile(path, maxSSHConfigBytes)
		hadPrevious := readErr == nil
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		var finish func(bool) error
		var err error
		if stage != nil {
			finish, err = stage()
			if err != nil {
				return err
			}
		}
		replacementAttempted := false
		err = s.Database.Tx(func(tx *sql.Tx) error {
			queries := New(tx)
			if err := mutate(queries); err != nil {
				return err
			}
			hosts, err := hostsIn(queries, principal)
			if err != nil {
				return err
			}
			if err := security.EnsurePrivateDir(filepath.Dir(path)); err != nil {
				return err
			}
			replacementAttempted = true
			return security.ReplaceFile(path, renderConfig(hosts))
		})
		if err != nil {
			var restoreErr error
			if replacementAttempted && hadPrevious {
				restoreErr = security.ReplaceFile(path, previous)
			} else if replacementAttempted {
				restoreErr = security.RemoveFile(path)
			}
			if finish != nil {
				restoreErr = errors.Join(restoreErr, finish(false))
			}
			return errors.Join(err, restoreErr)
		}
		if finish != nil {
			return finish(true)
		}
		return nil
	})
}

func (s Store) resolveSSHCredential(queries *Queries, principal string, host hostEntry) (hostEntry, error) {
	if host.Key == "" {
		return host, nil
	}
	if _, found, err := keyMetadata(queries, principal, host.Key); err != nil {
		return hostEntry{}, err
	} else if !found {
		return hostEntry{}, errSSHKeyNotFound
	}
	return withSSHCredential(host, host.Key, s.sshPath(principal, host.Key)), nil
}

// putHost resolves the host's key reference, then stores the resolved entry with store inside one config mutation.
func (s Store) putHost(principal, configPath string, host hostEntry, store func(*Queries, hostEntry) error) (hostEntry, error) {
	var resolved hostEntry
	err := s.mutateHosts(principal, configPath, func(queries *Queries) error {
		var err error
		if resolved, err = s.resolveSSHCredential(queries, principal, host); err != nil {
			return err
		}
		return store(queries, resolved)
	}, nil)
	return resolved, err
}

func (s Store) addHost(principal, configPath string, host hostEntry) (hostEntry, error) {
	return s.putHost(principal, configPath, host, func(queries *Queries, resolved hostEntry) error {
		payload, err := json.Marshal(resolved)
		if err != nil {
			return err
		}
		if err := queries.InsertHost(background, InsertHostParams{Principal: principal, Host: host.Name, Payload: string(payload)}); db.IsConstraint(err) {
			return security.New("ssh_host_exists", host.Name+" is already configured.", http.StatusConflict)
		} else {
			return err
		}
	})
}

func (s Store) updateHost(principal, configPath string, host hostEntry) (hostEntry, error) {
	return s.putHost(principal, configPath, host, func(queries *Queries, resolved hostEntry) error {
		return replaceHost(queries, principal, resolved)
	})
}

func (s Store) deleteHost(principal, path, name string) error {
	return s.mutateHosts(principal, path, func(queries *Queries) error {
		rows, err := queries.DeleteHost(background, DeleteHostParams{Principal: principal, Host: name})
		if err == nil && rows == 0 {
			return hostNotFound(name)
		}
		return err
	}, nil)
}

func (s Store) deleteSSHKey(principal, configPath, name string) error {
	return s.mutateHosts(principal, configPath, func(queries *Queries) error {
		if _, found, err := keyMetadata(queries, principal, name); err != nil {
			return err
		} else if !found {
			return errSSHKeyNotFound
		}
		hosts, err := hostsIn(queries, principal)
		if err != nil {
			return err
		}
		for _, host := range hosts {
			if host.Key == name {
				if err := replaceHost(queries, principal, withSSHCredential(host, "", "")); err != nil {
					return err
				}
			}
		}
		rows, err := queries.DeleteKey(background, DeleteKeyParams{Principal: principal, Name: name})
		if err == nil && rows == 0 {
			return errSSHKeyNotFound
		}
		return err
	}, func() (func(bool) error, error) {
		return s.stageSSHDelete(principal, name)
	})
}
