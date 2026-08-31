// Package sshconfig reads and edits the user's OpenSSH host configuration.
// It is the only subsystem that touches ~/.ssh/config, and it never runs ssh.
package sshconfig

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
)

// ValidAlias reports whether value is a host alias safe to place in an ssh
// argument vector. Every subsystem that names a host validates it here.
func ValidAlias(value string) bool { return aliasPattern.MatchString(value) }

// ErrInvalidAlias is what every subsystem reports for an alias this package
// rejects, so the refusal reads the same wherever it is raised.
var ErrInvalidAlias = apierr.New("invalid_ssh_alias", "invalid SSH alias", 400)

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Host struct {
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname,omitempty"`
	User            string   `json:"user,omitempty"`
	Port            int      `json:"port,omitempty"`
	IdentityFile    string   `json:"identityFile,omitempty"`
	ExtraDirectives []string `json:"extraDirectives"`
	// Managed marks the entries this package wrote, which are the only ones it
	// may remove; everything else is the user's own configuration.
	Managed bool `json:"managed"`
}

type HostList struct {
	Hosts []Host `json:"hosts"`
}

// Config names the two files a host lookup consults. The composition root
// supplies both; an empty one is simply not read.
type Config struct {
	UserPath   string
	SystemPath string
}

func (c Config) List() ([]Host, error) {
	hosts := map[string]Host{}
	visited := map[string]bool{}
	for _, path := range []string{c.SystemPath, c.UserPath} {
		if path == "" {
			continue
		}
		parsed, err := parseFile(path, visited)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, host := range parsed {
			hosts[host.Name] = host
		}
	}
	result := make([]Host, 0, len(hosts))
	for _, host := range hosts {
		result = append(result, host)
	}
	slices.SortFunc(result, func(a, b Host) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}

func parseFile(path string, visited map[string]bool) ([]Host, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if visited[absolute] {
		return nil, nil
	}
	visited[absolute] = true
	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var result []Host
	inMatch := false
	// Stanza bodies are scanned ahead, so the managed region is located once
	// rather than tracked as the cursor moves.
	blockStart, blockStop := blockBounds(lines)
	for i := 0; i < len(lines); {
		fields := strings.Fields(strings.TrimSpace(lines[i]))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			i++
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "match" {
			inMatch = true
			i++
			continue
		}
		if key == "include" && !inMatch {
			for _, pattern := range fields[1:] {
				pattern = expandHome(pattern)
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(absolute), pattern)
				}
				matches, _ := filepath.Glob(pattern)
				for _, match := range matches {
					included, includeErr := parseFile(match, visited)
					if includeErr != nil && !errors.Is(includeErr, os.ErrNotExist) {
						return nil, includeErr
					}
					result = append(result, included...)
				}
			}
			i++
			continue
		}
		if key != "host" {
			i++
			continue
		}
		inMatch = false
		start := i
		i++
		for i < len(lines) {
			next := strings.Fields(strings.TrimSpace(lines[i]))
			if len(next) > 0 && (strings.EqualFold(next[0], "Host") || strings.EqualFold(next[0], "Match")) {
				break
			}
			i++
		}
		aliases := make([]string, 0, len(fields)-1)
		for _, alias := range fields[1:] {
			if aliasPattern.MatchString(alias) && !strings.ContainsAny(alias, "*?!") {
				aliases = append(aliases, alias)
			}
		}
		if len(aliases) == 0 {
			continue
		}
		host := Host{Port: 22, ExtraDirectives: []string{}, Managed: blockStart >= 0 && start > blockStart && start < blockStop}
		for _, line := range lines[start+1 : i] {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) < 2 || strings.HasPrefix(parts[0], "#") {
				continue
			}
			value := strings.Join(parts[1:], " ")
			switch strings.ToLower(parts[0]) {
			case "hostname":
				host.Hostname = value
			case "user":
				host.User = value
			case "port":
				host.Port, _ = strconv.Atoi(value)
			case "identityfile":
				host.IdentityFile = value
			default:
				host.ExtraDirectives = append(host.ExtraDirectives, strings.TrimSpace(line))
			}
		}
		for _, alias := range aliases {
			copy := host
			copy.Name = alias
			copy.ExtraDirectives = append([]string{}, host.ExtraDirectives...)
			result = append(result, copy)
		}
	}
	return result, nil
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
