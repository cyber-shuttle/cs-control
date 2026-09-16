// Package sshconfig reads and edits one caller's OpenSSH host configuration, never the user's own ~/.ssh/config.
// It is the only subsystem that touches that file, and it never runs ssh.
// manage.go holds the only part of that file this package writes.
//
//	Host
//	HostList, Config
//	parseFile
//	SafeName
//	ValidAlias, ErrInvalidAlias, List
package sshconfig

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
)

type Host struct {
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname,omitempty"`
	User            string   `json:"user,omitempty"`
	Port            int      `json:"port,omitempty"`
	IdentityFile    string   `json:"identityFile,omitempty"`
	ExtraDirectives []string `json:"extraDirectives"`
	Managed         bool     `json:"managed"`
}

type HostList struct {
	Hosts []Host `json:"hosts"`
}

type Config struct {
	UserPath string
}

var safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func parseFile(path string) ([]Host, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	var result []Host
	blockStart, blockStop := blockBounds(lines)
	for i := 0; i < len(lines); {
		fields := strings.Fields(strings.TrimSpace(lines[i]))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			i++
			continue
		}
		if strings.ToLower(fields[0]) != "host" {
			i++
			continue
		}
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
			if len(alias) > 0 && len(alias) <= 128 && safeNamePattern.MatchString(alias) && !strings.ContainsAny(alias, "*?!") {
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

func SafeName(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && safeNamePattern.MatchString(value)
}

func ValidAlias(value string) bool { return SafeName(value, 128) }

var ErrInvalidAlias = apierr.New("invalid_ssh_alias", "invalid SSH alias", 400)

func (c Config) List() ([]Host, error) {
	parsed, err := parseFile(c.UserPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	hosts := map[string]Host{}
	for _, host := range parsed {
		hosts[host.Name] = host
	}
	result := make([]Host, 0, len(hosts))
	for _, host := range hosts {
		result = append(result, host)
	}
	slices.SortFunc(result, func(a, b Host) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}
