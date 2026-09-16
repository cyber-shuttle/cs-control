// Package sshconfig reads and edits one caller's OpenSSH host configuration, never the user's own ~/.ssh/config.
// It is the only subsystem that touches that file, and it never runs ssh.
// The write path is narrower than the read path: only entries fenced between blockBegin and blockEnd are ever
// rewritten; everything outside that block is read, never touched. ParseCommand turns a pasted ssh command
// line into the Host that reproduces it.
//
//	blockBegin, blockEnd, safeNamePattern, valuePattern, allowedOptions*, ErrInvalidAlias
//	Host, HostList, Config
//	firstField, blockBounds, stanzaEnd, managedStanza, parseFile
//	errUnmanaged, invalid, validText, option, stanza
//	SafeName, ValidAlias, List, ParseCommand
//	rewrite, replaceStanza, Add, Remove, Update
package sshconfig

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
)

const (
	blockBegin = "# >>> cybershuttle managed >>>"
	blockEnd   = "# <<< cybershuttle managed <<<"
)

var safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

var valuePattern = regexp.MustCompile(`^[A-Za-z0-9_@%:./+=,~-]{1,256}$`)

var allowedOptions = map[string]string{
	"proxyjump":                "ProxyJump",
	"stricthostkeychecking":    "StrictHostKeyChecking",
	"userknownhostsfile":       "UserKnownHostsFile",
	"identitiesonly":           "IdentitiesOnly",
	"identityagent":            "IdentityAgent",
	"forwardagent":             "ForwardAgent",
	"serveraliveinterval":      "ServerAliveInterval",
	"serveralivecountmax":      "ServerAliveCountMax",
	"preferredauthentications": "PreferredAuthentications",
	"pubkeyauthentication":     "PubkeyAuthentication",
	"pubkeyacceptedalgorithms": "PubkeyAcceptedAlgorithms",
	"hostkeyalgorithms":        "HostKeyAlgorithms",
	"kexalgorithms":            "KexAlgorithms",
	"ciphers":                  "Ciphers",
	"macs":                     "MACs",
	"addkeystoagent":           "AddKeysToAgent",
	"compression":              "Compression",
	"requesttty":               "RequestTTY",
}

var ErrInvalidAlias = apierr.New("invalid_ssh_alias", "invalid SSH alias", 400)

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

func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func blockBounds(lines []string) (int, int) {
	begin := -1
	for index, line := range lines {
		switch strings.TrimSpace(line) {
		case blockBegin:
			begin = index
		case blockEnd:
			if begin >= 0 {
				return begin, index
			}
		}
	}
	return -1, -1
}

func stanzaEnd(lines []string, from, limit int, matchToo bool) int {
	for ; from < limit; from++ {
		field := firstField(lines[from])
		if strings.EqualFold(field, "Host") || matchToo && strings.EqualFold(field, "Match") {
			break
		}
	}
	return from
}

func managedStanza(lines []string, alias string) (int, int, bool) {
	begin, end := blockBounds(lines)
	for index := begin + 1; begin >= 0 && index < end; index++ {
		fields := strings.Fields(lines[index])
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Host") || fields[1] != alias {
			continue
		}
		return index, stanzaEnd(lines, index+1, end, false), true
	}
	return 0, 0, false
}

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
		i = stanzaEnd(lines, i+1, len(lines), true)
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

func errUnmanaged(alias string) error {
	return apierr.New("ssh_host_not_managed", fmt.Sprintf("%s is not an alias this API manages", alias), http.StatusConflict)
}

func invalid(message string) error {
	return apierr.New("invalid_ssh_command", message, http.StatusBadRequest)
}

func validText(subject, text string) (string, error) {
	if !valuePattern.MatchString(text) {
		return "", invalid(fmt.Sprintf("The %s carries characters an ssh config cannot hold.", subject))
	}
	return text, nil
}

func option(key, value string) (string, error) {
	value, err := validText(key+" value", value)
	if err != nil {
		return "", err
	}
	return key + " " + value, nil
}

func stanza(host Host) []string {
	lines := []string{"Host " + host.Name}
	if host.Hostname != "" {
		lines = append(lines, "  HostName "+host.Hostname)
	}
	if host.User != "" {
		lines = append(lines, "  User "+host.User)
	}
	if host.Port != 0 && host.Port != 22 {
		lines = append(lines, "  Port "+strconv.Itoa(host.Port))
	}
	if host.IdentityFile != "" {
		lines = append(lines, "  IdentityFile "+host.IdentityFile)
	}
	for _, directive := range host.ExtraDirectives {
		lines = append(lines, "  "+strings.TrimSpace(directive))
	}
	return lines
}

func SafeName(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && safeNamePattern.MatchString(value)
}

func ValidAlias(value string) bool { return SafeName(value, 128) }

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

func ParseCommand(name, command string) (Host, error) {
	if !ValidAlias(name) {
		return Host{}, ErrInvalidAlias
	}
	fields := strings.Fields(command)
	if len(fields) > 0 && strings.EqualFold(filepath.Base(fields[0]), "ssh") {
		fields = fields[1:]
	}
	host := Host{Name: name, Port: 22, ExtraDirectives: []string{}}
	target := ""
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		value := func() (string, error) {
			if len(field) > 2 {
				return field[2:], nil
			}
			index++
			if index >= len(fields) {
				return "", invalid(fmt.Sprintf("%s expects a value.", field))
			}
			return fields[index], nil
		}
		switch {
		case field == "--":
			continue
		case strings.HasPrefix(field, "-p"):
			text, err := value()
			if err != nil {
				return Host{}, err
			}
			port, convErr := strconv.Atoi(text)
			if convErr != nil || port < 1 || port > 65535 {
				return Host{}, invalid(fmt.Sprintf("%q is not a port.", text))
			}
			host.Port = port
		case strings.HasPrefix(field, "-i"):
			text, err := value()
			if err != nil {
				return Host{}, err
			}
			host.IdentityFile, err = validText("identity file path", text)
			if err != nil {
				return Host{}, err
			}
		case strings.HasPrefix(field, "-l"):
			text, err := value()
			if err != nil {
				return Host{}, err
			}
			host.User, err = validText("user name", text)
			if err != nil {
				return Host{}, err
			}
		case strings.HasPrefix(field, "-J"):
			text, err := value()
			if err != nil {
				return Host{}, err
			}
			directive, err := option("ProxyJump", text)
			if err != nil {
				return Host{}, err
			}
			host.ExtraDirectives = append(host.ExtraDirectives, directive)
		case strings.HasPrefix(field, "-o"):
			text, err := value()
			if err != nil {
				return Host{}, err
			}
			key, setting, found := strings.Cut(text, "=")
			if !found {
				key, setting, found = strings.Cut(text, " ")
			}
			if !found {
				return Host{}, invalid(fmt.Sprintf("%q is not an ssh option.", text))
			}
			canonical, ok := allowedOptions[strings.ToLower(strings.TrimSpace(key))]
			if !ok {
				return Host{}, invalid(fmt.Sprintf("%s cannot be set from a pasted command.", strings.TrimSpace(key)))
			}
			directive, err := option(canonical, strings.TrimSpace(setting))
			if err != nil {
				return Host{}, err
			}
			host.ExtraDirectives = append(host.ExtraDirectives, directive)
		case strings.HasPrefix(field, "-"):
			return Host{}, invalid(fmt.Sprintf("%s is not supported here. Keep the command to the host, user, port, identity, jump host, and -o options.", field))
		case target == "":
			target = field
		default:
			return Host{}, invalid("Remove the remote command; the entry describes the connection only.")
		}
	}
	if target == "" {
		return Host{}, invalid("The command names no host.")
	}
	if user, hostname, found := strings.Cut(target, "@"); found {
		var err error
		if host.User, err = validText("user name", user); err != nil {
			return Host{}, err
		}
		target = hostname
	}
	hostname, err := validText("host name", target)
	if err != nil {
		return Host{}, err
	}
	host.Hostname = hostname
	return host, nil
}

func (c Config) rewrite(mutate func([]string) ([]string, error)) error {
	path := c.UserPath
	if path == "" {
		return errors.New("user SSH config path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var lines []string
	if text := strings.TrimSuffix(string(data), "\n"); text != "" || len(data) > 0 {
		lines = strings.Split(text, "\n")
	}
	updated, err := mutate(lines)
	if err != nil {
		return err
	}
	return safeio.ReplaceFile(path, []byte(strings.Join(updated, "\n")+"\n"))
}

func (c Config) replaceStanza(alias string, replacement []string) error {
	if !ValidAlias(alias) {
		return ErrInvalidAlias
	}
	return c.rewrite(func(lines []string) ([]string, error) {
		start, stop, ok := managedStanza(lines, alias)
		if !ok {
			return nil, errUnmanaged(alias)
		}
		return append(lines[:start:start], append(replacement, lines[stop:]...)...), nil
	})
}

func (c Config) Add(host Host) error {
	if !ValidAlias(host.Name) {
		return ErrInvalidAlias
	}
	existing, err := c.List()
	if err != nil {
		return err
	}
	for _, each := range existing {
		if strings.EqualFold(each.Name, host.Name) {
			return apierr.New("ssh_host_exists", fmt.Sprintf("%s is already configured.", host.Name), http.StatusConflict)
		}
	}
	return c.rewrite(func(lines []string) ([]string, error) {
		begin, end := blockBounds(lines)
		if begin < 0 {
			if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
				lines = append(lines, "")
			}
			lines = append(lines, blockBegin, blockEnd)
			end = len(lines) - 1
		}
		return append(lines[:end:end], append(stanza(host), lines[end:]...)...), nil
	})
}

func (c Config) Remove(alias string) error { return c.replaceStanza(alias, nil) }

func (c Config) Update(host Host) error { return c.replaceStanza(host.Name, stanza(host)) }
