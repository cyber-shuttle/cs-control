// Package sshconfig reads and edits one caller's OpenSSH host configuration, never the user's own ~/.ssh/config.
// It is the only subsystem that touches that file, and it never runs ssh.
// The write path is narrower than the read path: only entries fenced between blockBegin and blockEnd are ever
// rewritten; everything outside that block is read, never touched. ParseCommand turns a pasted ssh command
// line into the Host that reproduces it. Uploaded login keys sit in KeyDir; a host assigned one carries
// its path as IdentityFile with IdentitiesOnly, so ssh offers nothing else.
//
//	blockBegin, blockEnd, identitiesOnly, safeNamePattern, valuePattern, allowedOptions*
//	ErrInvalidAlias, ErrInvalidKeyName, ErrKeyNotFound
//	Host, HostList, Key, KeyList, Config
//	firstField, blockBounds, stanzaEnd, managedStanza, parseFile
//	errUnmanaged, invalid, validText, option, stanza
//	publicKeyOf, readKey
//	SafeName, ValidAlias, ValidKeyName, List, ParseCommand
//	rewrite, replaceStanza, Add, Remove, Update
//	ListKeys, PutKey, RemoveKey, WithKey, AssignKey
package sshconfig

import (
	"bytes"
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
	"golang.org/x/crypto/ssh"
)

const (
	blockBegin     = "# >>> cybershuttle managed >>>"
	blockEnd       = "# <<< cybershuttle managed <<<"
	identitiesOnly = "IdentitiesOnly yes"
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

var ErrInvalidKeyName = apierr.New("invalid_ssh_key_name", "invalid SSH key name", http.StatusBadRequest)

var ErrKeyNotFound = apierr.New("ssh_key_not_found", "SSH key is not stored", http.StatusNotFound)

type Host struct {
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname,omitempty"`
	User            string   `json:"user,omitempty"`
	Port            int      `json:"port,omitempty"`
	IdentityFile    string   `json:"identityFile,omitempty"`
	Key             string   `json:"key,omitempty"`
	ExtraDirectives []string `json:"extraDirectives"`
	Managed         bool     `json:"managed"`
}

type HostList struct {
	Hosts []Host `json:"hosts"`
}

type Key struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

type KeyList struct {
	Keys []Key `json:"keys"`
}

type Config struct {
	UserPath string
	KeyDir   string
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

// An encrypted OpenSSH key still exposes its public half, so a passphrase-protected upload is accepted and the
// passphrase is asked for at login like any other prompt.
func publicKeyOf(private []byte) (ssh.PublicKey, error) {
	signer, err := ssh.ParsePrivateKey(private)
	if err == nil {
		return signer.PublicKey(), nil
	}
	var locked *ssh.PassphraseMissingError
	if errors.As(err, &locked) && locked.PublicKey != nil {
		return locked.PublicKey, nil
	}
	return nil, apierr.New("invalid_ssh_key", "The file is not an SSH private key.", http.StatusBadRequest)
}

func readKey(path string) (Key, error) {
	private, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	public, err := publicKeyOf(private)
	if err != nil {
		return Key{}, err
	}
	return Key{Name: filepath.Base(path), Type: public.Type(), Fingerprint: ssh.FingerprintSHA256(public)}, nil
}

func SafeName(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && safeNamePattern.MatchString(value)
}

func ValidAlias(value string) bool { return SafeName(value, 128) }

func ValidKeyName(value string) bool { return SafeName(value, 64) && !strings.HasSuffix(value, ".pub") }

func (c Config) List() ([]Host, error) {
	parsed, err := parseFile(c.UserPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	hosts := map[string]Host{}
	for _, host := range parsed {
		if c.KeyDir != "" && filepath.Dir(host.IdentityFile) == c.KeyDir {
			host.Key = filepath.Base(host.IdentityFile)
		}
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

func (c Config) ListKeys() ([]Key, error) {
	if c.KeyDir == "" {
		return []Key{}, nil
	}
	entries, err := os.ReadDir(c.KeyDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	keys := []Key{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !ValidKeyName(entry.Name()) {
			continue
		}
		key, err := readKey(filepath.Join(c.KeyDir, entry.Name()))
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (c Config) PutKey(name string, private []byte) (Key, error) {
	if !ValidKeyName(name) {
		return Key{}, ErrInvalidKeyName
	}
	if c.KeyDir == "" {
		return Key{}, errors.New("SSH key directory is required")
	}
	public, err := publicKeyOf(private)
	if err != nil {
		return Key{}, err
	}
	if err := os.MkdirAll(c.KeyDir, 0o700); err != nil {
		return Key{}, err
	}
	private = append(bytes.TrimRight(private, "\r\n"), '\n')
	if err := safeio.ReplaceFile(filepath.Join(c.KeyDir, name), private); err != nil {
		return Key{}, err
	}
	return Key{Name: name, Type: public.Type(), Fingerprint: ssh.FingerprintSHA256(public)}, nil
}

// Removing a key also unassigns it, so no host is left naming a file that is gone.
func (c Config) RemoveKey(name string) error {
	if !ValidKeyName(name) {
		return ErrInvalidKeyName
	}
	if c.KeyDir == "" {
		return ErrKeyNotFound
	}
	if err := os.Remove(filepath.Join(c.KeyDir, name)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrKeyNotFound
		}
		return err
	}
	hosts, err := c.List()
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if host.Managed && host.Key == name {
			if err := c.Update(c.WithKey(host, "")); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c Config) WithKey(host Host, name string) Host {
	host.Key = name
	host.IdentityFile = ""
	host.ExtraDirectives = slices.DeleteFunc(slices.Clone(host.ExtraDirectives), func(directive string) bool {
		return strings.EqualFold(strings.Join(strings.Fields(directive), " "), identitiesOnly)
	})
	if name != "" {
		host.IdentityFile = filepath.Join(c.KeyDir, name)
		host.ExtraDirectives = append(host.ExtraDirectives, identitiesOnly)
	}
	return host
}

func (c Config) AssignKey(host Host, name string) (Host, error) {
	if name == "" {
		return host, nil
	}
	if !ValidKeyName(name) {
		return Host{}, ErrInvalidKeyName
	}
	if _, err := os.Stat(filepath.Join(c.KeyDir, name)); c.KeyDir == "" || err != nil {
		return Host{}, ErrKeyNotFound
	}
	return c.WithKey(host, name), nil
}
