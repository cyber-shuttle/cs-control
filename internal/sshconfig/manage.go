package sshconfig

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
)

// Entries this package writes live between these two markers. Everything
// outside them is the user's own configuration: it is read, never rewritten,
// and the hosts it declares cannot be removed through the API.
const (
	blockBegin = "# >>> cybershuttle managed >>>"
	blockEnd   = "# <<< cybershuttle managed <<<"
)

// A directive value ends up in the user's config file and then in an ssh
// argument vector, so it carries no whitespace, quoting, or line break.
var valuePattern = regexp.MustCompile(`^[A-Za-z0-9_@%:./+=,~-]{1,256}$`)

// Options that only name how a connection authenticates or keeps itself alive.
// Anything that can run a local program (ProxyCommand, LocalCommand) or pull in
// more configuration (Include, Match) is absent by intent.
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

func invalid(message string) error {
	return apierr.New("invalid_ssh_command", message, http.StatusBadRequest)
}

// ParseCommand turns the ssh command a user knows works into the host entry
// that reproduces it, so the alias they later select connects the same way.
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
			if !valuePattern.MatchString(text) {
				return Host{}, invalid("The identity file path carries characters an ssh config cannot hold.")
			}
			host.IdentityFile = text
		case strings.HasPrefix(field, "-l"):
			text, err := value()
			if err != nil {
				return Host{}, err
			}
			if !valuePattern.MatchString(text) {
				return Host{}, invalid("The user name carries characters an ssh config cannot hold.")
			}
			host.User = text
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
		if !valuePattern.MatchString(user) {
			return Host{}, invalid("The user name carries characters an ssh config cannot hold.")
		}
		host.User, target = user, hostname
	}
	if !valuePattern.MatchString(target) {
		return Host{}, invalid("The host name carries characters an ssh config cannot hold.")
	}
	host.Hostname = target
	return host, nil
}

func option(key, value string) (string, error) {
	if !valuePattern.MatchString(value) {
		return "", invalid(fmt.Sprintf("The %s value carries characters an ssh config cannot hold.", key))
	}
	return key + " " + value, nil
}

// Add writes the entry into the managed block, creating the block when this is
// the first one. An alias the user already declares is never overwritten.
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

// Remove deletes an entry this package wrote. A host the user declares
// elsewhere in their configuration is reported rather than rewritten.
func (c Config) Remove(alias string) error {
	if !ValidAlias(alias) {
		return ErrInvalidAlias
	}
	return c.rewrite(func(lines []string) ([]string, error) {
		begin, end := blockBounds(lines)
		if begin < 0 {
			return nil, errUnmanaged(alias)
		}
		for index := begin + 1; index < end; index++ {
			fields := strings.Fields(lines[index])
			if len(fields) != 2 || !strings.EqualFold(fields[0], "Host") || fields[1] != alias {
				continue
			}
			stop := index + 1
			for stop < end && !strings.EqualFold(firstField(lines[stop]), "Host") {
				stop++
			}
			return append(lines[:index:index], lines[stop:]...), nil
		}
		return nil, errUnmanaged(alias)
	})
}

func errUnmanaged(alias string) error {
	return apierr.New("ssh_host_not_managed", fmt.Sprintf("%s comes from your own SSH configuration; edit it there.", alias), http.StatusConflict)
}

func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
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

// rewrite replaces the user's config in one atomic step, so a failed write
// never leaves a half-written configuration behind.
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
	return safeio.ReplaceFile(path, []byte(strings.Join(updated, "\n")+"\n"), nil)
}
