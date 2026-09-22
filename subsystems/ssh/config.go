// Host values parse from a pasted ssh command restricted to connection options and allowlisted directives, and
// render to one OpenSSH stanza. The parsed value is both the wire shape and the stored payload.
package ssh

import (
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

type hostEntry struct {
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname,omitempty"`
	User            string   `json:"user,omitempty"`
	Port            int      `json:"port,omitempty"`
	IdentityFile    string   `json:"identityFile,omitempty"`
	Key             string   `json:"key,omitempty"`
	ExtraDirectives []string `json:"extraDirectives"`
	Managed         bool     `json:"managed"`
}

type hostList struct {
	Hosts []hostEntry `json:"hosts"`
}

func (h hostEntry) stanza() []string {
	config := map[string][]string{}
	add := func(key, value string) { config[key] = append(config[key], value) }
	if h.Hostname != "" {
		add("hostname", h.Hostname)
	}
	if h.User != "" {
		add("user", h.User)
	}
	if h.Port != 0 && h.Port != 22 {
		add("port", strconv.Itoa(h.Port))
	}
	if h.IdentityFile != "" {
		add("identityfile", h.IdentityFile)
	}
	for _, directive := range h.ExtraDirectives {
		if key, value, found := strings.Cut(strings.TrimSpace(directive), " "); found {
			add(strings.ToLower(key), strings.TrimSpace(value))
		}
	}
	lines := []string{"Host " + h.Name}
	for _, key := range slices.Sorted(maps.Keys(config)) {
		for _, value := range config[key] {
			lines = append(lines, "    "+key+" "+value)
		}
	}
	return append(lines, "")
}

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

func invalid(message string) error {
	return security.New("invalid_ssh_command", message, http.StatusBadRequest)
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

func parseCommand(name, command string) (hostEntry, error) {
	if !ssh.ValidAlias(name) {
		return hostEntry{}, ssh.ErrInvalidAlias
	}
	fields := strings.Fields(command)
	if len(fields) > 0 && strings.EqualFold(filepath.Base(fields[0]), "ssh") {
		fields = fields[1:]
	}
	host := hostEntry{Name: name, Port: 22, ExtraDirectives: []string{}}
	target := ""
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if field == "--" {
			continue
		}
		if !strings.HasPrefix(field, "-") {
			if target != "" {
				return hostEntry{}, invalid("Remove the remote command; the entry describes the connection only.")
			}
			target = field
			continue
		}
		if len(field) < 2 || !strings.ContainsRune("pilJo", rune(field[1])) {
			return hostEntry{}, invalid(fmt.Sprintf("%s is not supported here. Keep the command to the host, user, port, identity, jump host, and -o options.", field))
		}
		value := field[2:]
		if value == "" {
			if index+1 >= len(fields) {
				return hostEntry{}, invalid(fmt.Sprintf("%s expects a value.", field))
			}
			index++
			value = fields[index]
		}
		var err error
		switch field[1] {
		case 'p':
			host.Port, err = strconv.Atoi(value)
			if err != nil || host.Port < 1 || host.Port > 65535 {
				return hostEntry{}, invalid(fmt.Sprintf("%q is not a port.", value))
			}
		case 'i':
			host.IdentityFile, err = validText("identity file path", value)
		case 'l':
			host.User, err = validText("user name", value)
		case 'J':
			var directive string
			directive, err = option("ProxyJump", value)
			host.ExtraDirectives = append(host.ExtraDirectives, directive)
		case 'o':
			key, setting, found := strings.Cut(value, "=")
			if !found {
				key, setting, found = strings.Cut(value, " ")
			}
			if !found {
				return hostEntry{}, invalid(fmt.Sprintf("%q is not an ssh option.", value))
			}
			canonical, ok := allowedOptions[strings.ToLower(strings.TrimSpace(key))]
			if !ok {
				return hostEntry{}, invalid(fmt.Sprintf("%s cannot be set from a pasted command.", strings.TrimSpace(key)))
			}
			var directive string
			directive, err = option(canonical, strings.TrimSpace(setting))
			host.ExtraDirectives = append(host.ExtraDirectives, directive)
		}
		if err != nil {
			return hostEntry{}, err
		}
	}
	if target == "" {
		return hostEntry{}, invalid("The command names no host.")
	}
	var err error
	if user, hostname, found := strings.Cut(target, "@"); found {
		if host.User, err = validText("user name", user); err != nil {
			return hostEntry{}, err
		}
		target = hostname
	}
	host.Hostname, err = validText("host name", target)
	return host, err
}
