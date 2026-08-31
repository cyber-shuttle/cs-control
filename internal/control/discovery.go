package control

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/framed"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const (
	discoveryMarkerPrefix = "__CSCTL_DSC_6f1c9a7e4b2d8053_"
	markerUser            = discoveryMarkerPrefix + "USER__"
	markerAccounts        = discoveryMarkerPrefix + "ACCOUNTS__"
	markerPartitions      = discoveryMarkerPrefix + "PARTITIONS__"
	markerHome            = discoveryMarkerPrefix + "HOME__"
	markerDone            = discoveryMarkerPrefix + "DONE__"
	markerErrorUser       = discoveryMarkerPrefix + "ERROR_USER__"
	markerErrorAccounts   = discoveryMarkerPrefix + "ERROR_ACCOUNTS__"
	markerErrorPartitions = discoveryMarkerPrefix + "ERROR_PARTITIONS__"
	markerErrorHome       = discoveryMarkerPrefix + "ERROR_HOME__"
)

// discoveryScript is intentionally constant. No alias, username, path, or
// other persisted value is interpolated into the remote shell program.
const discoveryScript = `set -u
LC_ALL=C
LANG=C
export LC_ALL LANG
printf '%s\n' '` + markerUser + `'
if csctl_user=$(id -un); then :; else
  printf '%s\n' '` + markerErrorUser + `'
  exit 71
fi
case "$csctl_user" in
  ''|*[!A-Za-z0-9_.-]*) printf '%s\n' '` + markerErrorUser + `'; exit 72 ;;
esac
[ "${#csctl_user}" -le 64 ] || { printf '%s\n' '` + markerErrorUser + `'; exit 72; }
printf '%s\n' "$csctl_user"
printf '%s\n' '` + markerAccounts + `'
sacctmgr show associations where "user=$csctl_user" format=Account -p || {
  printf '%s\n' '` + markerErrorAccounts + `'
  exit 73
}
printf '%s\n' '` + markerPartitions + `'
sinfo -h -o '%P|%c|%m|%G' || {
  printf '%s\n' '` + markerErrorPartitions + `'
  exit 74
}
printf '%s\n' '` + markerHome + `'
printenv HOME || {
  printf '%s\n' '` + markerErrorHome + `'
  exit 75
}
printf '%s\n' '` + markerDone + `'
`

var (
	leadingDigits = regexp.MustCompile(`[0-9]+`)
	gresEntry     = regexp.MustCompile(`^(.+):([0-9]+)(?:\([^)]*\))?$`)
)

// discoveryResult reads the remote program's framed output. Every value it
// returns comes from a host this process does not trust, so an unsafe or
// unparsable one is a refusal rather than a resource.
func discoveryResult(alias, output string) (Resource, error) {
	for _, failure := range []struct{ marker, operation string }{
		{markerErrorUser, "identify remote user"},
		{markerErrorAccounts, "query SLURM allocation accounts"},
		{markerErrorPartitions, "query SLURM partitions"},
		{markerErrorHome, "read remote home directory"},
	} {
		if strings.Contains(output, failure.marker+"\n") {
			return Resource{}, fmt.Errorf("remote discovery failed to %s", failure.operation)
		}
	}
	sections, err := framed.Sections(output, discoveryMarkerPrefix, markerUser, markerAccounts, markerPartitions, markerHome, markerDone)
	if err != nil {
		return Resource{}, err
	}
	if strings.TrimSpace(sections[markerDone]) != "" {
		return Resource{}, errors.New("discovery output continued past its final marker")
	}
	if username := strings.TrimSpace(sections[markerUser]); !namePattern.MatchString(username) {
		return Resource{}, errors.New("remote username is unsafe")
	}
	home := strings.TrimSpace(sections[markerHome])
	if !safeRemotePath(home) {
		return Resource{}, errors.New("remote HOME is unsafe")
	}
	partitions, err := parsePartitions(sections[markerPartitions])
	if err != nil {
		return Resource{}, err
	}
	return Resource{Host: alias, Accounts: parseAccounts(sections[markerAccounts]), Partitions: partitions, HomeDir: home}, nil
}

// One fixed exec channel runs all discovery commands sequentially. The
// ControlMaster established by OpenSSH remains reusable by later operations.
func (s Service) Discover(ctx context.Context, alias string) (Resource, error) {
	// Resolving the configuration and running the program each apply the
	// runner's timeout, so the pair is bounded once here: a host that hangs at
	// both must not hold the request for twice as long.
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	stdout, stderr, runErr := s.Runner.RunOutput(ctx, alias, strings.NewReader(discoveryScript), "sh", "-s")
	// A host that demanded credentials or never answered explains the failure
	// better than the truncated output it produced on the way there.
	if runErr != nil && (errors.Is(runErr, context.DeadlineExceeded) || sshexec.AuthenticationFailure(stderr)) {
		return Resource{}, sshexec.ClassifyFailure(alias, stderr, runErr)
	}
	resource, err := discoveryResult(alias, stdout)
	switch {
	case runErr != nil && err != nil:
		return Resource{}, fmt.Errorf("%w: %s", err, sshexec.FailureMessage(stderr, runErr))
	case runErr != nil:
		return Resource{}, sshexec.ClassifyFailure(alias, stderr, runErr)
	}
	return resource, err
}

func parseAccounts(output string) []string {
	seen := map[string]bool{}
	accounts := []string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		account := strings.TrimSpace(strings.SplitN(line, "|", 2)[0])
		if strings.EqualFold(account, "Account") || !namePattern.MatchString(account) || seen[account] {
			continue
		}
		seen[account] = true
		accounts = append(accounts, account)
	}
	slices.Sort(accounts)
	return accounts
}

func parsePartitions(output string) ([]Partition, error) {
	partitions := []Partition{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid sinfo line: %q", line)
		}
		cpuText := leadingDigits.FindString(parts[1])
		memoryText := leadingDigits.FindString(parts[2])
		cpus, cpuErr := strconv.Atoi(cpuText)
		memory, memoryErr := strconv.Atoi(memoryText)
		if cpuErr != nil || memoryErr != nil {
			return nil, fmt.Errorf("invalid capacity in sinfo line: %q", line)
		}
		gres, err := parseGRES(strings.TrimSpace(parts[3]))
		if err != nil {
			return nil, err
		}
		partitions = append(partitions, Partition{Name: strings.TrimSuffix(strings.TrimSpace(parts[0]), "*"), CPUCount: cpus, MemoryMB: memory, GRES: gres})
	}
	return partitions, nil
}

func parseGRES(value string) ([]GRES, error) {
	if value == "" || value == "(null)" {
		return []GRES{}, nil
	}
	var entries []string
	start, depth := 0, 0
	for i, char := range value {
		switch char {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				entries = append(entries, strings.TrimSpace(value[start:i]))
				start = i + 1
			}
		}
	}
	entries = append(entries, strings.TrimSpace(value[start:]))
	result := make([]GRES, 0, len(entries))
	for _, entry := range entries {
		match := gresEntry.FindStringSubmatch(entry)
		if match == nil {
			return nil, fmt.Errorf("invalid GRES entry: %q", entry)
		}
		count, _ := strconv.Atoi(match[2])
		result = append(result, GRES{Name: match[1], Count: count})
	}
	return result, nil
}
