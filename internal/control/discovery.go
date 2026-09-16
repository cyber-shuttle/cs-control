// One fixed shell program run once per host, framed behind markers so login banner noise cannot be mistaken
// for content. It reads the remote username, Slurm accounts, sinfo partitions, and $HOME.
// This process does not trust the host, so an unsafe or unparsable value is a refusal.
//
//	discoveryMarkerPrefix, markerUser, markerAccounts, markerPartitions, markerHome, markerDone, markerErrorUser,
//	markerErrorAccounts, markerErrorPartitions, markerErrorHome
//	discoveryScript
//	leadingDigits, gresEntry
//	parseAccounts
//	parseGRES
//	parsePartitions
//	discoveryResult
//	Service
//	discover
package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
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

func parseAccounts(output string) []string {
	seen := map[string]bool{}
	accounts := []string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		account := strings.TrimSpace(strings.SplitN(line, "|", 2)[0])
		if strings.EqualFold(account, "Account") || !sshconfig.SafeName(account, 64) || seen[account] {
			continue
		}
		seen[account] = true
		accounts = append(accounts, account)
	}
	slices.Sort(accounts)
	return accounts
}

func parseGRES(value string) ([]gres, error) {
	if value == "" || value == "(null)" {
		return []gres{}, nil
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
	result := make([]gres, 0, len(entries))
	for _, entry := range entries {
		match := gresEntry.FindStringSubmatch(entry)
		if match == nil {
			return nil, fmt.Errorf("invalid GRES entry: %q", entry)
		}
		count, _ := strconv.Atoi(match[2])
		result = append(result, gres{Name: match[1], Count: count})
	}
	return result, nil
}

func parsePartitions(output string) ([]partition, error) {
	partitions := []partition{}
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
		partitions = append(partitions, partition{Name: strings.TrimSuffix(strings.TrimSpace(parts[0]), "*"), CPUCount: cpus, MemoryMB: memory, GRES: gres})
	}
	return partitions, nil
}

func discoveryResult(alias, output string) (resource, error) {
	for _, failure := range []struct{ marker, operation string }{
		{markerErrorUser, "identify remote user"},
		{markerErrorAccounts, "query the accounts the remote user is associated with"},
		{markerErrorPartitions, "query Slurm partitions"},
		{markerErrorHome, "read remote home directory"},
	} {
		if strings.Contains(output, failure.marker+"\n") {
			return resource{}, apierr.New("slurm_discovery_failed", "remote discovery failed to "+failure.operation, http.StatusBadGateway)
		}
	}
	parsed, err := sections(output, discoveryMarkerPrefix, []string{markerUser, markerAccounts, markerPartitions, markerHome, markerDone})
	if err != nil {
		return resource{}, err
	}
	if strings.TrimSpace(parsed[markerDone]) != "" {
		return resource{}, errors.New("discovery output continued past its final marker")
	}
	if username := strings.TrimSpace(parsed[markerUser]); !sshconfig.SafeName(username, 64) {
		return resource{}, errors.New("remote username is unsafe")
	}
	home := strings.TrimSpace(parsed[markerHome])
	if !safeRemotePath(home) {
		return resource{}, errors.New("remote HOME is unsafe")
	}
	partitions, err := parsePartitions(parsed[markerPartitions])
	if err != nil {
		return resource{}, err
	}
	return resource{Host: alias, Accounts: parseAccounts(parsed[markerAccounts]), Partitions: partitions, HomeDir: home}, nil
}

func (s Service) discover(ctx context.Context, alias string) (resource, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	stdout, stderr, runErr := s.Runner.RunOutput(ctx, alias, strings.NewReader(discoveryScript), "sh", "-s")
	if runErr != nil && (errors.Is(runErr, context.DeadlineExceeded) || sshexec.AuthenticationFailure(stderr)) {
		return resource{}, sshexec.ClassifyFailure(alias, stderr, runErr)
	}
	discovered, err := discoveryResult(alias, stdout)
	switch {
	case runErr != nil && err != nil:
		if classified := apierr.For(runErr); classified.Code != "internal_error" {
			return resource{}, runErr
		}
		return resource{}, fmt.Errorf("%w: %s", err, sshexec.FailureMessage(stderr, runErr))
	case runErr != nil:
		return resource{}, sshexec.ClassifyFailure(alias, stderr, runErr)
	}
	return discovered, err
}
