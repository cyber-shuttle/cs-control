package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const (
	discoveryMarkerPrefix = "__CSCTL_DSC_6f1c9a7e4b2d8053_"
	markerUserBegin       = discoveryMarkerPrefix + "USER_BEGIN__"
	markerUserEnd         = discoveryMarkerPrefix + "USER_END__"
	markerAccountsBegin   = discoveryMarkerPrefix + "ACCOUNTS_BEGIN__"
	markerAccountsEnd     = discoveryMarkerPrefix + "ACCOUNTS_END__"
	markerPartitionsBegin = discoveryMarkerPrefix + "PARTITIONS_BEGIN__"
	markerPartitionsEnd   = discoveryMarkerPrefix + "PARTITIONS_END__"
	markerHomeBegin       = discoveryMarkerPrefix + "HOME_BEGIN__"
	markerHomeEnd         = discoveryMarkerPrefix + "HOME_END__"
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
printf '%s\n' '` + markerUserBegin + `'
if csctl_user=$(id -un); then :; else
  printf '%s\n' '` + markerErrorUser + `'
  exit 71
fi
case "$csctl_user" in
  ''|*[!A-Za-z0-9_.-]*) printf '%s\n' '` + markerErrorUser + `'; exit 72 ;;
esac
[ "${#csctl_user}" -le 64 ] || { printf '%s\n' '` + markerErrorUser + `'; exit 72; }
printf '%s\n' "$csctl_user"
printf '%s\n' '` + markerUserEnd + `'
printf '%s\n' '` + markerAccountsBegin + `'
if sacctmgr show associations where "user=$csctl_user" format=Account -p; then
  printf '%s\n' '` + markerAccountsEnd + `'
else
  printf '%s\n' '` + markerErrorAccounts + `'
  exit 73
fi
printf '%s\n' '` + markerPartitionsBegin + `'
if sinfo -h -o '%P|%c|%m|%G'; then
  printf '%s\n' '` + markerPartitionsEnd + `'
else
  printf '%s\n' '` + markerErrorPartitions + `'
  exit 74
fi
printf '%s\n' '` + markerHomeBegin + `'
if printenv HOME; then
  printf '%s\n' '` + markerHomeEnd + `'
else
  printf '%s\n' '` + markerErrorHome + `'
  exit 75
fi
printf '%s\n' '` + markerDone + `'
`

type discoverySection int

const (
	discoveryExpectUser discoverySection = iota
	discoveryUser
	discoveryExpectAccounts
	discoveryAccounts
	discoveryExpectPartitions
	discoveryPartitions
	discoveryExpectHome
	discoveryHome
	discoveryExpectDone
	discoveryComplete
	discoveryFailed
)

type discoveryFramedOutput struct {
	remaining  int
	pending    []byte
	state      discoverySection
	username   bytes.Buffer
	accounts   bytes.Buffer
	partitions bytes.Buffer
	home       bytes.Buffer
	err        error
}

var (
	leadingDigits = regexp.MustCompile(`[0-9]+`)
	gresEntry     = regexp.MustCompile(`^(.+):([0-9]+)(?:\([^)]*\))?$`)
)

func newDiscoveryFramedOutput() *discoveryFramedOutput {
	return &discoveryFramedOutput{remaining: sshexec.MaxOutput, state: discoveryExpectUser}
}

func (o *discoveryFramedOutput) Write(data []byte) (int, error) {
	if len(data) > o.remaining {
		return len(data), errors.New("command output exceeded limit")
	}
	o.remaining -= len(data)
	o.pending = append(o.pending, data...)
	for {
		newline := bytes.IndexByte(o.pending, '\n')
		if newline < 0 {
			break
		}
		line := strings.TrimSuffix(string(o.pending[:newline]), "\r")
		o.pending = o.pending[newline+1:]
		o.consumeLine(line)
	}
	return len(data), nil
}

func (o *discoveryFramedOutput) consumeLine(line string) {
	if o.err != nil || o.state == discoveryFailed {
		return
	}
	if strings.HasPrefix(line, discoveryMarkerPrefix) {
		o.consumeMarker(line)
		return
	}
	var target *bytes.Buffer
	switch o.state {
	case discoveryUser:
		target = &o.username
	case discoveryAccounts:
		target = &o.accounts
	case discoveryPartitions:
		target = &o.partitions
	case discoveryHome:
		target = &o.home
	default:
		o.fail("unexpected discovery data outside a section")
		return
	}
	target.WriteString(line)
	target.WriteByte('\n')
}

func (o *discoveryFramedOutput) consumeMarker(marker string) {
	expect := func(state discoverySection, expected string, next discoverySection) bool {
		if o.state != state || marker != expected {
			return false
		}
		o.state = next
		return true
	}
	switch {
	case expect(discoveryExpectUser, markerUserBegin, discoveryUser):
	case expect(discoveryUser, markerUserEnd, discoveryExpectAccounts):
	case expect(discoveryExpectAccounts, markerAccountsBegin, discoveryAccounts):
	case expect(discoveryAccounts, markerAccountsEnd, discoveryExpectPartitions):
	case expect(discoveryExpectPartitions, markerPartitionsBegin, discoveryPartitions):
	case expect(discoveryPartitions, markerPartitionsEnd, discoveryExpectHome):
	case expect(discoveryExpectHome, markerHomeBegin, discoveryHome):
	case expect(discoveryHome, markerHomeEnd, discoveryExpectDone):
	case expect(discoveryExpectDone, markerDone, discoveryComplete):
	case marker == markerErrorUser && (o.state == discoveryUser || o.state == discoveryExpectUser):
		o.failCommand("identify remote user")
	case marker == markerErrorAccounts && o.state == discoveryAccounts:
		o.failCommand("query SLURM allocation accounts")
	case marker == markerErrorPartitions && o.state == discoveryPartitions:
		o.failCommand("query SLURM partitions")
	case marker == markerErrorHome && o.state == discoveryHome:
		o.failCommand("read remote home directory")
	default:
		o.fail("malformed, duplicate, or out-of-order discovery marker")
	}
}

func (o *discoveryFramedOutput) failCommand(operation string) {
	o.state = discoveryFailed
	o.err = fmt.Errorf("remote discovery failed to %s", operation)
}

func (o *discoveryFramedOutput) fail(message string) {
	o.state = discoveryFailed
	o.err = errors.New(message)
}

func (o *discoveryFramedOutput) result(alias string) (Resource, error) {
	if o.err != nil {
		return Resource{}, o.err
	}
	if len(o.pending) != 0 {
		return Resource{}, errors.New("discovery output ended with an incomplete line")
	}
	if o.state != discoveryComplete {
		return Resource{}, errors.New("discovery output ended before all sections completed")
	}
	username := strings.TrimSpace(o.username.String())
	if !namePattern.MatchString(username) {
		return Resource{}, errors.New("remote username is unsafe")
	}
	home := strings.TrimSpace(o.home.String())
	if !safeRemotePath(home) {
		return Resource{}, errors.New("remote HOME is unsafe")
	}
	partitions, err := parsePartitions(o.partitions.String())
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Host:       alias,
		Accounts:   parseAccounts(o.accounts.String()),
		Partitions: partitions,
		HomeDir:    home,
	}, nil
}

func (s Service) Discover(ctx context.Context, alias string) (Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	// One fixed exec channel runs all discovery commands sequentially. The
	// ControlMaster established by OpenSSH remains reusable by later operations.
	cmd, err := s.Runner.Command(ctx, alias, "sh -s")
	if err != nil {
		return Resource{}, err
	}
	cmd.Stdin = strings.NewReader(discoveryScript)
	stdout := newDiscoveryFramedOutput()
	stderr := sshexec.NewBoundedCapture("stderr")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := sshexec.RunCommand(ctx, cmd)
	if ctx.Err() != nil {
		return Resource{}, fmt.Errorf("ssh command timed out: %w", ctx.Err())
	}
	if runErr != nil {
		message := strings.TrimSpace(stderr.String())
		if sshexec.AuthenticationFailure(message) {
			return Resource{}, sshexec.AuthenticationRequired(alias)
		}
		if _, framedErr := stdout.result(alias); framedErr != nil {
			if message != "" {
				return Resource{}, fmt.Errorf("%w: %s", framedErr, message)
			}
			return Resource{}, framedErr
		}
		return Resource{}, fmt.Errorf("ssh command failed: %s", sshexec.FailureMessage(message, runErr))
	}
	return stdout.result(alias)
}

var _ io.Writer = (*discoveryFramedOutput)(nil)

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
