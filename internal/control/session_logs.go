// Session logs hold two kinds of narration: accumulating phase updates, and a remote stdout and stderr tail.
// Both are process-local, so a restart loses them and a terminal session's tail moves into its run record.
// Every line is sanitized and redacted before it is stored, since it reaches a browser.
//
//	maxSessionLogLines, maxSessionLogBytes, maxSessionLogLineBytes, sessionCredentialPatterns
//	sessionLogLine, sessionLogTail, sessionLogBuffer, sessionLogs
//	maxSessionLogCollections, sessionLogMarkerPrefix, sessionLogTailScript, remoteSessionTail, sessionLogTarget
//	terminalSequences, terminalControls
//	lines, stripSessionLogControls, redactSessionLogLine, sanitizedSessionLogLines
//	sessionLogMarker, decodeSessionLogTail
//	Forget, Append, MergeRemote, bufferLocked, Tail, SetSessionSensitive
//	NewSessionLogs
//	Service
//	ownedSessionTails, sessionStatus, sessionLogSensitiveValues
//	readRemoteSessionTails
//	collectStartingSessionLogs
package control

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

const (
	maxSessionLogLines     = 100
	maxSessionLogBytes     = 64 << 10
	maxSessionLogLineBytes = 4 << 10
)

var sessionCredentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	regexp.MustCompile(`\b(?:[a-f0-9]{64}|[a-f0-9]{32})\b`),
	regexp.MustCompile(`/[^\s'\"]*\.cybershuttle/sessions/s-[a-f0-9]{12}(?:/[^\s'\"]*)?`),
}

type sessionLogLine struct {
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

type sessionLogTail struct {
	SessionID string           `json:"sessionId"`
	Lines     []sessionLogLine `json:"lines"`
}

type sessionLogBuffer struct {
	statusBytes int
	status      []sessionLogLine
	remote      []sessionLogLine
}

type sessionLogs struct {
	mu        sync.RWMutex
	tails     map[string]*sessionLogBuffer
	sensitive map[string][]string
}

const (
	maxSessionLogCollections = 4
	sessionLogMarkerPrefix   = "__CSCTL_SESSION_LOG__"
)

const sessionLogTailScript = `set -eu
[ "$#" -ge 3 ]
[ "$1" = csctl-session-log-tail ]
shift
[ "$#" -le 8 ]
[ $(( $# % 2 )) -eq 0 ]
while [ "$#" -gt 0 ]; do
  csctl_session_id=$1
  csctl_seq=$2
  shift 2
  case "$csctl_session_id" in
    s-????????????) ;;
    *) exit 64 ;;
  esac
  case "${csctl_session_id#s-}" in
    *[!a-f0-9]*) exit 64 ;;
  esac
  case "$csctl_seq" in
    ''|*[!0-9]*) exit 64 ;;
  esac
  [ "$csctl_seq" -ge 1 ] || exit 64
  for csctl_stream in stdout stderr; do
    case "$csctl_stream" in
      stdout) csctl_suffix=out ;;
      stderr) csctl_suffix=err ;;
    esac
    csctl_log_path=$HOME/.cybershuttle/logs/$csctl_session_id-$csctl_seq.$csctl_suffix
    printf '` + sessionLogMarkerPrefix + `|%s|%s\n' "$csctl_session_id" "$csctl_stream"
    if [ -f "$csctl_log_path" ] && [ ! -L "$csctl_log_path" ]; then
      tail -n 100 -- "$csctl_log_path" | tail -c 16384 | od -An -v -tx1 | tr -d ' \n'
    fi
    printf '\n'
  done
done
`

type remoteSessionTail struct {
	stdout string
	stderr string
}

type sessionLogTarget struct {
	id  string
	seq int
}

var (
	terminalSequences = regexp.MustCompile(`(?s)(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|(?:\x1b\[|\x9b).*` +
		`|(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c)|(?:\x1b\]|\x9d).*` +
		`|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c)|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*` +
		`|\x1b[ -/]*[0-~]|\x1b[ -/]*`)
	terminalControls = regexp.MustCompile(`[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f]`)
)

func (b *sessionLogBuffer) lines() []sessionLogLine {
	return append(append([]sessionLogLine(nil), b.status...), b.remote...)
}

func stripSessionLogControls(value string) string {
	return terminalControls.ReplaceAllString(terminalSequences.ReplaceAllString(value, ""), "")
}

func redactSessionLogLine(value string, sensitive []string) string {
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{"#!", "#SBATCH"} {
		if strings.HasPrefix(trimmed, prefix) {
			return "[redacted]"
		}
	}
	for _, secret := range sensitive {
		value = strings.ReplaceAll(value, secret, "[redacted]")
	}
	for _, pattern := range sessionCredentialPatterns {
		value = pattern.ReplaceAllString(value, "[redacted]")
	}
	return value
}

func sanitizedSessionLogLines(value string, sensitive []string) []string {
	if value == "" {
		return nil
	}
	value = strings.ToValidUTF8(value, "�")
	value = stripSessionLogControls(value)
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	parts := strings.Split(value, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = redactSessionLogLine(part, sensitive)
		result = append(result, apierr.TruncateUTF8(part, maxSessionLogLineBytes))
	}
	return result
}

func sessionLogMarker(sessionID, stream string) string {
	return sessionLogMarkerPrefix + "|" + sessionID + "|" + stream
}

func decodeSessionLogTail(section string) (string, error) {
	data, err := hex.DecodeString(strings.TrimSpace(section))
	if err != nil || len(data) > maxSessionLogBytes {
		return "", errors.New("invalid session log tail encoding")
	}
	return string(data), nil
}

func (l *sessionLogs) Forget(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tails, sessionID)
	delete(l.sensitive, sessionID)
}

func (l *sessionLogs) Append(sessionID, text string, now time.Time) {
	if !idPattern.MatchString(sessionID) {
		return
	}
	l.mu.RLock()
	sensitive := append([]string(nil), l.sensitive[sessionID]...)
	l.mu.RUnlock()
	lines := sanitizedSessionLogLines(text, sensitive)
	if len(lines) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(sessionID)
	for _, line := range lines {
		entry := sessionLogLine{Stream: "status", Text: line, At: now}
		if last := len(buffer.status) - 1; last >= 0 && buffer.status[last].Stream == entry.Stream && buffer.status[last].Text == entry.Text {
			continue
		}
		buffer.status = append(buffer.status, entry)
		buffer.statusBytes += len(entry.Text)
		for len(buffer.status) > maxSessionLogLines || buffer.statusBytes > maxSessionLogBytes {
			buffer.statusBytes -= len(buffer.status[0].Text)
			buffer.status = buffer.status[1:]
		}
	}
}

func (l *sessionLogs) MergeRemote(sessionID, stdout, stderr string, now time.Time) bool {
	if !idPattern.MatchString(sessionID) {
		return false
	}
	l.mu.RLock()
	sensitive := append([]string(nil), l.sensitive[sessionID]...)
	l.mu.RUnlock()
	remote := make([]sessionLogLine, 0, maxSessionLogLines)
	for _, source := range []struct{ stream, text string }{{"stdout", stdout}, {"stderr", stderr}} {
		for _, line := range sanitizedSessionLogLines(source.text, sensitive) {
			remote = append(remote, sessionLogLine{Stream: source.stream, Text: line})
		}
	}
	if len(remote) > maxSessionLogLines {
		remote = remote[len(remote)-maxSessionLogLines:]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(sessionID)
	for i := range remote {
		remote[i].At = now
		if i < len(buffer.remote) && buffer.remote[i].Stream == remote[i].Stream && buffer.remote[i].Text == remote[i].Text {
			remote[i].At = buffer.remote[i].At
		}
	}
	buffer.remote = remote
	return len(buffer.remote) > 0
}

func (l *sessionLogs) bufferLocked(sessionID string) *sessionLogBuffer {
	buffer := l.tails[sessionID]
	if buffer == nil {
		buffer = &sessionLogBuffer{}
		l.tails[sessionID] = buffer
	}
	return buffer
}

func (l *sessionLogs) Tail(sessionID string) (sessionLogTail, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	buffer := l.tails[sessionID]
	if buffer == nil {
		return sessionLogTail{}, false
	}
	lines := buffer.lines()
	if len(lines) == 0 {
		return sessionLogTail{}, false
	}
	return sessionLogTail{SessionID: sessionID, Lines: lines}, true
}

func (l *sessionLogs) SetSessionSensitive(sessionID string, values ...string) {
	if !idPattern.MatchString(sessionID) {
		return
	}
	unique := make(map[string]bool, len(values))
	clean := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && value != "/" && len(value) >= 3 && !unique[value] {
			unique[value] = true
			clean = append(clean, value)
		}
	}
	slices.SortFunc(clean, func(a, b string) int { return len(b) - len(a) })
	l.mu.Lock()
	l.sensitive[sessionID] = clean
	l.mu.Unlock()
}

func NewSessionLogs() *sessionLogs {
	return &sessionLogs{tails: make(map[string]*sessionLogBuffer), sensitive: make(map[string][]string)}
}

func (s Service) ownedSessionTails(owned []Session) []sessionLogTail {
	tails := make([]sessionLogTail, 0, len(owned))
	for _, session := range owned {
		if tail, ok := s.Logs.Tail(session.ID); ok {
			tails = append(tails, tail)
		}
	}
	return tails
}

func (s Service) sessionStatus(sessionID, text string) { s.Logs.Append(sessionID, text, s.now()) }

func (s Service) sessionLogSensitiveValues(session Session) []string {
	return []string{session.PrivateRoot, session.WorkspaceRoot, s.linkspanPath()}
}

func (s Service) readRemoteSessionTails(ctx context.Context, host string, targets []sessionLogTarget) (map[string]remoteSessionTail, error) {
	if len(targets) == 0 || len(targets) > maxSessionLogCollections {
		return nil, errors.New("session log tail request must contain one to four IDs")
	}
	args := []string{"sh", "-s", "--", "csctl-session-log-tail"}
	requested := make(map[string]bool, len(targets))
	for _, target := range targets {
		if !idPattern.MatchString(target.id) || target.seq < 1 || requested[target.id] {
			return nil, errors.New("session log tail ID is invalid")
		}
		requested[target.id] = true
		args = append(args, target.id, strconv.Itoa(target.seq))
	}
	output, err := s.Runner.Run(ctx, host, strings.NewReader(sessionLogTailScript), args...)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, 2*len(targets))
	for _, target := range targets {
		names = append(names, sessionLogMarker(target.id, "stdout"), sessionLogMarker(target.id, "stderr"))
	}
	parsed, err := sections(output, sessionLogMarkerPrefix, names)
	if err != nil {
		return nil, err
	}
	result := make(map[string]remoteSessionTail, len(targets))
	for _, target := range targets {
		stdout, err := decodeSessionLogTail(parsed[sessionLogMarker(target.id, "stdout")])
		if err != nil {
			return nil, err
		}
		stderr, err := decodeSessionLogTail(parsed[sessionLogMarker(target.id, "stderr")])
		if err != nil {
			return nil, err
		}
		result[target.id] = remoteSessionTail{stdout: stdout, stderr: stderr}
	}
	return result, nil
}

func (s Service) collectStartingSessionLogs(ctx context.Context, sessions []Session) map[string]struct{} {
	started := make(map[string]struct{})
	if ctx.Err() != nil {
		return started
	}
	starting := make([]Session, 0, len(sessions))
	for _, session := range sessions {
		if session.State == "STARTING" && idPattern.MatchString(session.ID) &&
			session.Seq >= 1 && sshconfig.ValidAlias(session.SSHHost) {
			starting = append(starting, session)
		}
	}
	slices.SortFunc(starting, func(a, b Session) int {
		return cmp.Or(strings.Compare(a.SSHHost, b.SSHHost), strings.Compare(a.ID, b.ID))
	})
	for _, session := range starting {
		s.Logs.SetSessionSensitive(session.ID, s.sessionLogSensitiveValues(session)...)
	}
	byScope := groupByScope(starting, func(session Session) schedulerScope {
		return schedulerScope{owner: session.Owner, host: session.SSHHost}
	})

	for _, scope := range sortedScopes(byScope) {
		targets := make([]sessionLogTarget, len(byScope[scope]))
		for i, session := range byScope[scope] {
			targets[i] = sessionLogTarget{id: session.ID, seq: session.Seq}
		}
		for chunk := range slices.Chunk(targets, maxSessionLogCollections) {
			if ctx.Err() != nil {
				return started
			}
			tails, err := s.forPrincipal(scope.owner).readRemoteSessionTails(ctx, scope.host, chunk)
			if err != nil || ctx.Err() != nil {
				continue
			}
			for _, target := range chunk {
				if s.Logs.MergeRemote(target.id, tails[target.id].stdout, tails[target.id].stderr, s.now()) {
					started[target.id] = struct{}{}
				}
			}
		}
	}
	return started
}
