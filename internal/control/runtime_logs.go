package control

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxRuntimeLogLines     = 100
	maxRuntimeLogBytes     = 64 << 10
	maxRuntimeLogLineBytes = 4 << 10
)

var (
	errInvalidRuntimeLogStream = errors.New("runtime log stream must be status, stdout, or stderr")
	runtimeCredentialPatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
		regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		regexp.MustCompile(`\b(?:[a-f0-9]{64}|[a-f0-9]{32})\b`),
		regexp.MustCompile(`/[^\s'\"]*\.cybershuttle/runtimes/rt-[a-f0-9]{12}(?:/[^\s'\"]*)?`),
		regexp.MustCompile(`/[^\s'\"]*cs-rt-[a-f0-9]{12}\.sock`),
	}
)

// RuntimeLogLine is one sanitized, browser-safe line of runtime startup output.
// The time is when the line was observed here, which is what an owner reading a
// stalled allocation needs: how long ago it last said anything.
type RuntimeLogLine struct {
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
}

// RuntimeLogTail is the complete current process-local tail for one runtime.
type RuntimeLogTail struct {
	RuntimeID string           `json:"runtimeId"`
	Lines     []RuntimeLogLine `json:"lines"`
}

// runtimeLogBuffer keeps this process's own narration apart from the remote
// tail. Narration accumulates; the remote tail is whatever the last read
// returned, so it is replaced rather than merged and there is nothing to
// reconcile between two copies of the same file.
type runtimeLogBuffer struct {
	statusBytes int
	status      []RuntimeLogLine
	remote      []RuntimeLogLine
}

func (b *runtimeLogBuffer) lines() []RuntimeLogLine {
	return append(append([]RuntimeLogLine(nil), b.status...), b.remote...)
}

// RuntimeLogs is a focused, bounded process-local store for runtime startup
// output. It is intentionally independent of persisted runtime state.
type RuntimeLogs struct {
	mu        sync.RWMutex
	tails     map[string]*runtimeLogBuffer
	sensitive map[string][]string
	cursors   map[string]int
	Now       func() time.Time
}

func NewRuntimeLogs() *RuntimeLogs {
	return &RuntimeLogs{
		tails:     make(map[string]*runtimeLogBuffer),
		sensitive: make(map[string][]string),
		cursors:   make(map[string]int),
	}
}

func (l *RuntimeLogs) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

// Forget drops a deleted runtime's tail so a reused process does not keep
// output for an allocation the owner has removed.
func (l *RuntimeLogs) Forget(runtimeID string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tails, runtimeID)
	delete(l.sensitive, runtimeID)
	delete(l.cursors, runtimeID)
}

// Append sanitizes and appends one or more CR/LF-delimited lines. Repeating the
// current final line is a no-op so periodic phase observations do not grow the
// tail or advance its revision.
func (l *RuntimeLogs) Append(runtimeID, stream, text string) error {
	if stream != "status" && stream != "stdout" && stream != "stderr" {
		return errInvalidRuntimeLogStream
	}
	if l == nil || !idPattern.MatchString(runtimeID) {
		return nil
	}
	l.mu.RLock()
	sensitive := append([]string(nil), l.sensitive[runtimeID]...)
	l.mu.RUnlock()
	lines := sanitizedRuntimeLogLines(text, sensitive)
	if len(lines) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(runtimeID)
	for _, line := range lines {
		entry := RuntimeLogLine{Stream: stream, Text: line, At: l.now()}
		if len(buffer.status) > 0 && buffer.status[len(buffer.status)-1] == entry {
			continue
		}
		buffer.status = append(buffer.status, entry)
		buffer.statusBytes += len(entry.Text)
		for len(buffer.status) > maxRuntimeLogLines || buffer.statusBytes > maxRuntimeLogBytes {
			buffer.statusBytes -= len(buffer.status[0].Text)
			buffer.status = buffer.status[1:]
		}
	}
	return nil
}

// MergeRemote replaces the stored remote tail with what the last read returned.
// The remote script always returns the whole bounded tail, so there is nothing
// to diff against the previous copy.
func (l *RuntimeLogs) MergeRemote(runtimeID, stdout, stderr string) error {
	if l == nil || !idPattern.MatchString(runtimeID) {
		return nil
	}
	l.mu.RLock()
	sensitive := append([]string(nil), l.sensitive[runtimeID]...)
	l.mu.RUnlock()
	remote := make([]RuntimeLogLine, 0, maxRuntimeLogLines)
	for _, stream := range []string{"stdout", "stderr"} {
		text := stdout
		if stream == "stderr" {
			text = stderr
		}
		for _, line := range sanitizedRuntimeLogLines(text, sensitive) {
			remote = append(remote, RuntimeLogLine{Stream: stream, Text: line, At: l.now()})
		}
	}
	if len(remote) > maxRuntimeLogLines {
		remote = remote[len(remote)-maxRuntimeLogLines:]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bufferLocked(runtimeID).remote = remote
	return nil
}

func (l *RuntimeLogs) bufferLocked(runtimeID string) *runtimeLogBuffer {
	if l.tails == nil {
		l.tails = make(map[string]*runtimeLogBuffer)
	}
	buffer := l.tails[runtimeID]
	if buffer == nil {
		buffer = &runtimeLogBuffer{}
		l.tails[runtimeID] = buffer
	}
	return buffer
}

// Tail returns an isolated copy of one runtime's current tail.
func (l *RuntimeLogs) Tail(runtimeID string) (RuntimeLogTail, bool) {
	if l == nil {
		return RuntimeLogTail{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	buffer := l.tails[runtimeID]
	if buffer == nil {
		return RuntimeLogTail{}, false
	}
	lines := buffer.lines()
	if len(lines) == 0 {
		return RuntimeLogTail{}, false
	}
	return RuntimeLogTail{RuntimeID: runtimeID, Lines: lines}, true
}

// ownedRuntimeTails returns the tail of each supplied runtime. Callers pass the
// already owner-filtered set, so a tail can never travel to a principal that
// does not own the runtime that produced it.
func (s Service) ownedRuntimeTails(owned []Runtime) []RuntimeLogTail {
	if s.Logs == nil {
		return nil
	}
	tails := make([]RuntimeLogTail, 0, len(owned))
	for _, runtime := range owned {
		if tail, ok := s.Logs.Tail(runtime.ID); ok {
			tails = append(tails, tail)
		}
	}
	return tails
}

// SetRuntimeSensitive replaces the exact values that must be removed from all
// subsequently stored output for one runtime. Longer values are applied first
// so nested paths collapse to one stable marker.
func (l *RuntimeLogs) SetRuntimeSensitive(runtimeID string, values ...string) {
	if l == nil || !idPattern.MatchString(runtimeID) {
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
	if l.sensitive == nil {
		l.sensitive = make(map[string][]string)
	}
	l.sensitive[runtimeID] = clean
	l.mu.Unlock()
}

// nextRuntimeLogBatch advances a process-local per-host cursor. Stable input
// order plus this cursor guarantees bounded collection without extra SSH rounds.
func (l *RuntimeLogs) nextRuntimeLogBatch(host string, ids []string, limit int) []string {
	if l == nil || len(ids) == 0 || limit <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cursors == nil {
		l.cursors = make(map[string]int)
	}
	start := l.cursors[host] % len(ids)
	count := limit
	if len(ids) < count {
		count = len(ids)
	}
	selected := make([]string, count)
	for i := 0; i < count; i++ {
		selected[i] = ids[(start+i)%len(ids)]
	}
	l.cursors[host] = (start + count) % len(ids)
	return selected
}

func sanitizedRuntimeLogLines(value string, sensitive []string) []string {
	if value == "" {
		return nil
	}
	value = strings.ToValidUTF8(value, "�")
	value = stripRuntimeLogControls(value)
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	parts := strings.Split(value, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = redactRuntimeLogLine(part, sensitive)
		result = append(result, truncateRuntimeLogLine(part))
	}
	return result
}

func truncateRuntimeLogLine(value string) string {
	if len(value) <= maxRuntimeLogLineBytes {
		return value
	}
	value = value[:maxRuntimeLogLineBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func redactRuntimeLogLine(value string, sensitive []string) string {
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{"#!", "#SBATCH", "TOKEN_FILE=", "READY_FILE=", "PRIVATE_ROOT=", "WORKSPACE_ROOT="} {
		if strings.HasPrefix(trimmed, prefix) {
			return "[redacted]"
		}
	}
	for _, secret := range sensitive {
		value = strings.ReplaceAll(value, secret, "[redacted]")
	}
	for _, pattern := range runtimeCredentialPatterns {
		value = pattern.ReplaceAllString(value, "[redacted]")
	}
	return value
}

// stripRuntimeLogControls removes complete terminal control sequences for both
// 7-bit ESC and UTF-8 C1 introducers. Parsing the complete stream retains string
// control state across line endings. It never interprets terminal content.
func stripRuntimeLogControls(value string) string {
	runes := []rune(value)
	var output strings.Builder
	for i := 0; i < len(runes); {
		switch runes[i] {
		case 0x1b:
			i = skipANSISequence(runes, i)
			continue
		case 0x9b:
			i = skipCSI(runes, i+1)
			continue
		case 0x9d:
			i = skipANSIString(runes, i+1, true)
			continue
		case 0x90, 0x98, 0x9e, 0x9f:
			i = skipANSIString(runes, i+1, false)
			continue
		}
		r := runes[i]
		if r == '\r' || r == '\n' {
			output.WriteRune(r)
			i++
			continue
		}
		if (r >= 0 && r < 0x20) || (r >= 0x7f && r <= 0x9f) {
			i++
			continue
		}
		output.WriteRune(r)
		i++
	}
	return output.String()
}

func skipANSISequence(value []rune, start int) int {
	if start+1 >= len(value) {
		return len(value)
	}
	switch value[start+1] {
	case '[':
		return skipCSI(value, start+2)
	case ']':
		return skipANSIString(value, start+2, true)
	case 'P', 'X', '^', '_':
		return skipANSIString(value, start+2, false)
	}
	// ECMA-48 escape sequences are ESC, zero or more intermediate bytes
	// (0x20-0x2f), then one final byte (0x30-0x7e). Incomplete sequences are
	// consumed through the end rather than exposing their payload.
	i := start + 1
	for i < len(value) && value[i] >= 0x20 && value[i] <= 0x2f {
		i++
	}
	if i < len(value) && value[i] >= 0x30 && value[i] <= 0x7e {
		return i + 1
	}
	return len(value)
}

func skipCSI(value []rune, start int) int {
	intermediates := false
	for i := start; i < len(value); i++ {
		switch {
		case value[i] >= 0x40 && value[i] <= 0x7e:
			return i + 1
		case value[i] >= 0x30 && value[i] <= 0x3f && !intermediates:
			continue
		case value[i] >= 0x20 && value[i] <= 0x2f:
			intermediates = true
		default:
			return len(value)
		}
	}
	return len(value)
}

func skipANSIString(value []rune, start int, allowBEL bool) int {
	for i := start; i < len(value); i++ {
		if value[i] == 0x9c || (allowBEL && value[i] == 0x07) {
			return i + 1
		}
		if value[i] == 0x1b && i+1 < len(value) && value[i+1] == '\\' {
			return i + 2
		}
	}
	return len(value)
}

// Work done for a host rather than for a runtime has no tail to write to.
func (s Service) runtimeStatus(runtimeID, text string) {
	if s.Logs != nil && runtimeID != "" {
		_ = s.Logs.Append(runtimeID, "status", text)
	}
}
