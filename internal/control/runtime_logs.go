package control

import (
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	maxRuntimeLogLines     = 100
	maxRuntimeLogBytes     = 64 << 10
	maxRuntimeLogLineBytes = 4 << 10
)

var runtimeCredentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	regexp.MustCompile(`\b(?:[a-f0-9]{64}|[a-f0-9]{32})\b`),
	regexp.MustCompile(`/[^\s'\"]*\.cybershuttle/runtimes/rt-[a-f0-9]{12}(?:/[^\s'\"]*)?`),
}

// RuntimeLogLine is one sanitized, browser-safe line of runtime startup output,
// timed when it was observed here: how long ago a stalled allocation last spoke.
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

// runtimeLogBuffer keeps this process's own narration, which accumulates, apart
// from the remote tail, which is replaced by whatever the last read returned.
type runtimeLogBuffer struct {
	statusBytes int
	status      []RuntimeLogLine
	remote      []RuntimeLogLine
}

func (b *runtimeLogBuffer) lines() []RuntimeLogLine {
	return append(append([]RuntimeLogLine(nil), b.status...), b.remote...)
}

// RuntimeLogs is a bounded process-local store for runtime startup output,
// deliberately independent of persisted runtime state.
type RuntimeLogs struct {
	mu        sync.RWMutex
	tails     map[string]*runtimeLogBuffer
	sensitive map[string][]string
	Now       func() time.Time
}

func NewRuntimeLogs() *RuntimeLogs {
	return &RuntimeLogs{tails: make(map[string]*runtimeLogBuffer), sensitive: make(map[string][]string)}
}

func (l *RuntimeLogs) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

// Forget drops a deleted runtime's tail, which a reused process would keep.
func (l *RuntimeLogs) Forget(runtimeID string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tails, runtimeID)
	delete(l.sensitive, runtimeID)
}

// Append sanitizes and appends CR/LF-delimited lines of this process's own
// narration. Repeating the final line is a no-op, so a periodic phase
// observation neither grows the tail nor advances its revision.
func (l *RuntimeLogs) Append(runtimeID, text string) {
	if l == nil || !idPattern.MatchString(runtimeID) {
		return
	}
	l.mu.RLock()
	sensitive := append([]string(nil), l.sensitive[runtimeID]...)
	l.mu.RUnlock()
	lines := sanitizedRuntimeLogLines(text, sensitive)
	if len(lines) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(runtimeID)
	for _, line := range lines {
		entry := RuntimeLogLine{Stream: "status", Text: line, At: l.now()}
		if last := len(buffer.status) - 1; last >= 0 && buffer.status[last].Stream == entry.Stream && buffer.status[last].Text == entry.Text {
			continue
		}
		buffer.status = append(buffer.status, entry)
		buffer.statusBytes += len(entry.Text)
		for len(buffer.status) > maxRuntimeLogLines || buffer.statusBytes > maxRuntimeLogBytes {
			buffer.statusBytes -= len(buffer.status[0].Text)
			buffer.status = buffer.status[1:]
		}
	}
}

// MergeRemote replaces the stored remote tail. The remote script always returns
// the whole bounded tail, so there is nothing to diff against the previous copy.
func (l *RuntimeLogs) MergeRemote(runtimeID, stdout, stderr string) {
	if l == nil || !idPattern.MatchString(runtimeID) {
		return
	}
	l.mu.RLock()
	sensitive := append([]string(nil), l.sensitive[runtimeID]...)
	l.mu.RUnlock()
	remote := make([]RuntimeLogLine, 0, maxRuntimeLogLines)
	for _, source := range []struct{ stream, text string }{{"stdout", stdout}, {"stderr", stderr}} {
		for _, line := range sanitizedRuntimeLogLines(source.text, sensitive) {
			remote = append(remote, RuntimeLogLine{Stream: source.stream, Text: line})
		}
	}
	if len(remote) > maxRuntimeLogLines {
		remote = remote[len(remote)-maxRuntimeLogLines:]
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(runtimeID)
	// A line that has not changed keeps the time it was first observed, so a
	// re-read of the same tail serialises identically and the poll's ETag holds.
	for i := range remote {
		remote[i].At = now
		if i < len(buffer.remote) && buffer.remote[i].Stream == remote[i].Stream && buffer.remote[i].Text == remote[i].Text {
			remote[i].At = buffer.remote[i].At
		}
	}
	buffer.remote = remote
}

func (l *RuntimeLogs) bufferLocked(runtimeID string) *runtimeLogBuffer {
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
// already owner-filtered set, so a tail never travels to a foreign principal.
func (s Service) ownedRuntimeTails(owned []Runtime) []RuntimeLogTail {
	tails := make([]RuntimeLogTail, 0, len(owned))
	for _, runtime := range owned {
		if tail, ok := s.Logs.Tail(runtime.ID); ok {
			tails = append(tails, tail)
		}
	}
	return tails
}

// SetRuntimeSensitive replaces the exact values redacted from one runtime's
// later output. Longer values apply first, so nested paths collapse to one marker.
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
	l.sensitive[runtimeID] = clean
	l.mu.Unlock()
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
		result = append(result, truncateUTF8(part, maxRuntimeLogLineBytes))
	}
	return result
}

func redactRuntimeLogLine(value string, sensitive []string) string {
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{"#!", "#SBATCH"} {
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

var (
	// A complete terminal control sequence in either encoding: CSI, the string
	// controls with their ST or BEL terminators, and a plain escape. Each has a
	// trailing alternative consuming an unterminated one to end of stream.
	terminalSequences = regexp.MustCompile(`(?s)(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|(?:\x1b\[|\x9b).*` +
		`|(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c)|(?:\x1b\]|\x9d).*` +
		`|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c)|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*` +
		`|\x1b[ -/]*[0-~]|\x1b[ -/]*`)
	// Everything else a terminal would act on. Line endings survive: the tail
	// is split on them.
	terminalControls = regexp.MustCompile(`[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f]`)
)

// stripRuntimeLogControls strips both 7-bit ESC and C1 introducers over the whole
// stream at once, so a string control cannot leak its payload by ending a line.
func stripRuntimeLogControls(value string) string {
	return terminalControls.ReplaceAllString(terminalSequences.ReplaceAllString(value, ""), "")
}

func (s Service) runtimeStatus(runtimeID, text string) { s.Logs.Append(runtimeID, text) }
