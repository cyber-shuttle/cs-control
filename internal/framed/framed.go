// Package framed reads marker-delimited output from a remote command. The
// remote program prints each section's name on a line of its own, followed by
// that section's content.
package framed

import (
	"errors"
	"strings"
)

// Sections returns the content of each named section. Every line beginning with
// prefix is a marker, and the markers must be exactly names, in that order: a
// missing, duplicate, out-of-order or unknown marker, data ahead of the first
// one, or a truncated final line is a refusal rather than something to parse,
// because the host that produced the output is not trusted.
func Sections(output, prefix string, names ...string) (map[string]string, error) {
	if output != "" && !strings.HasSuffix(output, "\n") {
		return nil, errors.New("framed output ended with an incomplete line")
	}
	sections := make(map[string]string, len(names))
	next, content := 0, []string(nil)
	flush := func() {
		if next > 0 {
			sections[names[next-1]] = strings.Join(content, "\n")
		}
		content = nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, prefix) {
			if next == 0 && line != "" {
				return nil, errors.New("framed output began outside a section")
			}
			content = append(content, line)
			continue
		}
		if next == len(names) || line != names[next] {
			return nil, errors.New("malformed, duplicate, or out-of-order framed marker")
		}
		flush()
		next++
	}
	flush()
	if next < len(names) {
		return nil, errors.New("framed output ended before all sections completed")
	}
	return sections, nil
}
