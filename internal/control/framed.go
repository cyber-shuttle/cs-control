// Marker-delimited output from a remote command. Each section's name is printed on a line of its own.
// The host is not trusted, so an out-of-order, missing, duplicate, or unknown marker is a refusal.
//
//	sections
package control

import (
	"errors"
	"strings"
)

func sections(output, prefix string, names []string) (map[string]string, error) {
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
			if next == 0 {
				continue
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
