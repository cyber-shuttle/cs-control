package control

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/framed"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

const (
	maxRuntimeLogCollections = 4
	runtimeLogMarkerPrefix   = "__CSCTL_RUNTIME_LOG__"
)

const runtimeLogTailScript = `set -eu
[ "$#" -ge 2 ]
[ "$1" = csctl-runtime-log-tail ]
shift
[ "$#" -le 4 ]
for csctl_runtime_id in "$@"; do
  case "$csctl_runtime_id" in
    rt-????????????) ;;
    *) exit 64 ;;
  esac
  case "${csctl_runtime_id#rt-}" in
    *[!a-f0-9]*) exit 64 ;;
  esac
  for csctl_stream in stdout stderr; do
    case "$csctl_stream" in
      stdout) csctl_suffix=out ;;
      stderr) csctl_suffix=err ;;
    esac
    csctl_log_path=$HOME/.cybershuttle/logs/$csctl_runtime_id.$csctl_suffix
    printf '__CSCTL_RUNTIME_LOG__|%s|%s\n' "$csctl_runtime_id" "$csctl_stream"
    if [ -f "$csctl_log_path" ] && [ ! -L "$csctl_log_path" ]; then
      tail -n 100 -- "$csctl_log_path" | tail -c 65536 | od -An -v -tx1 | tr -d ' \n'
    fi
    printf '\n'
  done
done
`

type remoteRuntimeTail struct {
	stdout string
	stderr string
}

func (s Service) collectStartingRuntimeLogs(ctx context.Context, runtimes []Runtime) map[string]struct{} {
	completed := make(map[string]struct{})
	if s.Logs == nil || ctx.Err() != nil {
		return completed
	}
	starting := make([]Runtime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime.State == "STARTING" && idPattern.MatchString(runtime.ID) && sshconfig.ValidAlias(runtime.SSHHost) {
			starting = append(starting, runtime)
		}
	}
	slices.SortFunc(starting, func(a, b Runtime) int {
		return cmp.Or(strings.Compare(a.SSHHost, b.SSHHost), strings.Compare(a.ID, b.ID))
	})
	byHost := make(map[string][]string)
	byID := make(map[string]Runtime, len(starting))
	for _, runtime := range starting {
		byHost[runtime.SSHHost] = append(byHost[runtime.SSHHost], runtime.ID)
		byID[runtime.ID] = runtime
		s.Logs.SetRuntimeSensitive(runtime.ID, s.runtimeLogSensitiveValues(runtime)...)
	}

	// One SSH command per batch, sized by what the remote script accepts.
	for _, host := range slices.Sorted(maps.Keys(byHost)) {
		for ids := range slices.Chunk(byHost[host], maxRuntimeLogCollections) {
			if ctx.Err() != nil {
				return completed
			}
			tails, err := s.readRemoteRuntimeTails(ctx, host, ids)
			if err != nil || ctx.Err() != nil {
				continue
			}
			for _, id := range ids {
				// Refresh exact values alongside each merge in case persisted runtime
				// metadata changed between reconciliation snapshots.
				s.Logs.SetRuntimeSensitive(id, s.runtimeLogSensitiveValues(byID[id])...)
				s.Logs.MergeRemote(id, tails[id].stdout, tails[id].stderr)
				completed[id] = struct{}{}
			}
		}
	}
	return completed
}

func (s Service) runtimeLogSensitiveValues(runtime Runtime) []string {
	return []string{runtime.PrivateRoot, runtime.WorkspaceRoot, s.effectiveConfig().LinkspanPath}
}

func (s Service) readRemoteRuntimeTails(ctx context.Context, host string, ids []string) (map[string]remoteRuntimeTail, error) {
	if len(ids) == 0 || len(ids) > maxRuntimeLogCollections {
		return nil, errors.New("runtime log tail request must contain one to four IDs")
	}
	args := []string{"sh", "-s", "--", "csctl-runtime-log-tail"}
	requested := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !idPattern.MatchString(id) || requested[id] {
			return nil, errors.New("runtime log tail ID is invalid")
		}
		requested[id] = true
		args = append(args, id)
	}
	output, err := s.Runner.Run(ctx, host, strings.NewReader(runtimeLogTailScript), args...)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, 2*len(ids))
	for _, id := range ids {
		names = append(names, runtimeLogMarker(id, "stdout"), runtimeLogMarker(id, "stderr"))
	}
	sections, err := framed.Sections(output, runtimeLogMarkerPrefix, names...)
	if err != nil {
		return nil, err
	}
	result := make(map[string]remoteRuntimeTail, len(ids))
	for _, id := range ids {
		stdout, err := decodeRuntimeLogTail(sections[runtimeLogMarker(id, "stdout")])
		if err != nil {
			return nil, err
		}
		stderr, err := decodeRuntimeLogTail(sections[runtimeLogMarker(id, "stderr")])
		if err != nil {
			return nil, err
		}
		result[id] = remoteRuntimeTail{stdout: stdout, stderr: stderr}
	}
	return result, nil
}

func runtimeLogMarker(runtimeID, stream string) string {
	return runtimeLogMarkerPrefix + "|" + runtimeID + "|" + stream
}

func decodeRuntimeLogTail(section string) (string, error) {
	data, err := hex.DecodeString(strings.TrimSpace(section))
	if err != nil || len(data) > maxRuntimeLogBytes {
		return "", errors.New("invalid runtime log tail encoding")
	}
	return string(data), nil
}
