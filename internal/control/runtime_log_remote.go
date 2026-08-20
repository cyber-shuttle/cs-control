package control

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	pathpkg "path"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

const maxRuntimeLogCollections = 4

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
    printf '__CSCTL_RUNTIME_LOG__|%s|%s|' "$csctl_runtime_id" "$csctl_stream"
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

	// Each host batch uses one SSH command and contains at most four runtimes.
	// Hosts are processed in stable order so the cap cannot starve a later host.
	for _, host := range slices.Sorted(maps.Keys(byHost)) {
		if ctx.Err() != nil {
			return completed
		}
		ids := s.Logs.nextRuntimeLogBatch(host, byHost[host], maxRuntimeLogCollections)
		tails, err := s.readRemoteRuntimeTails(ctx, host, ids)
		if err != nil || ctx.Err() != nil {
			continue
		}
		for _, id := range ids {
			tail := tails[id]
			// Refresh exact values alongside each merge in case persisted runtime
			// metadata changed between reconciliation snapshots.
			s.Logs.SetRuntimeSensitive(id, s.runtimeLogSensitiveValues(byID[id])...)
			if mergeErr := s.Logs.MergeRemote(id, tail.stdout, tail.stderr); mergeErr == nil {
				completed[id] = struct{}{}
			}
		}
	}
	return completed
}

func (s Service) runtimeLogSensitiveValues(runtime Runtime) []string {
	cfg := s.effectiveConfig()
	socketName := runtime.JobName + ".sock"
	return []string{
		runtime.PrivateRoot,
		runtime.WorkspaceRoot,
		pathpkg.Join("/tmp", socketName),
		socketName,
		cfg.LinkspanPath,
	}
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
	result := make(map[string]remoteRuntimeTail, len(ids))
	seen := make(map[string]bool, len(ids)*2)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.SplitN(line, "|", 4)
		if len(parts) != 4 || parts[0] != "__CSCTL_RUNTIME_LOG__" || !requested[parts[1]] || (parts[2] != "stdout" && parts[2] != "stderr") {
			return nil, errors.New("invalid runtime log tail response")
		}
		key := parts[1] + "\x00" + parts[2]
		if seen[key] {
			return nil, errors.New("duplicate runtime log tail response")
		}
		seen[key] = true
		data, decodeErr := hex.DecodeString(parts[3])
		if decodeErr != nil || len(data) > maxRuntimeLogBytes {
			return nil, errors.New("invalid runtime log tail encoding")
		}
		tail := result[parts[1]]
		if parts[2] == "stdout" {
			tail.stdout = string(data)
		} else {
			tail.stderr = string(data)
		}
		result[parts[1]] = tail
	}
	for id := range requested {
		if !seen[id+"\x00stdout"] || !seen[id+"\x00stderr"] {
			return nil, fmt.Errorf("incomplete runtime log tail response for %s", id)
		}
	}
	return result, nil
}
