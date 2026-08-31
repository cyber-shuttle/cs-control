package control

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// Two downloads is not a scheduler round trip, so this gets its own budget
// rather than the SSH default.
const provisionTimeout = 5 * time.Minute

// The interpreter the managed Jupyter environment is built on. Jupyter Server
// requires 3.10 or newer, and uv supplies the version rather than the host.
const provisionPythonVersion = "3.12"

// provisionScript is intentionally constant: the paths and the workflow document
// arrive as arguments, so nothing derived from a request is written into the
// remote shell program.
//
// It installs the two binaries an allocation needs before it can run --
// Linkspan, which the job execs, and uv, which the workflow builds the
// environment with -- writes the workflow that allocation will run, and reports
// each outcome as one line the caller turns into runtime status. Present and
// working is left alone; absent or broken is replaced.
const provisionScript = `set -u
LC_ALL=C
LANG=C
export LC_ALL LANG
[ "$#" -eq 5 ] && [ "$1" = csctl-provision ] || { printf '%s\n' 'error=arguments'; exit 70; }
shift
home=$1
linkspan=$2
workflow=$3
document=$4
case "$home" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac
case "$linkspan" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac
case "$workflow" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac

uv="$home/.local/bin/uv"
if [ -x "$uv" ] || command -v uv >/dev/null 2>&1; then
  printf '%s\n' 'uv=present'
else
  curl -LsSf https://astral.sh/uv/install.sh 2>/dev/null | sh >/dev/null 2>&1 || {
    printf '%s\n' 'error=uv-install'; exit 71; }
  [ -x "$uv" ] || { printf '%s\n' 'error=uv-missing'; exit 72; }
  printf '%s\n' 'uv=installed'
fi

# Newest wins, and a tie goes to the release: a build made by hand carries a
# version above the published one and is left alone, while a release that has
# caught up (same tag or higher) replaces it. Both installers follow this rule,
# so neither can undo the other.
installed=""
[ -x "$linkspan" ] && installed=$("$linkspan" --version 2>/dev/null | head -1 | tr -d 'v \r')
latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
  https://github.com/cyber-shuttle/linkspan/releases/latest 2>/dev/null | sed 's#.*/##' | tr -d 'v \r')
# What is installed is X.Y.Z for a release or X.Y.Z.<commit> for a build ahead
# of one; anything else -- an unversioned build above all else -- sorts above
# every release under sort -V, so it does not count as a version at all. What is
# published is always a release, so equal numbers mean the release has caught up
# and takes over, whether what is installed is a build or the same release.
installed=$(printf '%s' "$installed" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9a-f]{7,40})?$')
numbers=$(printf '%s' "$installed" | cut -d. -f1-3)
latest=$(printf '%s' "$latest" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+$')
keep=0
if [ -n "$installed" ]; then
  if [ -z "$latest" ]; then
    # No published release to compare against; a working binary beats a guess.
    keep=1
  elif [ "$numbers" != "$latest" ]; then
    [ "$(printf '%s\n%s\n' "$numbers" "$latest" | sort -V | tail -1)" = "$numbers" ] && keep=1
  elif [ "$installed" = "$numbers" ]; then
    # The published release is already the one installed: nothing to fetch. A
    # build ahead of it carries the commit that says so, and yields to it.
    keep=1
  fi
fi
if [ "$keep" = 1 ]; then
  printf '%s\n' 'linkspan=present'
else
  bin_dir=$(dirname "$linkspan")
  install -d -m 700 "$bin_dir" 2>/dev/null || { printf '%s\n' 'error=linkspan-directory'; exit 77; }
  arch=$(uname -m)
  case "$arch" in
    x86_64) arch=x86_64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) printf '%s\n' 'error=architecture'; exit 78 ;;
  esac
  staged="$bin_dir/.linkspan.$$"
  # Staged and moved, so a partial download never becomes the binary a job execs.
  curl -fsSL "https://github.com/cyber-shuttle/linkspan/releases/latest/download/linkspan_Linux_${arch}.tar.gz" 2>/dev/null |
    tar -xzO linkspan > "$staged" 2>/dev/null || {
      rm -f "$staged"; printf '%s\n' 'error=linkspan-download'; exit 79; }
  [ -s "$staged" ] || { rm -f "$staged"; printf '%s\n' 'error=linkspan-download'; exit 79; }
  chmod 700 "$staged" && mv -f "$staged" "$linkspan" || {
    rm -f "$staged"; printf '%s\n' 'error=linkspan-install'; exit 80; }
  printf '%s\n' 'linkspan=installed'
fi
# An allocation hosts a tunnel the control plane created, which needs a
# host-scoped token. A Linkspan without that flag starts, refuses the argument,
# and takes the allocation with it, so it is refused here instead.
"$linkspan" --help 2>&1 | grep -q -- '-tunnel-host-token' || {
  printf '%s\n' 'error=linkspan-unsupported'; exit 81; }

# What the allocation is for travels with it, staged and moved so a partial
# write never becomes the document Linkspan reads.
umask 077
staged="$workflow.staged"
install -d -m 700 "$(dirname "$workflow")" 2>/dev/null &&
  printf '%s' "$document" | base64 -d > "$staged" 2>/dev/null &&
  [ -s "$staged" ] && mv -f "$staged" "$workflow" || {
    rm -f "$staged"; printf '%s\n' 'error=workflow'; exit 82; }
printf '%s\n' 'provision=complete'
`

// What each refusal means to the person who asked for a runtime.
var provisionFailures = map[string]string{
	"uv-install":           "could not install uv, which the allocation builds its environment with",
	"uv-missing":           "uv is not executable after installation",
	"arguments":            "the host was given paths it could not use",
	"linkspan-directory":   "could not create the directory the Linkspan binary belongs in",
	"architecture":         "the host reports an architecture Linkspan is not released for",
	"linkspan-download":    "could not download the Linkspan release",
	"linkspan-install":     "could not install the downloaded Linkspan binary",
	"linkspan-unsupported": "the Linkspan on this host has no --tunnel-host-token, so it cannot host the tunnel this runtime was given",
	"workflow":             "could not write the workflow the allocation runs",
}

// provisionRuntime gives a host the two binaries an allocation needs and the
// workflow that allocation will run, in one round trip, before the runtime is
// submitted to it. What is already there is left untouched. The runtime is the
// durable one: its workflow names the ports this generation was given.
func (s Service) provisionRuntime(ctx context.Context, alias string, runtime Runtime, home, linkspan string) error {
	// One preparation per host at a time. A second caller is told to come back
	// rather than made to wait behind an install it cannot see, and never runs
	// a second uv against the environment the first one is building.
	if _, busy := hostPreparations.LoadOrStore(alias, true); busy {
		return apierr.New("runtime_provisioning_in_progress",
			"The runtime environment on "+alias+" is still being prepared. Try again in a moment.", http.StatusConflict)
	}
	defer hostPreparations.Delete(alias)
	// Installing an environment is the host's business, not this request's: a
	// caller that goes away must not leave a half-built one behind.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionTimeout)
	defer cancel()
	s.runtimeStatus(runtime.ID, "Preparing the runtime environment")
	document := base64.StdEncoding.EncodeToString([]byte(runtimeWorkflow(runtime, home)))
	remote := strings.Join([]string{
		sshexec.ShellQuote("sh"), sshexec.ShellQuote("-s"), sshexec.ShellQuote("--"),
		sshexec.ShellQuote("csctl-provision"), sshexec.ShellQuote(home), sshexec.ShellQuote(linkspan),
		sshexec.ShellQuote(runtimeWorkflowPath(runtime)), sshexec.ShellQuote(document),
	}, " ")
	cmd, err := s.Runner.Command(ctx, alias, remote)
	if err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(provisionScript)
	outText, errText, runErr := sshexec.RunBounded(ctx, cmd)
	report := provisionOutcome(outText)
	if runErr != nil {
		if ctx.Err() != nil {
			return apierr.New("runtime_provisioning_failed", "Preparing the runtime environment on "+alias+" timed out.", http.StatusGatewayTimeout)
		}
		return apierr.New("runtime_provisioning_failed", provisionMessage(alias, report["error"], errText), http.StatusBadGateway)
	}
	if report["provision"] != "complete" {
		return apierr.New("runtime_provisioning_failed", provisionMessage(alias, report["error"], errText), http.StatusBadGateway)
	}
	for _, installed := range []struct{ key, what string }{
		{"uv", "uv"},
		{"linkspan", "Linkspan"},
	} {
		if report[installed.key] == "installed" {
			s.runtimeStatus(runtime.ID, "Installed "+installed.what)
		}
	}
	s.runtimeStatus(runtime.ID, "Runtime environment ready")
	return nil
}

// hostPreparations is process-wide because "is this host being prepared" is a
// fact about the host, not about any one request.
var hostPreparations sync.Map

func provisionOutcome(output string) map[string]string {
	report := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if key, value, found := strings.Cut(strings.TrimSpace(line), "="); found {
			report[key] = value
		}
	}
	return report
}

func provisionMessage(alias, failure, stderr string) string {
	if reason, known := provisionFailures[failure]; known {
		return fmt.Sprintf("Preparing the runtime environment on %s failed: %s.", alias, reason)
	}
	if detail := strings.TrimSpace(stderr); detail != "" {
		return fmt.Sprintf("Preparing the runtime environment on %s failed: %s", alias, detail)
	}
	return "Preparing the runtime environment on " + alias + " failed."
}
