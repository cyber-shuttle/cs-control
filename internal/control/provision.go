package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
)

// Two downloads is not a scheduler round trip, so this gets its own budget
// rather than the SSH default.
const provisionTimeout = 5 * time.Minute

// The interpreter the managed Jupyter environment is built on. Jupyter Server
// requires 3.10 or newer, and uv supplies the version rather than the host.
const provisionPythonVersion = "3.12"

// provisionScript is intentionally constant. The workspace root and the
// Linkspan path arrive as arguments, so nothing derived from a request is ever
// written into the remote shell program.
//
// It is the same install every time: present and working is left alone, absent
// or broken is replaced, and each outcome is reported as one line the caller
// turns into runtime status.
// provisionScript is intentionally constant. The home and the Linkspan path
// arrive as arguments, so nothing derived from a request is ever written into
// the remote shell program.
//
// It installs the two binaries an allocation needs before it can run: Linkspan,
// which the job execs, and uv, which the workflow inside the job builds the
// environment with. Everything else -- the environment, its dependencies, the
// server -- belongs to the allocation and happens through Linkspan. Both are
// single downloads, so this stays a matter of seconds.
const provisionScript = `set -u
LC_ALL=C
LANG=C
export LC_ALL LANG
[ "$#" -eq 3 ]
[ "$1" = csctl-provision ]
shift
home=$1
linkspan=$2
case "$home$linkspan" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac

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
keep=0
# Only a plain version number can win: an unversioned build ("dev") sorts above
# every release under sort -V, which would make it permanent.
case "$installed" in ''|*[!0-9.]*) installed="" ;; esac
if [ -n "$installed" ]; then
  if [ -z "$latest" ]; then
    # Nothing to compare against; a working binary is worth more than a guess.
    keep=1
  elif [ "$installed" != "$latest" ] &&
       [ "$(printf '%s\n%s\n' "$installed" "$latest" | sort -V | tail -1)" = "$installed" ]; then
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
}

// provisionRuntime makes a host able to run a runtime before one is submitted
// to it. A host that already has both is left untouched, so this costs one
// round trip on every allocation after the first.
// provisionRuntime gives a host the two binaries an allocation needs and the
// workflow that allocation will run. The runtime is the durable one: its
// workflow names the ports this generation was given.
func (s Service) provisionRuntime(ctx context.Context, alias string, runtime Runtime, linkspan string) error {
	// One preparation per host at a time. A second caller is told to come back
	// rather than made to wait behind an install it cannot see, and never runs
	// a second uv against the environment the first one is building.
	release, busy := hostPreparations.begin(alias)
	if busy {
		return apierr.New("runtime_provisioning_in_progress",
			"The runtime environment on "+alias+" is still being prepared. Try again in a moment.", http.StatusConflict)
	}
	defer release()
	// Installing an environment is the host's business, not this request's: a
	// caller that goes away must not leave a half-built one behind.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionTimeout)
	defer cancel()
	s.runtimeStatus(runtime.ID, "Preparing the runtime environment")
	remote := strings.Join([]string{
		sshexec.ShellQuote("sh"), sshexec.ShellQuote("-s"), sshexec.ShellQuote("--"),
		sshexec.ShellQuote("csctl-provision"), sshexec.ShellQuote(runtime.HomeDir), sshexec.ShellQuote(linkspan),
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
	// What the allocation is for travels with it: the workflow Linkspan runs is
	// installed here, alongside the binaries it needs.
	if err := s.installRuntimeWorkflow(ctx, alias, runtime); err != nil {
		return err
	}
	s.runtimeStatus(runtime.ID, "Runtime environment ready")
	return nil
}

// hostPreparations is process-wide because "is this host being prepared" is a
// fact about the host, not about any one request.
var hostPreparations = preparations{active: map[string]bool{}}

type preparations struct {
	mu     sync.Mutex
	active map[string]bool
}

func (p *preparations) begin(alias string) (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[alias] {
		return func() {}, true
	}
	p.active[alias] = true
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.active, alias)
	}, false
}

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
