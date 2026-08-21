package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// Installing an interpreter and a release archive is not a scheduler round
// trip, so provisioning gets its own budget rather than the SSH default.
const provisionTimeout = 15 * time.Minute

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
const provisionScript = `set -u
LC_ALL=C
LANG=C
export LC_ALL LANG
[ "$#" -eq 3 ]
[ "$1" = csctl-provision ]
shift
workspace=$1
linkspan=$2
case "$workspace$linkspan" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac
env_dir="$workspace/.cybershuttle/jupyter-env"
python="$env_dir/bin/python"
imports='import ipykernel, jupyter_server, jupyter_server_terminals'

if [ -x "$python" ] && "$python" -c "$imports" >/dev/null 2>&1; then
  printf '%s\n' 'jupyter=present'
else
  uv=""
  for candidate in "$HOME/.local/bin/uv" "$(command -v uv 2>/dev/null)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then uv=$candidate; break; fi
  done
  if [ -z "$uv" ]; then
    curl -LsSf https://astral.sh/uv/install.sh 2>/dev/null | sh >/dev/null 2>&1 || {
      printf '%s\n' 'error=uv-install'; exit 71; }
    uv="$HOME/.local/bin/uv"
  fi
  [ -x "$uv" ] || { printf '%s\n' 'error=uv-missing'; exit 72; }
  install -d -m 700 "$workspace/.cybershuttle" || { printf '%s\n' 'error=workspace'; exit 73; }
  "$uv" venv --quiet --clear --python ` + provisionPythonVersion + ` "$env_dir" >/dev/null 2>&1 || {
    printf '%s\n' 'error=python'; exit 74; }
  "$uv" pip install --quiet --python "$python" jupyter-server ipykernel jupyter-server-terminals >/dev/null 2>&1 || {
    printf '%s\n' 'error=jupyter'; exit 75; }
  "$python" -c "$imports" >/dev/null 2>&1 || { printf '%s\n' 'error=jupyter-verify'; exit 76; }
  printf '%s\n' 'jupyter=installed'
fi

if [ -x "$linkspan" ]; then
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
printf '%s\n' 'provision=complete'
`

// What each refusal means to the person who asked for a runtime.
var provisionFailures = map[string]string{
	"uv-install":         "could not install uv, which builds the managed Jupyter environment",
	"uv-missing":         "uv is not executable after installation",
	"arguments":          "the host was given paths it could not use",
	"workspace":          "could not create the .cybershuttle directory in the workspace",
	"python":             "could not create the Python " + provisionPythonVersion + " environment",
	"jupyter":            "could not install Jupyter Server into the environment",
	"jupyter-verify":     "the Jupyter environment is missing its own packages after installation",
	"linkspan-directory": "could not create the directory the Linkspan binary belongs in",
	"architecture":       "the host reports an architecture Linkspan is not released for",
	"linkspan-download":  "could not download the Linkspan release",
	"linkspan-install":   "could not install the downloaded Linkspan binary",
}

// provisionRuntime makes a host able to run a runtime before one is submitted
// to it. A host that already has both is left untouched, so this costs one
// round trip on every allocation after the first.
func (s Service) provisionRuntime(ctx context.Context, alias string, prepared *preparedRuntime) error {
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	s.runtimeStatus(prepared.runtime.ID, "Preparing the runtime environment")
	remote := strings.Join([]string{
		sshexec.ShellQuote("sh"), sshexec.ShellQuote("-s"), sshexec.ShellQuote("--"),
		sshexec.ShellQuote("csctl-provision"),
		sshexec.ShellQuote(prepared.runtime.WorkspaceRoot), sshexec.ShellQuote(prepared.linkspan),
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
		{"jupyter", "Jupyter environment"},
		{"linkspan", "Linkspan"},
	} {
		if report[installed.key] == "installed" {
			s.runtimeStatus(prepared.runtime.ID, "Installed "+installed.what)
		}
	}
	s.runtimeStatus(prepared.runtime.ID, "Runtime environment ready")
	return nil
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
