// The two things a session hands the scheduler: the constant batch script and the workflow Linkspan runs, plus
// the one round trip a login node gets before submission to install Linkspan and write that workflow there.
// Submission and validation share the same constant script, run through sbatch: a refusal from Slurm itself is
// an answer, not a failed call, but an ambiguous outcome may still be queued; provisioning is tracked by the
// Service, so a second caller for the same host is told to come back rather than race the first.
//
//	provisionTimeout, provisionScript, provisionFailures
//	submissionError
//	ambiguousSubmission, sessionWorkflowPath, minutesToWalltime, jobName, sessionLogBasename
//	validationMessage, buildValidationResult
//	buildScript
//	sessionWorkflow
//	provisionOutcome, provisionMessage
//	Error, Unwrap
//	Service
//	submitSessionScript, validateScript, provisionSession
package control

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const provisionTimeout = 5 * time.Minute

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
# The document below is the tasks form Linkspan reads from 0.19.0; an older
# Linkspan starts, refuses the document, and takes the session with it, so it
# is refused here instead.
version=$("$linkspan" --version 2>/dev/null | head -1 | tr -d 'v \r')
[ "$(printf '%s\n%s\n' 0.19.0 "$version" | sort -V | head -1)" = 0.19.0 ] || {
  printf '%s\n' 'error=linkspan-unsupported'; exit 81; }

# What the session is for travels with it, staged and moved so a partial
# write never becomes the document Linkspan reads.
umask 077
staged="$workflow.staged"
install -d -m 700 "$(dirname "$workflow")" 2>/dev/null &&
  printf '%s' "$document" | base64 -d > "$staged" 2>/dev/null &&
  [ -s "$staged" ] && mv -f "$staged" "$workflow" || {
    rm -f "$staged"; printf '%s\n' 'error=workflow'; exit 82; }
printf '%s\n' 'provision=complete'
`

var provisionFailures = map[string]string{
	"arguments":            "the host was given paths it could not use",
	"linkspan-directory":   "could not create the directory the Linkspan binary belongs in",
	"architecture":         "the host reports an architecture Linkspan is not released for",
	"linkspan-download":    "could not download the Linkspan release",
	"linkspan-install":     "could not install the downloaded Linkspan binary",
	"linkspan-unsupported": "the Linkspan on this host is older than 0.19.0, so it cannot read the workflow this session was given",
	"workflow":             "could not write the workflow the session runs",
}

type submissionError struct {
	cause     error
	ambiguous bool
}

func ambiguousSubmission(err error) bool {
	var submit *submissionError
	return errors.As(err, &submit) && submit.ambiguous
}

func sessionWorkflowPath(session Session) string {
	return strings.TrimSuffix(session.PrivateRoot, "/") + "/workflow.yaml"
}

func minutesToWalltime(minutes int) string {
	days, rest := minutes/(24*60), minutes%(24*60)
	hours, mins := rest/60, rest%60
	if days > 0 {
		return fmt.Sprintf("%d-%02d:%02d:00", days, hours, mins)
	}
	return fmt.Sprintf("%02d:%02d:00", hours, mins)
}

func jobName(id string, seq int) string { return "cs-" + id + "-" + strconv.Itoa(seq) }

func sessionLogBasename(id string, seq int) string { return id + "-" + strconv.Itoa(seq) }

func validationMessage(result commandResult) string {
	if result.passed {
		if message := strings.TrimSpace(result.stdout); message != "" {
			return message
		}
		return "Slurm accepted the job script."
	}
	if message := strings.TrimSpace(result.stderr); message != "" {
		return message
	}
	if message := strings.TrimSpace(result.stdout); message != "" {
		return message
	}
	return "Slurm rejected the job script."
}

func buildValidationResult(prepared *preparedSession, result commandResult) *validationResult {
	status := "FAILED"
	if result.passed {
		status = "PASSED"
	}
	return &validationResult{SessionID: prepared.session.ID, Script: prepared.script, Status: status, Message: validationMessage(result), Stdout: strings.TrimSpace(result.stdout), Stderr: strings.TrimSpace(result.stderr)}
}

func buildScript(session Session, linkspan string) string {
	walltime := minutesToWalltime(session.Resources.WallMinutes)
	lines := []string{"#!/bin/bash", "#SBATCH --nodes=1", "#SBATCH --ntasks=1", "#SBATCH --cpus-per-task=" + strconv.Itoa(session.Resources.Cores), "#SBATCH --mem=" + strconv.Itoa(session.Resources.MemoryMB) + "M", "#SBATCH --time=" + walltime, "#SBATCH --partition=" + session.Partition}
	if session.Account != "" {
		lines = append(lines, "#SBATCH --account="+session.Account)
	}
	if session.Resources.GPUCount > 0 {
		gres := "#SBATCH --gres=gpu:"
		if session.Resources.GPUType != "gpu" {
			gres += session.Resources.GPUType + ":"
		}
		lines = append(lines, gres+strconv.Itoa(session.Resources.GPUCount))
	}
	logBase := sessionLogBasename(session.ID, session.Seq)
	lines = append(lines,
		"set -eu", "umask 077", `LOG_DIR="$HOME/.cybershuttle/logs"`, `install -d -m 700 "$LOG_DIR"`, `exec >"$LOG_DIR/`+logBase+`.out" 2>"$LOG_DIR/`+logBase+`.err"`, "unset XDG_RUNTIME_DIR TMPDIR",
		"LINKSPAN_BIN="+sshexec.ShellQuote(linkspan),
		`exec "$LINKSPAN_BIN" --port "$CS_CONTROL_PORT" --tunnel-enable --tunnel-id "$CS_TUNNEL_ID" --tunnel-cluster "$CS_TUNNEL_CLUSTER" --tunnel-host-token "$CS_TUNNEL_HOST_TOKEN" --workflow `+sshexec.ShellQuote(sessionWorkflowPath(session)),
		"")
	return strings.Join(lines, "\n")
}

func sessionWorkflow(session Session) string {
	port := strconv.Itoa(int(sessionPorts(session.ID, session.Seq).jupyter))
	return strings.Join([]string{
		"name: cs-session",
		"tasks:",
		"  - on: start",
		"    steps:",
		"      - name: Start Jupyter Server",
		"        action: jupyter.sessions.start",
		"        params:",
		"          root_dir: " + fmt.Sprintf("%q", session.WorkspaceRoot),
		"          addr: " + fmt.Sprintf("%q", "127.0.0.1:"+port),
		"",
	}, "\n")
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
		return fmt.Sprintf("Preparing the session environment on %s failed: %s.", alias, reason)
	}
	if detail := strings.TrimSpace(stderr); detail != "" {
		return fmt.Sprintf("Preparing the session environment on %s failed: %s", alias, detail)
	}
	return "Preparing the session environment on " + alias + " failed."
}

func (e *submissionError) Error() string { return e.cause.Error() }

func (e *submissionError) Unwrap() error { return e.cause }

func (s Service) submitSessionScript(ctx context.Context, host string, session Session, script, jupyterToken, hostToken string) (string, error) {
	jobName := session.JobName
	ports := sessionPorts(session.ID, session.Seq)
	export := fmt.Sprintf("--export=ALL,JUPYTER_TOKEN=%s,CS_TUNNEL_HOST_TOKEN=%s,CS_CONTROL_PORT=%d,CS_TUNNEL_ID=%s,CS_TUNNEL_CLUSTER=%s",
		jupyterToken, hostToken, ports.control, session.Tunnel.ID, session.Tunnel.ClusterID)
	outText, errText, runErr := s.Runner.RunOutput(ctx, host, strings.NewReader(script), "sbatch", "--job-name="+jobName, export, "--parsable")
	if runErr != nil {
		cause := apierr.Redact(fmt.Sprintf("submit %s failed", jobName),
			errors.New(sshexec.FailureMessage(errText, runErr)), jupyterToken, hostToken)
		return "", &submissionError{cause: cause, ambiguous: sshexec.AmbiguousExit(runErr)}
	}
	jobID := strings.SplitN(strings.TrimSpace(outText), ";", 2)[0]
	if !jobPattern.MatchString(jobID) {
		return "", &submissionError{cause: fmt.Errorf("submit outcome pending reconciliation for %s: invalid job ID", jobName), ambiguous: true}
	}
	return jobID, nil
}

func (s Service) validateScript(ctx context.Context, alias, script string) (commandResult, error) {
	outText, errText, err := s.Runner.RunOutput(ctx, alias, strings.NewReader(script), "sbatch", "--test-only")
	if !sshexec.AmbiguousExit(err) {
		return commandResult{stdout: outText, stderr: errText, passed: err == nil}, nil
	}
	return commandResult{}, sshexec.ClassifyFailure(alias, errText, err)
}

func (s Service) provisionSession(ctx context.Context, alias string, session Session, home, linkspan string) error {
	key := s.Runner.Hosts.UserPath + "\x00" + alias
	if _, busy := s.HostPreparations.LoadOrStore(key, true); busy {
		return apierr.New("session_provisioning_in_progress",
			"The session environment on "+alias+" is still being prepared. Try again in a moment.", http.StatusConflict)
	}
	defer s.HostPreparations.Delete(key)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionTimeout)
	defer cancel()
	s.sessionStatus(session.ID, "Preparing the session environment")
	document := base64.StdEncoding.EncodeToString([]byte(sessionWorkflow(session)))
	remote := strings.Join([]string{
		sshexec.ShellQuote("sh"), sshexec.ShellQuote("-s"), sshexec.ShellQuote("--"),
		sshexec.ShellQuote("csctl-provision"), sshexec.ShellQuote(home), sshexec.ShellQuote(linkspan),
		sshexec.ShellQuote(sessionWorkflowPath(session)), sshexec.ShellQuote(document),
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
			return apierr.New("session_provisioning_failed", "Preparing the session environment on "+alias+" timed out.", http.StatusGatewayTimeout)
		}
		return apierr.New("session_provisioning_failed", provisionMessage(alias, report["error"], errText), http.StatusBadGateway)
	}
	if report["provision"] != "complete" {
		return apierr.New("session_provisioning_failed", provisionMessage(alias, report["error"], errText), http.StatusBadGateway)
	}
	if report["linkspan"] == "installed" {
		s.sessionStatus(session.ID, "Installed Linkspan")
	}
	s.sessionStatus(session.ID, "Session environment ready")
	return nil
}
