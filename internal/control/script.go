// The two things a session hands the scheduler: the constant batch script, and the workflow Linkspan runs.
// Submission and validation share this file, since both run the identical script through sbatch.
// A refusal from Slurm itself is an answer, not a failed call, but an ambiguous outcome may still be queued.
//
//	submissionError, ambiguousSubmission
//	sessionWorkflowPath, minutesToWalltime, jobName, sessionLogBasename
//	validationMessage, buildValidationResult
//	buildScript
//	sessionWorkflow
//	Error, Unwrap
//	Service
//	submitSessionScript, validateScript
package control

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

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

func jobName(id, generation string) string { return "cs-" + id + "-" + generation }

func sessionLogBasename(id, generation string) string { return id + "-" + generation }

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
	logBase := sessionLogBasename(session.ID, session.Generation)
	lines = append(lines,
		"set -eu", "umask 077", `LOG_DIR="$HOME/.cybershuttle/logs"`, `install -d -m 700 "$LOG_DIR"`, `exec >"$LOG_DIR/`+logBase+`.out" 2>"$LOG_DIR/`+logBase+`.err"`, "unset XDG_RUNTIME_DIR TMPDIR",
		"LINKSPAN_BIN="+sshexec.ShellQuote(linkspan),
		`exec "$LINKSPAN_BIN" --port "$CS_CONTROL_PORT" --tunnel-enable --tunnel-id "$CS_TUNNEL_ID" --tunnel-cluster "$CS_TUNNEL_CLUSTER" --tunnel-host-token "$CS_TUNNEL_HOST_TOKEN" --workflow `+sshexec.ShellQuote(sessionWorkflowPath(session)),
		"")
	return strings.Join(lines, "\n")
}

func sessionWorkflow(session Session) string {
	port := strconv.Itoa(int(sessionPorts(session.ID, session.Generation).jupyter))
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

func (e *submissionError) Error() string { return e.cause.Error() }

func (e *submissionError) Unwrap() error { return e.cause }

func (s Service) submitSessionScript(ctx context.Context, host string, session Session, script, jupyterToken, hostToken string) (string, error) {
	jobName := session.JobName
	ports := sessionPorts(session.ID, session.Generation)
	export := fmt.Sprintf("--export=ALL,JUPYTER_TOKEN=%s,CS_TUNNEL_HOST_TOKEN=%s,CS_CONTROL_PORT=%d,CS_TUNNEL_ID=%s,CS_TUNNEL_CLUSTER=%s",
		jupyterToken, hostToken, ports.control, session.Tunnel.ID, session.Tunnel.ClusterID)
	outText, errText, runErr := s.Runner.RunOutput(ctx, host, strings.NewReader(script), "sbatch", "--job-name="+jobName, export, "--parsable")
	if runErr != nil {
		cause := devtunnel.SafeError(fmt.Sprintf("submit %s failed", jobName),
			errors.New(sshexec.FailureMessage(errText, runErr)), jupyterToken, hostToken)
		var exit *exec.ExitError
		ambiguous := !errors.As(runErr, &exit) || exit.ExitCode() == 255
		return "", &submissionError{cause: cause, ambiguous: ambiguous}
	}
	jobID := strings.SplitN(strings.TrimSpace(outText), ";", 2)[0]
	if !jobPattern.MatchString(jobID) {
		return "", &submissionError{cause: fmt.Errorf("submit outcome pending reconciliation for %s: invalid job ID", jobName), ambiguous: true}
	}
	return jobID, nil
}

func (s Service) validateScript(ctx context.Context, alias, script string) (commandResult, error) {
	outText, errText, err := s.Runner.RunOutput(ctx, alias, strings.NewReader(script), "sbatch", "--test-only")
	var exit *exec.ExitError
	if err == nil || errors.As(err, &exit) && exit.ExitCode() != 255 {
		return commandResult{stdout: outText, stderr: errText, passed: err == nil}, nil
	}
	return commandResult{}, sshexec.ClassifyFailure(alias, errText, err)
}
