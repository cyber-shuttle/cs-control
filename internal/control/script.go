package control

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

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

func (s Service) submitRuntimeScript(ctx context.Context, host, jobName, script, jupyterToken string, secrets ...string) (string, error) {
	hostToken := ""
	if len(secrets) > 0 {
		hostToken = secrets[0]
	}
	export := "--export=ALL,CS_JUPYTER_TOKEN=" + jupyterToken + ",CS_TUNNEL_HOST_TOKEN=" + hostToken
	remote := strings.Join([]string{sshexec.ShellQuote("sbatch"), sshexec.ShellQuote(export), sshexec.ShellQuote("--parsable")}, " ")
	commandCtx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	cmd, err := s.Runner.Command(commandCtx, host, remote)
	if err != nil {
		return "", &submissionError{cause: fmt.Errorf("submit outcome pending reconciliation for %s: %w", jobName, err), ambiguous: true}
	}
	cmd.Stdin = strings.NewReader(script)
	outText, errText, runErr := sshexec.RunBounded(commandCtx, cmd)
	if runErr != nil {
		message := strings.TrimSpace(errText)
		if message == "" {
			message = runErr.Error()
		}
		for _, secret := range append([]string{jupyterToken}, secrets...) {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
		}
		ambiguous := commandCtx.Err() != nil
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			ambiguous = exit.ExitCode() == 255
		} else if commandCtx.Err() == nil {
			ambiguous = true
		}
		return "", &submissionError{cause: fmt.Errorf("submit %s failed: %s", jobName, message), ambiguous: ambiguous}
	}
	jobID := strings.SplitN(strings.TrimSpace(outText), ";", 2)[0]
	if !jobPattern.MatchString(jobID) {
		return "", &submissionError{cause: fmt.Errorf("submit outcome pending reconciliation for %s: invalid job ID", jobName), ambiguous: true}
	}
	return jobID, nil
}

func (s Service) validateScript(ctx context.Context, alias, script string) (commandResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	cmd, err := s.Runner.Command(ctx, alias, sshexec.ShellQuote("sbatch")+" "+sshexec.ShellQuote("--test-only"))
	if err != nil {
		return commandResult{}, err
	}
	cmd.Stdin = strings.NewReader(script)
	outText, errText, err := sshexec.RunBounded(ctx, cmd)
	result := commandResult{stdout: outText, stderr: errText, passed: err == nil}
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return commandResult{}, fmt.Errorf("slurm validation timed out: %w", ctx.Err())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() != 255 {
		return result, nil
	}
	message := strings.TrimSpace(errText)
	if sshexec.AuthenticationFailure(message) {
		return commandResult{}, sshexec.AuthenticationRequired(alias)
	}
	if message == "" {
		message = err.Error()
	}
	return commandResult{}, fmt.Errorf("validate Slurm script over SSH: %s", message)
}

func validationResult(prepared *preparedRuntime, result commandResult) *ValidationResult {
	status := "FAILED"
	if result.passed {
		status = "PASSED"
	}
	return &ValidationResult{RuntimeID: prepared.runtime.ID, Script: prepared.script, Status: status, Message: validationMessage(result), Stdout: strings.TrimSpace(result.stdout), Stderr: strings.TrimSpace(result.stderr)}
}

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

func buildScript(runtime Runtime, linkspan string) string {
	walltime := minutesToWalltime(runtime.Resources.WallMinutes)
	lines := []string{"#!/bin/bash", "#SBATCH --job-name=" + runtime.JobName, "#SBATCH --nodes=1", "#SBATCH --ntasks=1", "#SBATCH --cpus-per-task=" + strconv.Itoa(runtime.Resources.Cores), "#SBATCH --mem=" + strconv.Itoa(runtime.Resources.MemoryMB) + "M", "#SBATCH --time=" + walltime, "#SBATCH --partition=" + runtime.Partition}
	if runtime.Account != "" {
		lines = append(lines, "#SBATCH --account="+runtime.Account)
	}
	if runtime.Resources.GPUCount > 0 {
		gres := "#SBATCH --gres=gpu:"
		if runtime.Resources.GPUType != "gpu" {
			gres += runtime.Resources.GPUType + ":"
		}
		lines = append(lines, gres+strconv.Itoa(runtime.Resources.GPUCount))
	}
	ports := allocationPorts(runtime.ID, runtime.Generation)
	lines = append(lines,
		"set -eu", "umask 077", `LOG_DIR="$HOME/.cybershuttle/logs"`, `install -d -m 700 "$LOG_DIR"`, `exec >"$LOG_DIR/`+runtime.ID+`.out" 2>"$LOG_DIR/`+runtime.ID+`.err"`, "unset XDG_RUNTIME_DIR TMPDIR",
		"LINKSPAN_BIN="+sshexec.ShellQuote(linkspan),
		"JUPYTER_PYTHON="+sshexec.ShellQuote(jupyterPython(runtime)),
		// Jupyter Server owns its own token auth, CORS and root confinement; nothing proxies it.
		// Both credentials arrive in the job environment, so neither appears in this script.
		fmt.Sprintf(`"$JUPYTER_PYTHON" -m jupyter_server --no-browser --ip=127.0.0.1 --port=%d --ServerApp.root_dir=%s --ServerApp.allow_origin='*' --IdentityProvider.token="$CS_JUPYTER_TOKEN" &`,
			ports.jupyter, sshexec.ShellQuote(runtime.WorkspaceRoot)),
		fmt.Sprintf(`exec "$LINKSPAN_BIN" --port %d --tunnel-enable --tunnel-id %s --tunnel-cluster %s --tunnel-host-token "$CS_TUNNEL_HOST_TOKEN"`,
			ports.control, sshexec.ShellQuote(runtime.Tunnel.ID), sshexec.ShellQuote(runtime.Tunnel.ClusterID)),
		"")
	return strings.Join(lines, "\n")
}

// jupyterPython is the interpreter cs-control provisions per owner; the browser never computes paths.
func jupyterPython(runtime Runtime) string {
	return strings.TrimSuffix(runtime.WorkspaceRoot, "/") + "/.cybershuttle/jupyter-env/bin/python"
}

func minutesToWalltime(minutes int) string {
	days, rest := minutes/(24*60), minutes%(24*60)
	hours, mins := rest/60, rest%60
	if days > 0 {
		return fmt.Sprintf("%d-%02d:%02d:00", days, hours, mins)
	}
	return fmt.Sprintf("%02d:%02d:00", hours, mins)
}

func jobName(id string) string { return "cs-" + id }

func validRuntimeJobName(runtime *Runtime) bool {
	return runtime.JobName == jobName(runtime.ID)
}

func (e *submissionError) Error() string { return e.cause.Error() }

func (e *submissionError) Unwrap() error { return e.cause }
