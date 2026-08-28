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

func (s Service) submitRuntimeScript(ctx context.Context, host string, runtime Runtime, script, jupyterToken, hostToken string) (string, error) {
	jobName := runtime.JobName
	// The allocation identity, the job name included, is only known once the
	// tunnel exists, so it rides the command line alongside the tokens and
	// leaves the reviewed script byte-identical to the one Slurm validated.
	ports := allocationPorts(runtime.ID, runtime.Generation)
	// Jupyter Server reads its own token and port from the environment, so the
	// workflow that starts it names neither and nothing secret is written down.
	export := fmt.Sprintf("--export=ALL,JUPYTER_TOKEN=%s,CS_TUNNEL_HOST_TOKEN=%s,JUPYTER_PORT=%d,CS_CONTROL_PORT=%d,CS_TUNNEL_ID=%s,CS_TUNNEL_CLUSTER=%s",
		jupyterToken, hostToken, ports.jupyter, ports.control, runtime.Tunnel.ID, runtime.Tunnel.ClusterID)
	remote := strings.Join([]string{sshexec.ShellQuote("sbatch"), sshexec.ShellQuote("--job-name=" + jobName), sshexec.ShellQuote(export), sshexec.ShellQuote("--parsable")}, " ")
	commandCtx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	cmd, err := s.Runner.Command(commandCtx, host, remote)
	if err != nil {
		return "", &submissionError{cause: fmt.Errorf("submit outcome pending reconciliation for %s: %w", jobName, err), ambiguous: true}
	}
	cmd.Stdin = strings.NewReader(script)
	outText, errText, runErr := sshexec.RunBounded(commandCtx, cmd)
	if runErr != nil {
		message := sshexec.FailureMessage(errText, runErr)
		for _, secret := range []string{jupyterToken, hostToken} {
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
	return commandResult{}, fmt.Errorf("validate Slurm script over SSH: %s", sshexec.FailureMessage(message, err))
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
	lines := []string{"#!/bin/bash", "#SBATCH --nodes=1", "#SBATCH --ntasks=1", "#SBATCH --cpus-per-task=" + strconv.Itoa(runtime.Resources.Cores), "#SBATCH --mem=" + strconv.Itoa(runtime.Resources.MemoryMB) + "M", "#SBATCH --time=" + walltime, "#SBATCH --partition=" + runtime.Partition}
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
	lines = append(lines,
		"set -eu", "umask 077", `LOG_DIR="$HOME/.cybershuttle/logs"`, `install -d -m 700 "$LOG_DIR"`, `exec >"$LOG_DIR/`+runtime.ID+`.out" 2>"$LOG_DIR/`+runtime.ID+`.err"`, "unset XDG_RUNTIME_DIR TMPDIR",
		"LINKSPAN_BIN="+sshexec.ShellQuote(linkspan),
		// The allocation runs Linkspan and nothing else. What belongs inside it is
		// the workflow's business, so this script names no application at all.
		`exec "$LINKSPAN_BIN" --port "$CS_CONTROL_PORT" --tunnel-enable --tunnel-id "$CS_TUNNEL_ID" --tunnel-cluster "$CS_TUNNEL_CLUSTER" --tunnel-host-token "$CS_TUNNEL_HOST_TOKEN" --workflow `+sshexec.ShellQuote(runtimeWorkflowPath(runtime)),
		"")
	return strings.Join(lines, "\n")
}

// jupyterPython is the interpreter cs-control provisions per account, beside the
// binary it also installs. One account, one environment: a workspace chooses
// what a server opens, not what runs it. The browser never computes paths.
func jupyterPython(runtime Runtime) string {
	return jupyterEnvironment(runtime.HomeDir) + "/bin/python"
}

func jupyterEnvironment(home string) string {
	return strings.TrimSuffix(home, "/") + "/.cybershuttle/jupyter-env"
}

func minutesToWalltime(minutes int) string {
	days, rest := minutes/(24*60), minutes%(24*60)
	hours, mins := rest/60, rest%60
	if days > 0 {
		return fmt.Sprintf("%d-%02d:%02d:00", days, hours, mins)
	}
	return fmt.Sprintf("%02d:%02d:00", hours, mins)
}

// A card outlives the allocations it runs, so the job name carries the
// generation: without it the accounting record of the run that finished is read
// as the outcome of the run being submitted.
func jobName(id, generation string) string { return "cs-" + id + "-" + generation }

func validRuntimeJobName(runtime *Runtime) bool {
	// A live job cannot be renamed, so names written before this stay valid.
	return runtime.JobName == jobName(runtime.ID, runtime.Generation) || runtime.JobName == "cs-"+runtime.ID
}

func (e *submissionError) Error() string { return e.cause.Error() }

func (e *submissionError) Unwrap() error { return e.cause }
