// Package proc ends the process groups the SSH subsystems start. Every remote
// command runs in its own group so a ProxyCommand or other descendant cannot
// outlive the session that spawned it and keep inherited descriptors open.
package proc

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Signal delivers signal to cmd's whole process group, falling back to the
// direct process when the group send is refused.
func Signal(cmd *exec.Cmd, signal os.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if value, ok := signal.(syscall.Signal); ok {
		if syscall.Kill(-cmd.Process.Pid, value) == nil {
			return
		}
	}
	_ = cmd.Process.Signal(signal)
}

// GroupAlive reports whether any member of cmd's process group still exists.
func GroupAlive(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	err := syscall.Kill(-cmd.Process.Pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// TerminateGroup ends cmd's process group and does not return until Wait has.
// It always re-checks for descendants after TERM: the direct SSH process may
// exit promptly while a ProxyCommand ignores TERM and keeps the group alive.
//
// exited must be closed once the caller's Wait returns. Closing rather than
// sending is what lets an already-reaped process be recognised here and by any
// other observer, so no caller needs to track that separately.
func TerminateGroup(cmd *exec.Cmd, exited <-chan struct{}, grace time.Duration) {
	if cmd == nil || cmd.Process == nil || exited == nil {
		return
	}
	select {
	case <-exited:
		// Wait already reaped this exact process; never signal a reusable PID.
		return
	default:
	}
	Signal(cmd, syscall.SIGTERM)
	reaped := false
	select {
	case <-exited:
		reaped = true
	case <-time.After(grace):
	}
	if GroupAlive(cmd) {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if !reaped {
		// Commands normally own a process group, but teardown must also be safe
		// for startup failures and tests before Setpgid/PTY ownership exists.
		_ = cmd.Process.Kill()
		<-exited
	}
}
