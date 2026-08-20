package control

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

type schedulerObservation struct {
	jobID string
	state string
	node  string
}

type cancellationTarget struct {
	key     string
	flag    string
	value   string
	runtime string
}

const schedulerMarkerCancel = "__CSCTL_SCANCEL__"
const schedulerMarkerQueue = "__CSCTL_SQUEUE__"
const schedulerMarkerAccounting = "__CSCTL_SACCT__"

// reconcileSnapshots performs all scheduler and endpoint I/O without holding
// the state lock. Scheduler calls are batched into one SSH execution per host.
func (s Service) reconcileSnapshots(ctx context.Context, snapshots []Runtime) []Runtime {
	results := append([]Runtime(nil), snapshots...)
	byHost := map[string][]int{}
	for i := range results {
		if reconcile(results[i].State) {
			byHost[results[i].SSHHost] = append(byHost[results[i].SSHHost], i)
		}
	}
	var wg sync.WaitGroup
	for host, indexes := range byHost {
		host, indexes := host, indexes
		wg.Add(1)
		go func() {
			defer wg.Done()
			group := make([]Runtime, len(indexes))
			for position, index := range indexes {
				group[position] = results[index]
			}
			observations, cancelErrors, err := s.schedulerObservations(ctx, host, group)
			if err != nil {
				// Service shutdown or a superseded background refresh must leave the
				// last good persisted runtime state completely untouched.
				if ctx.Err() != nil {
					return
				}
				for _, index := range indexes {
					if !s.reconciliationSnapshotCurrent(snapshots[index]) {
						continue
					}
					results[index].Error = err.Error()
					s.runtimeStatus(results[index].ID, "Runtime status check failed")
				}
				return
			}
			for _, index := range indexes {
				if !s.reconciliationSnapshotCurrent(snapshots[index]) {
					continue
				}
				runtime := &results[index]
				previousState, previousNode := runtime.State, runtime.Node
				observation, ok := observations[runtime.ID]
				if !ok {
					// Slurm can briefly omit a newly submitted job from both squeue and
					// sacct. Retain the last good active state without presenting that
					// expected propagation window as a runtime failure. STOPPING still
					// exposes missing cancellation state because cleanup depends on it.
					if runtime.State != "STOPPING" {
						continue
					}
					if message := cancelErrors[runtime.ID]; message != "" {
						runtime.Error = message
					} else {
						runtime.Error = "scheduler returned no state"
					}
					s.runtimeStatus(runtime.ID, "Runtime status is temporarily unavailable")
					continue
				}
				if runtime.JobID == "" && observation.jobID != "" {
					runtime.JobID = observation.jobID
				}
				_ = setRuntimeNode(runtime, observation.node)
				if runtime.Node != "" && runtime.Node != previousNode {
					s.runtimeStatus(runtime.ID, "Compute node assigned: "+runtime.Node)
				}
				class := classifySchedulerState(observation.state)
				// A word this scheduler vocabulary does not cover says nothing about
				// the allocation, so it is not an observation. Retaining the last good
				// state here is what lets every state below be a pure function of the
				// class, with no fall-through and no second opinion about readiness.
				if class == schedulerUnknown {
					continue
				}
				wasStopping := runtime.State == "STOPPING"
				next := nextState(runtime.State, class)
				if next == "STOPPED" || next == "FAILED" {
					s.runtimeStatus(runtime.ID, "Cleaning up runtime credentials")
					cleanupErr := s.Credentials.Delete(runtime.ID, runtime.Generation)
					if cleanupErr != nil {
						runtime.State = "STOPPING"
						runtime.Error = "runtime cleanup pending: " + cleanupErr.Error()
						s.runtimeStatus(runtime.ID, "Runtime cleanup is pending")
						continue
					}
					s.runtimeStatus(runtime.ID, "Runtime credential cleanup complete")
				}
				runtime.State = next
				if next != previousState {
					switch next {
					case "QUEUED":
						s.runtimeStatus(runtime.ID, "Runtime is queued")
					case "STARTING":
						s.runtimeStatus(runtime.ID, "Allocation is starting")
					case "READY":
						s.runtimeStatus(runtime.ID, "Allocation is running")
					case "STOPPED":
						s.runtimeStatus(runtime.ID, "Runtime stopped")
					case "FAILED":
						s.runtimeStatus(runtime.ID, "Runtime failed")
					}
				}
				if wasStopping && runtime.State == "STOPPING" {
					runtime.Error = cancelErrors[runtime.ID]
				} else {
					runtime.Error = ""
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return snapshots
	}

	// Startup file collection shares the first running reconciliation round.
	// Keep the allocation in STARTING until that collection completes, then
	// expose scheduler-confirmed readiness without consulting Linkspan.
	collected := s.collectStartingRuntimeLogs(ctx, results)
	if ctx.Err() != nil {
		return snapshots
	}
	for index := range results {
		if _, ok := collected[results[index].ID]; ok && results[index].State == "STARTING" {
			results[index].State = "READY"
			s.runtimeStatus(results[index].ID, "Allocation is running")
		}
	}

	return results
}

// schedulerClass is the family a raw Slurm state belongs to. The scheduler's
// vocabulary is parsed in exactly one place so the policies below cannot drift.
type schedulerClass int

const (
	schedulerUnknown schedulerClass = iota
	schedulerPending
	schedulerActive
	schedulerStopped
	schedulerFailed
)

func classifySchedulerState(raw string) schedulerClass {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return schedulerUnknown
	}
	switch strings.TrimSuffix(strings.ToUpper(fields[0]), "+") {
	case "PENDING", "REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SUSPENDED":
		return schedulerPending
	case "RUNNING", "CONFIGURING", "COMPLETING", "RESIZING", "SIGNALING", "STAGE_OUT":
		return schedulerActive
	case "COMPLETED", "CANCELLED", "STOPPED":
		return schedulerStopped
	case "BOOT_FAIL", "DEADLINE", "FAILED", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "REVOKED", "SPECIAL_EXIT", "TIMEOUT":
		return schedulerFailed
	}
	return schedulerUnknown
}

// nextState is the allocation's state after one scheduler observation. A stop in
// progress and a runtime already reported ready both latch, so a live
// observation can never regress either. Callers must have excluded
// schedulerUnknown, which is the absence of an observation rather than a class.
func nextState(current string, class schedulerClass) string {
	switch {
	case current == "STOPPING" && (class == schedulerPending || class == schedulerActive):
		return "STOPPING"
	case class == schedulerPending:
		return "QUEUED"
	case class == schedulerActive && current == "READY":
		return "READY"
	case class == schedulerActive:
		return "STARTING"
	case class == schedulerStopped:
		return "STOPPED"
	}
	return "FAILED"
}

func cancellationTargets(runtimes []Runtime) []cancellationTarget {
	seen := map[string]bool{}
	targets := make([]cancellationTarget, 0)
	for _, runtime := range runtimes {
		if runtime.State != "STOPPING" {
			continue
		}
		target := cancellationTarget{runtime: runtime.ID}
		if runtime.JobID != "" {
			target.key, target.value = "id:"+runtime.JobID, runtime.JobID
		} else {
			target.key, target.flag, target.value = "name:"+runtime.JobName, "--name", runtime.JobName
		}
		if seen[target.key] {
			continue
		}
		seen[target.key] = true
		targets = append(targets, target)
	}
	slices.SortFunc(targets, func(a, b cancellationTarget) int { return strings.Compare(a.key, b.key) })
	return targets
}

func appendCancellation(script *strings.Builder, target cancellationTarget) {
	// scancel is deliberately outside `set -e`: an already-terminal job is a
	// normal race and must never prevent the scheduler observations below.
	script.WriteString("csctl_cancel_output=$(scancel ")
	if target.flag != "" {
		script.WriteString(target.flag)
		script.WriteString("=")
	}
	script.WriteString(sshexec.ShellQuote(target.value))
	script.WriteString(" 2>&1)\ncsctl_cancel_status=$?\n")
	script.WriteString("if [ \"$csctl_cancel_status\" -ne 0 ]; then\n")
	script.WriteString("  csctl_cancel_message=$(printf '%s' \"$csctl_cancel_output\" | tr '\\n|' '  ')\n")
	script.WriteString("  printf '%s|%s|%s\\n' ")
	script.WriteString(sshexec.ShellQuote(schedulerMarkerCancel))
	script.WriteString(" ")
	script.WriteString(sshexec.ShellQuote(target.key))
	script.WriteString(" \"$csctl_cancel_message\"\nfi\n")
}

func (s Service) schedulerObservations(ctx context.Context, host string, runtimes []Runtime) (map[string]schedulerObservation, map[string]string, error) {
	names := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		names = append(names, runtime.JobName)
	}
	slices.Sort(names)
	targets := cancellationTargets(runtimes)
	var script strings.Builder
	script.WriteString("set -u\n")
	for _, target := range targets {
		appendCancellation(&script, target)
	}
	script.WriteString("printf '%s\\n' ")
	script.WriteString(sshexec.ShellQuote(schedulerMarkerQueue))
	script.WriteString("\nsqueue --me --noheader --format='%i|%T|%N|%j'\n")
	script.WriteString("printf '%s\\n' ")
	script.WriteString(sshexec.ShellQuote(schedulerMarkerAccounting))
	script.WriteString("\nsacct --noheader -X --name=")
	script.WriteString(sshexec.ShellQuote(strings.Join(names, ",")))
	script.WriteString(" --format=JobIDRaw,State,NodeList,JobName --parsable2\n")
	output, err := s.Runner.Run(ctx, host, strings.NewReader(script.String()), "sh", "-s", "--", "csctl-runtime-status")
	if err != nil {
		return nil, nil, err
	}
	byID, byName := map[string]schedulerObservation{}, map[string]schedulerObservation{}
	cancelByKey := map[string]string{}
	section := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, schedulerMarkerCancel+"|") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) == 3 {
				cancelByKey[parts[1]] = strings.TrimSpace(parts[2])
			}
			continue
		}
		switch line {
		case schedulerMarkerQueue:
			section = "queue"
			continue
		case schedulerMarkerAccounting:
			section = "accounting"
			continue
		case "":
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 4 || !jobPattern.MatchString(strings.TrimSpace(parts[0])) {
			continue
		}
		observation := schedulerObservation{jobID: strings.TrimSpace(parts[0]), state: strings.TrimSpace(parts[1]), node: strings.TrimSpace(parts[2])}
		name := strings.TrimSpace(parts[3])
		if section == "queue" || byID[observation.jobID].jobID == "" {
			byID[observation.jobID], byName[name] = observation, observation
		}
	}
	result := make(map[string]schedulerObservation, len(runtimes))
	cancelErrors := make(map[string]string)
	for _, runtime := range runtimes {
		if runtime.JobID != "" {
			if observation, ok := byID[runtime.JobID]; ok {
				result[runtime.ID] = observation
			}
		} else if observation, ok := byName[runtime.JobName]; ok {
			result[runtime.ID] = observation
		}
		if runtime.State == "STOPPING" {
			key := "name:" + runtime.JobName
			if runtime.JobID != "" {
				key = "id:" + runtime.JobID
			}
			if message := cancelByKey[key]; message != "" {
				cancelErrors[runtime.ID] = message
			}
		}
	}
	return result, cancelErrors, nil
}

func (s Service) reconciliationSnapshotCurrent(snapshot Runtime) bool {
	current := false
	_ = s.Store.withLock(func(_ Store, state *state) error {
		runtime := state.Runtimes[snapshot.ID]
		current = runtime != nil && runtime.UpdatedAt.Equal(snapshot.UpdatedAt) && runtime.State == snapshot.State && runtime.JobID == snapshot.JobID
		return nil
	})
	return current
}

func changedReconciliation(before, after Runtime) bool {
	return before.State != after.State || before.Error != after.Error || before.JobID != after.JobID || before.Node != after.Node
}

func mergeReconciled(current, snapshot, candidate *Runtime, now time.Time) bool {
	if current == nil || !current.UpdatedAt.Equal(snapshot.UpdatedAt) || current.State != snapshot.State || current.JobID != snapshot.JobID {
		return false
	}
	if !changedReconciliation(*snapshot, *candidate) {
		return false
	}
	current.State, current.Error, current.JobID, current.Node, current.UpdatedAt = candidate.State, candidate.Error, candidate.JobID, candidate.Node, now
	return true
}

func sortedRuntimeCopies(current *state) []Runtime {
	result := make([]Runtime, 0, len(current.Runtimes))
	for _, id := range slices.Sorted(maps.Keys(current.Runtimes)) {
		result = append(result, *current.Runtimes[id])
	}
	return result
}
