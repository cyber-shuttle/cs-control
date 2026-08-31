package control

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/framed"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

type schedulerObservation struct {
	jobID string
	state string
	node  string
	// Absent from squeue, so zero means "not reported" rather than "just started".
	elapsedSeconds int64
}

type cancellationTarget struct {
	key   string
	flag  string
	value string
}

const (
	schedulerMarkerPrefix     = "__CSCTL_S"
	schedulerMarkerCancel     = schedulerMarkerPrefix + "CANCEL__"
	schedulerMarkerQueue      = schedulerMarkerPrefix + "QUEUE__"
	schedulerMarkerAccounting = schedulerMarkerPrefix + "ACCT__"
)

// Slurm stops reporting a job eventually and a login node is not always
// reachable, so an observation cannot be the only thing that retires a runtime.
const (
	schedulerPropagationWindow = 2 * time.Minute
	allocationWallGrace        = 10 * time.Minute
	schedulerLookbackSlack     = time.Hour
	// Past this the scheduler has already stopped knowing about the runtime, and
	// an unbounded accounting query is slow for everybody on the cluster.
	schedulerLookbackMax = 30 * 24 * time.Hour
)

var stateNarration = map[string]string{
	"QUEUED":   "Runtime is queued",
	"STARTING": "Allocation is starting",
	"READY":    "Allocation is running",
	"STOPPED":  "Runtime stopped",
	"FAILED":   "Runtime failed",
}

func transitionNarration(state string, class schedulerClass) string {
	if state == "STOPPED" && class == schedulerExpired {
		return "Runtime reached its walltime"
	}
	return stateNarration[state]
}

// startedRuntime reports whether Slurm had begun running the allocation, which
// is what makes its --time a deadline rather than an open-ended queue wait.
func startedRuntime(runtime Runtime) bool {
	return runtime.State == "STARTING" || runtime.State == "READY"
}

// outlivedAllocation reports that Slurm has certainly reaped the job, whatever
// the scheduler last said. A queued allocation has no such deadline.
func outlivedAllocation(runtime Runtime, now time.Time) bool {
	if !startedRuntime(runtime) || runtime.StartedAt.IsZero() || runtime.Resources.WallMinutes <= 0 {
		return false
	}
	return now.Sub(runtime.StartedAt) > time.Duration(runtime.Resources.WallMinutes)*time.Minute+allocationWallGrace
}

// unknownToScheduler reports that a scheduler which answered has had long enough
// to know this job and does not. Measured from the submission, not the card: a
// relaunch keeps a creation time whose window ran out long ago.
func unknownToScheduler(runtime Runtime, now time.Time) bool {
	return now.Sub(runtime.UpdatedAt) > schedulerPropagationWindow
}

// unreachableScheduler resolves a runtime whose host did not answer. No answer
// is not the same as no allocation, so the last good state stands until the
// allocation's own --time has passed.
func unreachableScheduler(runtime *Runtime, err error, now time.Time) []string {
	if outlivedAllocation(*runtime, now) {
		runtime.State, runtime.Error = "STOPPED", ""
		return []string{"Allocation reached its wall-time limit"}
	}
	runtime.Error = err.Error()
	return []string{"Runtime status check failed"}
}

// missingFromScheduler resolves a runtime the scheduler answered about without
// mentioning. Slurm can briefly omit a newly submitted job from both squeue and
// sacct, so only absence past the propagation window retires the allocation.
func missingFromScheduler(runtime *Runtime, cancelError string, now time.Time) []string {
	if runtime.State == "STOPPING" {
		runtime.Error = cmp.Or(cancelError, "scheduler returned no state")
		return []string{"Runtime status is temporarily unavailable"}
	}
	if !unknownToScheduler(*runtime, now) {
		return nil
	}
	runtime.State, runtime.Error = "STOPPED", ""
	return []string{"Allocation is no longer known to the scheduler"}
}

// applyObservation folds one scheduler observation into the runtime.
func (s Service) applyObservation(runtime *Runtime, observation schedulerObservation, cancelError string) []string {
	var lines []string
	if runtime.JobID == "" {
		runtime.JobID = observation.jobID
	}
	previousNode := runtime.Node
	setRuntimeNode(runtime, observation.node)
	if runtime.Node != "" && runtime.Node != previousNode {
		lines = append(lines, "Compute node assigned: "+runtime.Node)
	}
	// A word outside the scheduler vocabulary says nothing about the allocation,
	// so it is not an observation: the last good state stands.
	class := classifySchedulerState(observation.state)
	if class == schedulerUnknown {
		return lines
	}
	if class == schedulerActive && runtime.StartedAt.IsZero() {
		// Anchor the wall-time countdown to Slurm's elapsed run-time rather than to
		// this poll, the same way cs-bridge does; without one the poll errs late.
		runtime.StartedAt = s.now().Add(-time.Duration(observation.elapsedSeconds) * time.Second)
	}
	previous := runtime.State
	next := nextState(previous, class)
	if next == "STOPPED" || next == "FAILED" {
		lines = append(lines, "Cleaning up runtime credentials")
		if err := s.Credentials.Delete(runtime.ID, runtime.Generation); err != nil {
			runtime.State = "STOPPING"
			runtime.Error = "runtime cleanup pending: " + err.Error()
			return append(lines, "Runtime cleanup is pending")
		}
		lines = append(lines, "Runtime credential cleanup complete")
	}
	runtime.State = next
	if next != previous {
		if line := transitionNarration(next, class); line != "" {
			lines = append(lines, line)
		}
	}
	runtime.Error = ""
	if previous == "STOPPING" && next == "STOPPING" {
		runtime.Error = cancelError
	}
	return lines
}

// reconcileSnapshots performs all scheduler and endpoint I/O without holding the
// state lock, batching scheduler calls into one SSH execution per host.
//
// Narration is returned per snapshot rather than appended to the tail here: the
// round runs on a snapshot that the owner may have superseded by stopping or
// relaunching the runtime, and only the caller's merge lock can tell.
func (s Service) reconcileSnapshots(ctx context.Context, snapshots []Runtime) ([]Runtime, [][]string) {
	results := append([]Runtime(nil), snapshots...)
	narration := make([][]string, len(results))
	byHost := map[string][]int{}
	for i := range results {
		if reconcile(results[i].State) {
			byHost[results[i].SSHHost] = append(byHost[results[i].SSHHost], i)
		}
	}
	var wg sync.WaitGroup
	for host, indexes := range byHost {
		wg.Add(1)
		go func() {
			defer wg.Done()
			group := make([]Runtime, len(indexes))
			for position, index := range indexes {
				group[position] = results[index]
			}
			observations, cancelErrors, err := s.schedulerObservations(ctx, host, group)
			// Service shutdown or a superseded background refresh must leave the last
			// good persisted runtime state completely untouched.
			if err != nil && ctx.Err() != nil {
				return
			}
			for _, index := range indexes {
				runtime := &results[index]
				switch observation, ok := observations[runtime.ID]; {
				case err != nil:
					narration[index] = unreachableScheduler(runtime, err, s.now())
				case !ok:
					narration[index] = missingFromScheduler(runtime, cancelErrors[runtime.ID], s.now())
				default:
					narration[index] = s.applyObservation(runtime, observation, cancelErrors[runtime.ID])
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return snapshots, make([][]string, len(snapshots))
	}

	// Startup file collection shares the first running reconciliation round. Keep
	// the allocation in STARTING until that collection completes, then expose
	// scheduler-confirmed readiness without consulting Linkspan.
	collected := s.collectStartingRuntimeLogs(ctx, results)
	if ctx.Err() != nil {
		return snapshots, make([][]string, len(snapshots))
	}
	for index := range results {
		if _, ok := collected[results[index].ID]; ok && results[index].State == "STARTING" {
			results[index].State = "READY"
			narration[index] = append(narration[index], "Allocation is running")
		}
	}
	return results, narration
}

// schedulerClass is the family a raw Slurm state belongs to. The scheduler's
// vocabulary is parsed in exactly one place so the policies below cannot drift.
type schedulerClass int

const (
	schedulerUnknown schedulerClass = iota
	schedulerPending
	schedulerActive
	schedulerStopped
	schedulerExpired
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
	// Running out the walltime is what the allocation was asked to do, so it ends
	// stopped rather than failed; the class exists only to say which happened.
	case "TIMEOUT":
		return schedulerExpired
	case "BOOT_FAIL", "DEADLINE", "FAILED", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "REVOKED", "SPECIAL_EXIT":
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
	case class == schedulerStopped || class == schedulerExpired:
		return "STOPPED"
	}
	return "FAILED"
}

func cancellationTargets(runtimes []Runtime) []cancellationTarget {
	targets := make([]cancellationTarget, 0)
	for _, runtime := range runtimes {
		if runtime.State != "STOPPING" {
			continue
		}
		target := cancellationTarget{key: "id:" + runtime.JobID, value: runtime.JobID}
		if runtime.JobID == "" {
			target = cancellationTarget{key: "name:" + runtime.JobName, flag: "--name", value: runtime.JobName}
		}
		targets = append(targets, target)
	}
	slices.SortFunc(targets, func(a, b cancellationTarget) int { return strings.Compare(a.key, b.key) })
	return targets
}

// statusScript cancels every runtime being stopped, then reports the queue and
// the accounting database, each behind its own marker.
func (s Service) statusScript(runtimes []Runtime) string {
	var script strings.Builder
	marker := func(name string) { fmt.Fprintf(&script, "printf '%%s\\n' %s\n", sshexec.ShellQuote(name)) }

	script.WriteString("set -u\n")
	marker(schedulerMarkerCancel)
	for _, target := range cancellationTargets(runtimes) {
		flag := ""
		if target.flag != "" {
			flag = target.flag + "="
		}
		// scancel is deliberately outside `set -e`: an already-terminal job is a
		// normal race and must never prevent the scheduler observations below.
		fmt.Fprintf(&script, "csctl_cancel=$(scancel %s%s 2>&1) || printf '%%s|%%s\\n' %s \"$(printf '%%s' \"$csctl_cancel\" | tr '\\n|' '  ')\"\n",
			flag, sshexec.ShellQuote(target.value), sshexec.ShellQuote(target.key))
	}
	marker(schedulerMarkerQueue)
	script.WriteString("squeue --me --noheader --format='%i|%T|%N|%j'\n")

	names := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		names = append(names, runtime.JobName)
	}
	slices.Sort(names)
	marker(schedulerMarkerAccounting)
	fmt.Fprintf(&script, "sacct --noheader -X --starttime=%s --name=%s --format=JobIDRaw,State,NodeList,JobName,ElapsedRaw --parsable2\n",
		sshexec.ShellQuote(schedulerLookback(runtimes, s.now())), sshexec.ShellQuote(strings.Join(names, ",")))
	return script.String()
}

func (s Service) schedulerObservations(ctx context.Context, host string, runtimes []Runtime) (map[string]schedulerObservation, map[string]string, error) {
	output, err := s.Runner.Run(ctx, host, strings.NewReader(s.statusScript(runtimes)), "sh", "-s", "--", "csctl-runtime-status")
	if err != nil {
		return nil, nil, err
	}
	sections, err := framed.SectionsAfterPreamble(output, schedulerMarkerPrefix, schedulerMarkerCancel, schedulerMarkerQueue, schedulerMarkerAccounting)
	if err != nil {
		return nil, nil, err
	}
	cancelByKey := map[string]string{}
	for _, line := range strings.Split(sections[schedulerMarkerCancel], "\n") {
		if key, message, ok := strings.Cut(line, "|"); ok {
			cancelByKey[key] = strings.TrimSpace(message)
		}
	}
	byID, byName := map[string]schedulerObservation{}, map[string]schedulerObservation{}
	// The queue is what the scheduler is doing now, so it is read second and
	// stands over an accounting row for the same job.
	for _, marker := range []string{schedulerMarkerAccounting, schedulerMarkerQueue} {
		queue := marker == schedulerMarkerQueue
		for _, line := range strings.Split(sections[marker], "\n") {
			parts := strings.Split(strings.TrimSpace(line), "|")
			if len(parts) < 4 || !jobPattern.MatchString(strings.TrimSpace(parts[0])) {
				continue
			}
			observation := schedulerObservation{jobID: strings.TrimSpace(parts[0]), state: strings.TrimSpace(parts[1]), node: strings.TrimSpace(parts[2])}
			if len(parts) > 4 {
				if seconds, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64); err == nil && seconds >= 0 {
					observation.elapsedSeconds = seconds
				}
			}
			if name := strings.TrimSpace(parts[3]); queue || byID[observation.jobID].jobID == "" {
				byID[observation.jobID], byName[name] = observation, observation
			}
		}
	}
	result := make(map[string]schedulerObservation, len(runtimes))
	cancelErrors := make(map[string]string)
	for _, runtime := range runtimes {
		key := "name:" + runtime.JobName
		observation, ok := byName[runtime.JobName]
		if runtime.JobID != "" {
			key = "id:" + runtime.JobID
			observation, ok = byID[runtime.JobID]
		}
		if ok {
			result[runtime.ID] = observation
		}
		if message := cancelByKey[key]; message != "" && runtime.State == "STOPPING" {
			cancelErrors[runtime.ID] = message
		}
	}
	return result, cancelErrors, nil
}

func changedReconciliation(before, after Runtime) bool {
	return before.State != after.State || before.Error != after.Error || before.JobID != after.JobID || before.Node != after.Node || !before.StartedAt.Equal(after.StartedAt)
}

// reconciliationSnapshotCurrent reports that the persisted runtime is still the
// one this round observed, so neither its result nor its narration belongs to a
// runtime the owner has since stopped or relaunched.
func reconciliationSnapshotCurrent(current, snapshot *Runtime) bool {
	return current != nil && current.UpdatedAt.Equal(snapshot.UpdatedAt) && current.State == snapshot.State && current.JobID == snapshot.JobID
}

func (s Service) narrateReconciled(current, snapshot *Runtime, lines []string) {
	if !reconciliationSnapshotCurrent(current, snapshot) {
		return
	}
	for _, line := range lines {
		s.runtimeStatus(snapshot.ID, line)
	}
}

func mergeReconciled(current, snapshot, candidate *Runtime, now time.Time) bool {
	if !reconciliationSnapshotCurrent(current, snapshot) || !changedReconciliation(*snapshot, *candidate) {
		return false
	}
	current.State, current.Error, current.JobID, current.Node, current.UpdatedAt = candidate.State, candidate.Error, candidate.JobID, candidate.Node, now
	current.StartedAt = candidate.StartedAt
	return true
}

func sortedRuntimeCopies(current *state) []Runtime {
	result := make([]Runtime, 0, len(current.Runtimes))
	for _, id := range slices.Sorted(maps.Keys(current.Runtimes)) {
		result = append(result, *current.Runtimes[id])
	}
	return result
}

// schedulerLookback is how far back sacct is asked to look, as a relative window.
// Slurm reads an absolute --starttime in the cluster's own timezone, which is not
// necessarily ours, so an absolute stamp can land in the cluster's future -- sacct
// then refuses the whole range and every status check fails. Its default of
// midnight today is likewise too narrow: it hides every older allocation, which
// then reads as missing rather than finished.
func schedulerLookback(runtimes []Runtime, now time.Time) string {
	oldest := now
	for _, runtime := range runtimes {
		if !runtime.CreatedAt.IsZero() && runtime.CreatedAt.Before(oldest) {
			oldest = runtime.CreatedAt
		}
	}
	window := min(now.Sub(oldest)+schedulerLookbackSlack, schedulerLookbackMax)
	return "now-" + strconv.FormatInt(int64(window.Seconds()), 10) + "seconds"
}
