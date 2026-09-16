// Scheduler reconciliation folds one Slurm observation into every watched session, batched by groupByScope.
// classifySchedulerState is the only place that parses Slurm's vocabulary.
// Silence is not evidence, so a session with no observation stays put until its walltime or window expires.
//
//	schedulerObservation, cancellationTarget
//	schedulerMarker*, schedulerPropagationWindow, walltimeGrace, schedulerLookbackSlack, schedulerLookbackMax
//	stateNarration, schedulerScope
//	schedulerClass, schedulerUnknown, schedulerPending, schedulerActive, schedulerStopped, schedulerExpired,
//		schedulerFailed
//	transitionNarration, startedSession, outlivedWalltime, unknownToScheduler
//	unreachableScheduler, missingFromScheduler, classifySchedulerState, nextState
//	groupByScope, sortedScopes, cancellationTargets
//	changedReconciliation, reconciliationSnapshotCurrent, mergeReconciled
//	sortedSessionCopies, sacctLookback, schedulerLookback
//	Service
//	applyObservation, reconcileSnapshots, statusScript, schedulerObservations, narrateReconciled
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

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

type schedulerObservation struct {
	jobID          string
	state          string
	node           string
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

const (
	schedulerPropagationWindow = 2 * time.Minute
	walltimeGrace              = 10 * time.Minute
	schedulerLookbackSlack     = time.Hour
	schedulerLookbackMax       = 30 * 24 * time.Hour
)

var stateNarration = map[string]string{
	"QUEUED":   "Session is queued",
	"STARTING": "Session is starting",
	"READY":    "Session is running",
	"STOPPED":  "Session stopped",
	"FAILED":   "Session failed",
}

type schedulerScope struct {
	owner authn.Principal
	host  string
}

type schedulerClass int

const (
	schedulerUnknown schedulerClass = iota
	schedulerPending
	schedulerActive
	schedulerStopped
	schedulerExpired
	schedulerFailed
)

func transitionNarration(state string, class schedulerClass) string {
	if state == "STOPPED" && class == schedulerExpired {
		return "Session reached its walltime"
	}
	return stateNarration[state]
}

func startedSession(session Session) bool {
	return session.State == "STARTING" || session.State == "READY"
}

func outlivedWalltime(session Session, now time.Time) bool {
	if !startedSession(session) || session.StartedAt.IsZero() || session.Resources.WallMinutes <= 0 {
		return false
	}
	return now.Sub(session.StartedAt) > time.Duration(session.Resources.WallMinutes)*time.Minute+walltimeGrace
}

func unknownToScheduler(session Session, now time.Time) bool {
	return now.Sub(session.UpdatedAt) > schedulerPropagationWindow
}

func unreachableScheduler(session *Session, err error, now time.Time) []string {
	if outlivedWalltime(*session, now) {
		session.State, session.Error = "STOPPED", ""
		return []string{"Session reached its walltime"}
	}
	session.Error = boundedSessionError(err)
	return []string{"Session status check failed"}
}

func missingFromScheduler(session *Session, cancelError string, now time.Time) []string {
	if session.JobID == "" && now.Sub(session.UpdatedAt) <= provisionTimeout {
		return nil
	}
	if session.State == "STOPPING" && !unknownToScheduler(*session, now) {
		session.Error = cmp.Or(cancelError, "scheduler returned no state")
		return []string{"Session status is temporarily unavailable"}
	}
	if session.JobID != "" && !unknownToScheduler(*session, now) {
		return nil
	}
	session.State, session.Error = "STOPPED", ""
	return []string{"Session is no longer known to the scheduler"}
}

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
	case "TIMEOUT":
		return schedulerExpired
	case "BOOT_FAIL", "DEADLINE", "FAILED", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "REVOKED", "SPECIAL_EXIT":
		return schedulerFailed
	}
	return schedulerUnknown
}

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

func groupByScope[T any](items []T, scope func(T) schedulerScope) map[schedulerScope][]T {
	byScope := map[schedulerScope][]T{}
	for _, item := range items {
		key := scope(item)
		byScope[key] = append(byScope[key], item)
	}
	return byScope
}

func sortedScopes[T any](byScope map[schedulerScope][]T) []schedulerScope {
	return slices.SortedFunc(maps.Keys(byScope), func(a, b schedulerScope) int {
		return cmp.Or(strings.Compare(a.host, b.host), strings.Compare(a.owner.Subject, b.owner.Subject))
	})
}

func cancellationTargets(sessions []Session) []cancellationTarget {
	targets := make([]cancellationTarget, 0)
	for _, session := range sessions {
		if session.State != "STOPPING" {
			continue
		}
		target := cancellationTarget{key: "id:" + session.JobID, value: session.JobID}
		if session.JobID == "" {
			target = cancellationTarget{key: "name:" + session.JobName, flag: "--name", value: session.JobName}
		}
		targets = append(targets, target)
	}
	slices.SortFunc(targets, func(a, b cancellationTarget) int { return strings.Compare(a.key, b.key) })
	return targets
}

func changedReconciliation(before, after Session) bool {
	return before.State != after.State || before.Error != after.Error || before.JobID != after.JobID || before.Node != after.Node || !before.StartedAt.Equal(after.StartedAt)
}

func reconciliationSnapshotCurrent(current, snapshot *Session) bool {
	return current != nil && current.UpdatedAt.Equal(snapshot.UpdatedAt) && current.State == snapshot.State && current.JobID == snapshot.JobID
}

func mergeReconciled(current, snapshot, candidate *Session, now time.Time) bool {
	if !reconciliationSnapshotCurrent(current, snapshot) || !changedReconciliation(*snapshot, *candidate) {
		return false
	}
	current.State, current.Error, current.JobID, current.Node, current.UpdatedAt = candidate.State, candidate.Error, candidate.JobID, candidate.Node, now
	current.StartedAt = candidate.StartedAt
	return true
}

func sortedSessionCopies(current *state) []Session {
	result := make([]Session, 0, len(current.Sessions))
	for _, id := range slices.Sorted(maps.Keys(current.Sessions)) {
		result = append(result, *current.Sessions[id])
	}
	return result
}

func sacctLookback(oldest, now time.Time) string {
	window := min(now.Sub(oldest)+schedulerLookbackSlack, schedulerLookbackMax)
	return "now-" + strconv.FormatInt(int64(window.Seconds()), 10) + "seconds"
}

func schedulerLookback(sessions []Session, now time.Time) string {
	oldest := now
	for _, session := range sessions {
		if !session.CreatedAt.IsZero() && session.CreatedAt.Before(oldest) {
			oldest = session.CreatedAt
		}
	}
	return sacctLookback(oldest, now)
}

func (s Service) applyObservation(session *Session, observation schedulerObservation, cancelError string) []string {
	var lines []string
	if session.JobID == "" {
		session.JobID = observation.jobID
	}
	previousNode := session.Node
	setSessionNode(session, observation.node)
	if session.Node != "" && session.Node != previousNode {
		lines = append(lines, "Compute node assigned: "+session.Node)
	}
	class := classifySchedulerState(observation.state)
	if class == schedulerUnknown {
		return lines
	}
	if class == schedulerActive && session.StartedAt.IsZero() {
		session.StartedAt = s.now().Add(-time.Duration(observation.elapsedSeconds) * time.Second)
	}
	previous := session.State
	next := nextState(previous, class)
	session.State = next
	if next != previous {
		if line := transitionNarration(next, class); line != "" {
			lines = append(lines, line)
		}
	}
	session.Error = ""
	if previous == "STOPPING" && next == "STOPPING" {
		session.Error = cancelError
	}
	return lines
}

func (s Service) reconcileSnapshots(ctx context.Context, snapshots []Session) ([]Session, [][]string) {
	results := append([]Session(nil), snapshots...)
	narration := make([][]string, len(results))
	var indexes []int
	for i := range results {
		if reconcilable(results[i].State) {
			indexes = append(indexes, i)
		}
	}
	byScope := groupByScope(indexes, func(i int) schedulerScope {
		return schedulerScope{owner: results[i].Owner, host: results[i].SSHHost}
	})
	var wg sync.WaitGroup
	for scope, indexes := range byScope {
		wg.Add(1)
		go func() {
			defer wg.Done()
			group := make([]Session, len(indexes))
			for position, index := range indexes {
				group[position] = results[index]
			}
			observations, cancelErrors, err := s.forPrincipal(scope.owner).schedulerObservations(ctx, scope.host, group)
			if err != nil && ctx.Err() != nil {
				return
			}
			for _, index := range indexes {
				session := &results[index]
				switch observation, ok := observations[session.ID]; {
				case err != nil:
					narration[index] = unreachableScheduler(session, err, s.now())
				case !ok:
					narration[index] = missingFromScheduler(session, cancelErrors[session.ID], s.now())
				default:
					narration[index] = s.applyObservation(session, observation, cancelErrors[session.ID])
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return snapshots, make([][]string, len(snapshots))
	}

	started := s.collectStartingSessionLogs(ctx, results)
	if ctx.Err() != nil {
		return snapshots, make([][]string, len(snapshots))
	}
	for index := range results {
		if _, ok := started[results[index].ID]; ok && results[index].State == "STARTING" {
			results[index].State = "READY"
			narration[index] = append(narration[index], "Session is running")
		}
	}
	return results, narration
}

func (s Service) statusScript(sessions []Session) string {
	var script strings.Builder
	marker := func(name string) { fmt.Fprintf(&script, "printf '%%s\\n' %s\n", sshexec.ShellQuote(name)) }

	script.WriteString("set -u\n")
	marker(schedulerMarkerCancel)
	for _, target := range cancellationTargets(sessions) {
		flag := ""
		if target.flag != "" {
			flag = target.flag + "="
		}
		fmt.Fprintf(&script, "csctl_cancel=$(scancel %s%s 2>&1) || printf '%%s|%%s\\n' %s \"$(printf '%%s' \"$csctl_cancel\" | tr '\\n|' '  ')\"\n",
			flag, sshexec.ShellQuote(target.value), sshexec.ShellQuote(target.key))
	}
	marker(schedulerMarkerQueue)
	script.WriteString("squeue --me --noheader --format='%i|%T|%N|%j'\n")

	names := make([]string, 0, len(sessions))
	for _, session := range sessions {
		names = append(names, session.JobName)
	}
	slices.Sort(names)
	marker(schedulerMarkerAccounting)
	fmt.Fprintf(&script, "sacct --noheader -X --starttime=%s --name=%s --format=JobIDRaw,State,NodeList,JobName,ElapsedRaw --parsable2\n",
		sshexec.ShellQuote(schedulerLookback(sessions, s.now())), sshexec.ShellQuote(strings.Join(names, ",")))
	return script.String()
}

func (s Service) schedulerObservations(ctx context.Context, host string, sessions []Session) (map[string]schedulerObservation, map[string]string, error) {
	output, err := s.Runner.Run(ctx, host, strings.NewReader(s.statusScript(sessions)), "sh", "-s", "--", "csctl-session-status")
	if err != nil {
		return nil, nil, err
	}
	parsed, err := sections(output, schedulerMarkerPrefix, []string{schedulerMarkerCancel, schedulerMarkerQueue, schedulerMarkerAccounting})
	if err != nil {
		return nil, nil, err
	}
	cancelByKey := map[string]string{}
	for _, line := range strings.Split(parsed[schedulerMarkerCancel], "\n") {
		if key, message, ok := strings.Cut(line, "|"); ok {
			cancelByKey[key] = strings.TrimSpace(message)
		}
	}
	byID, byName := map[string]schedulerObservation{}, map[string]schedulerObservation{}
	for _, marker := range []string{schedulerMarkerAccounting, schedulerMarkerQueue} {
		queue := marker == schedulerMarkerQueue
		for _, line := range strings.Split(parsed[marker], "\n") {
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
				if observation.elapsedSeconds == 0 {
					observation.elapsedSeconds = byID[observation.jobID].elapsedSeconds
				}
				byID[observation.jobID], byName[name] = observation, observation
			}
		}
	}
	result := make(map[string]schedulerObservation, len(sessions))
	cancelErrors := make(map[string]string)
	for _, session := range sessions {
		key := "name:" + session.JobName
		observation, ok := byName[session.JobName]
		if session.JobID != "" {
			key = "id:" + session.JobID
			observation, ok = byID[session.JobID]
		}
		if ok {
			result[session.ID] = observation
		}
		if message := cancelByKey[key]; message != "" && session.State == "STOPPING" {
			cancelErrors[session.ID] = message
		}
	}
	return result, cancelErrors, nil
}

func (s Service) narrateReconciled(current, snapshot *Session, lines []string) {
	if !reconciliationSnapshotCurrent(current, snapshot) {
		return
	}
	for _, line := range lines {
		s.sessionStatus(snapshot.ID, line)
	}
}
