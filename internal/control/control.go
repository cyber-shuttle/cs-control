package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	stateVersion = 1
	maxOutput    = 1 << 20
)

var (
	aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	namePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	idPattern    = regexp.MustCompile(`^rt-[a-f0-9]{12}$`)
	jobPattern   = regexp.MustCompile(`^[0-9]+$`)
	wallPattern  = regexp.MustCompile(`^(?:[0-9]+-)?[0-9]{1,2}:[0-9]{2}:[0-9]{2}$`)
)

type GRES struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Partition struct {
	Name     string `json:"name"`
	CPUCount int    `json:"cpuCount"`
	Memory   string `json:"memory"`
	GRES     []GRES `json:"gres"`
}

type Resource struct {
	Host       string      `json:"host"`
	Accounts   []string    `json:"accounts"`
	Partitions []Partition `json:"partitions"`
	HomeDir    string      `json:"homeDir"`
}

type Runtime struct {
	ID             string    `json:"id"`
	SSH            string    `json:"ssh"`
	JobID          string    `json:"jobId,omitempty"`
	JobName        string    `json:"jobName"`
	State          string    `json:"state"`
	ReconcileError string    `json:"reconcileError,omitempty"`
	Partition      string    `json:"partition"`
	Account        string    `json:"account,omitempty"`
	CPUs           int       `json:"cpus"`
	MemoryMB       int       `json:"memoryMb"`
	Walltime       string    `json:"walltime"`
	Linkspan       string    `json:"linkspan"`
	Workflow       string    `json:"workflow"`
	RemoteRoot     string    `json:"remoteRoot"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type CreateRequest struct {
	ID         string
	SSH        string
	Partition  string
	Account    string
	CPUs       int
	MemoryMB   int
	Walltime   string
	Linkspan   string
	Workflow   string
	RemoteRoot string
}

type state struct {
	Version  int                 `json:"version"`
	Runtimes map[string]*Runtime `json:"runtimes"`
}

type Runner struct {
	SSHBin  string
	Timeout time.Duration
}

type Store struct{ Dir string }

type Service struct {
	Runner Runner
	Store  Store
	Now    func() time.Time
}

type limitBuffer struct {
	buf bytes.Buffer
	n   int
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.n {
		remain := b.n - b.buf.Len()
		if remain > 0 {
			_, _ = b.buf.Write(p[:remain])
		}
		return len(p), errors.New("command output exceeded limit")
	}
	return b.buf.Write(p)
}

func (b *limitBuffer) String() string { return b.buf.String() }

func (r Runner) run(ctx context.Context, alias, command string, stdin io.Reader) (string, error) {
	if !aliasPattern.MatchString(alias) {
		return "", errors.New("invalid SSH alias")
	}
	if r.SSHBin == "" {
		r.SSHBin = "ssh"
	}
	if r.Timeout <= 0 {
		r.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.SSHBin, alias, command)
	cmd.Stdin = stdin
	stdout := &limitBuffer{n: maxOutput}
	stderr := &limitBuffer{n: maxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("ssh command timed out: %w", ctx.Err())
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("ssh command failed: %s", message)
	}
	return stdout.String(), nil
}

func (r Runner) Discover(ctx context.Context, alias string) (Resource, error) {
	accountsOutput, err := r.run(ctx, alias, "sacctmgr show associations where user=$USER format=Account -p", nil)
	if err != nil {
		return Resource{}, err
	}
	partitionsOutput, err := r.run(ctx, alias, `sinfo -h -o "%P|%c|%m|%G"`, nil)
	if err != nil {
		return Resource{}, err
	}
	homeOutput, err := r.run(ctx, alias, "echo $HOME", nil)
	if err != nil {
		return Resource{}, err
	}
	partitions, err := parsePartitions(partitionsOutput)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Host:       alias,
		Accounts:   parseAccounts(accountsOutput),
		Partitions: partitions,
		HomeDir:    strings.TrimSpace(homeOutput),
	}, nil
}

func parseAccounts(output string) []string {
	seen := map[string]bool{}
	var accounts []string
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		account := strings.TrimSpace(strings.SplitN(line, "|", 2)[0])
		if account != "" && !seen[account] {
			seen[account] = true
			accounts = append(accounts, account)
		}
	}
	return accounts
}

func parsePartitions(output string) ([]Partition, error) {
	var partitions []Partition
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid sinfo line: %q", line)
		}
		cpuText := regexp.MustCompile(`[0-9]+`).FindString(parts[1])
		cpus, err := strconv.Atoi(cpuText)
		if err != nil {
			return nil, fmt.Errorf("invalid CPU count in sinfo line: %q", line)
		}
		gres, err := parseGRES(strings.TrimSpace(parts[3]))
		if err != nil {
			return nil, err
		}
		partitions = append(partitions, Partition{
			Name:     strings.TrimSuffix(strings.TrimSpace(parts[0]), "*"),
			CPUCount: cpus,
			Memory:   strings.TrimSpace(parts[2]),
			GRES:     gres,
		})
	}
	return partitions, nil
}

func parseGRES(value string) ([]GRES, error) {
	if value == "" || value == "(null)" {
		return []GRES{}, nil
	}
	var entries []string
	start, depth := 0, 0
	for i, char := range value {
		switch char {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				entries = append(entries, strings.TrimSpace(value[start:i]))
				start = i + 1
			}
		}
	}
	entries = append(entries, strings.TrimSpace(value[start:]))
	pattern := regexp.MustCompile(`^(.+):([0-9]+)(?:\([^)]*\))?$`)
	result := make([]GRES, 0, len(entries))
	for _, entry := range entries {
		match := pattern.FindStringSubmatch(entry)
		if match == nil {
			return nil, fmt.Errorf("invalid GRES entry: %q", entry)
		}
		count, _ := strconv.Atoi(match[2])
		result = append(result, GRES{Name: match[1], Count: count})
	}
	return result, nil
}

func (s Store) withLock(fn func(Store, *state) error) error {
	if s.Dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		s.Dir = filepath.Join(home, ".cybershuttle", "control")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(s.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck
	current, err := s.load()
	if err != nil {
		return err
	}
	return fn(s, current)
}

func (s Store) load() (*state, error) {
	path := filepath.Join(s.Dir, "state.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &state{Version: stateVersion, Runtimes: map[string]*Runtime{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if current.Version != stateVersion || current.Runtimes == nil {
		return nil, errors.New("unsupported state file")
	}
	for id, runtime := range current.Runtimes {
		if err := validateStoredRuntime(id, runtime); err != nil {
			return nil, fmt.Errorf("invalid stored runtime %q: %w", id, err)
		}
	}
	return &current, nil
}

func (s Store) save(current *state) error {
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(s.Dir, ".state-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(s.Dir, "state.json")); err != nil {
		return err
	}
	directory, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s Service) Create(ctx context.Context, request CreateRequest) (*Runtime, error) {
	if err := validateCreate(&request); err != nil {
		return nil, err
	}
	if request.ID == "" {
		var random [6]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		request.ID = "rt-" + hex.EncodeToString(random[:])
	}
	if !idPattern.MatchString(request.ID) {
		return nil, errors.New("runtime ID must match rt-[a-f0-9]{12}")
	}
	var created *Runtime
	err := s.Store.withLock(func(store Store, current *state) error {
		if _, exists := current.Runtimes[request.ID]; exists {
			return errors.New("runtime ID already exists")
		}
		now := s.now()
		intent := &Runtime{
			ID: request.ID, SSH: request.SSH, JobName: jobName(request.ID), State: "SUBMITTING",
			Partition: request.Partition, Account: request.Account, CPUs: request.CPUs,
			MemoryMB: request.MemoryMB, Walltime: request.Walltime, Linkspan: request.Linkspan,
			Workflow: request.Workflow, RemoteRoot: request.RemoteRoot, CreatedAt: now, UpdatedAt: now,
		}
		current.Runtimes[intent.ID] = intent
		if err := store.save(current); err != nil {
			return fmt.Errorf("persist submit intent: %w", err)
		}

		output, err := s.Runner.run(ctx, request.SSH, "sbatch --parsable", strings.NewReader(buildScript(request)))
		if err != nil {
			return fmt.Errorf("submit outcome pending reconciliation for %s: %w", intent.JobName, err)
		}
		jobID := strings.SplitN(strings.TrimSpace(output), ";", 2)[0]
		if !jobPattern.MatchString(jobID) {
			return fmt.Errorf("submit outcome pending reconciliation for %s: invalid job ID %q", intent.JobName, output)
		}
		intent.JobID, intent.State, intent.UpdatedAt = jobID, "PENDING", s.now()
		if err := store.save(current); err != nil {
			_, cancelErr := s.Runner.run(ctx, request.SSH, "scancel --jobid "+jobID, nil)
			if cancelErr != nil {
				return fmt.Errorf("persist submitted job %s: %w; compensation scancel failed: %v", jobID, err, cancelErr)
			}
			return fmt.Errorf("persist submitted job %s: %w; job was cancelled", jobID, err)
		}
		copy := *intent
		created = &copy
		return nil
	})
	return created, err
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func validateCreate(request *CreateRequest) error {
	if !aliasPattern.MatchString(request.SSH) {
		return errors.New("invalid SSH alias")
	}
	if !namePattern.MatchString(request.Partition) {
		return errors.New("invalid partition")
	}
	if request.Account != "" && !namePattern.MatchString(request.Account) {
		return errors.New("invalid account")
	}
	if request.CPUs < 1 || request.CPUs > 4096 {
		return errors.New("cpus must be between 1 and 4096")
	}
	if request.MemoryMB < 1 || request.MemoryMB > 100_000_000 {
		return errors.New("memory-mb is out of range")
	}
	if !wallPattern.MatchString(request.Walltime) {
		return errors.New("walltime must use [days-]HH:MM:SS")
	}
	for name, path := range map[string]string{"linkspan": request.Linkspan, "workflow": request.Workflow} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("%s must be an absolute remote path", name)
		}
	}
	if request.RemoteRoot != "" && (!filepath.IsAbs(request.RemoteRoot) || strings.ContainsAny(request.RemoteRoot, "\x00\r\n")) {
		return errors.New("remote-root must be an absolute remote path")
	}
	return nil
}

func validateStoredRuntime(key string, runtime *Runtime) error {
	if runtime == nil || !idPattern.MatchString(key) || runtime.ID != key {
		return errors.New("runtime ID is invalid or does not match its key")
	}
	request := CreateRequest{
		ID: runtime.ID, SSH: runtime.SSH, Partition: runtime.Partition, Account: runtime.Account,
		CPUs: runtime.CPUs, MemoryMB: runtime.MemoryMB, Walltime: runtime.Walltime,
		Linkspan: runtime.Linkspan, Workflow: runtime.Workflow, RemoteRoot: runtime.RemoteRoot,
	}
	if err := validateCreate(&request); err != nil {
		return err
	}
	if runtime.JobName != jobName(runtime.ID) {
		return errors.New("invalid job name")
	}
	if runtime.State == "SUBMITTING" {
		if runtime.JobID != "" && !jobPattern.MatchString(runtime.JobID) {
			return errors.New("invalid job ID")
		}
	} else if !jobPattern.MatchString(runtime.JobID) {
		return errors.New("invalid job ID")
	}
	if !knownState(runtime.State) {
		return errors.New("invalid runtime state")
	}
	if runtime.CreatedAt.IsZero() || runtime.UpdatedAt.IsZero() {
		return errors.New("timestamps are required")
	}
	return nil
}

func knownState(value string) bool {
	switch value {
	case "SUBMITTING", "PENDING", "RUNNING", "CONFIGURING", "COMPLETING", "RESIZING",
		"REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SIGNALING", "STAGE_OUT", "SUSPENDED",
		"STOPPING", "BOOT_FAIL", "CANCELLED", "COMPLETED", "DEADLINE", "FAILED", "NODE_FAIL",
		"OUT_OF_MEMORY", "PREEMPTED", "REVOKED", "SPECIAL_EXIT", "TIMEOUT", "UNKNOWN":
		return true
	default:
		return false
	}
}

func jobName(id string) string { return "cs-" + id }

func buildScript(request CreateRequest) string {
	root := request.RemoteRoot
	if root == "" {
		root = "$HOME/.cybershuttle/runtimes/" + request.ID
	}
	lines := []string{
		"#!/bin/bash",
		"#SBATCH --job-name=" + jobName(request.ID),
		"#SBATCH --nodes=1",
		"#SBATCH --ntasks=1",
		"#SBATCH --cpus-per-task=" + strconv.Itoa(request.CPUs),
		"#SBATCH --mem=" + strconv.Itoa(request.MemoryMB) + "M",
		"#SBATCH --time=" + request.Walltime,
		"#SBATCH --partition=" + request.Partition,
	}
	if request.Account != "" {
		lines = append(lines, "#SBATCH --account="+request.Account)
	}
	lines = append(lines,
		"set -eu",
		`LOG_DIR="$HOME/.cybershuttle/logs"`,
		`mkdir -p "$LOG_DIR"`,
		`exec >"$LOG_DIR/`+request.ID+`.out" 2>"$LOG_DIR/`+request.ID+`.err"`,
		"unset XDG_RUNTIME_DIR TMPDIR",
	)
	if request.RemoteRoot == "" {
		lines = append(lines, `REMOTE_ROOT="$HOME/.cybershuttle/runtimes/`+request.ID+`"`)
	} else {
		lines = append(lines, "REMOTE_ROOT="+shellQuote(root))
	}
	lines = append(lines,
		`mkdir -p "$REMOTE_ROOT"`,
		`SOCKET_DIR="${SLURM_TMPDIR:-/tmp}"`,
		`SOCKET="$SOCKET_DIR/`+jobName(request.ID)+`.sock"`,
		`rm -f "$SOCKET"`,
		"exec "+shellQuote(request.Linkspan)+" --host 127.0.0.1 --port 0 --socket \"$SOCKET\" --workflow "+shellQuote(request.Workflow)+" --runtime-id "+shellQuote(request.ID)+` --remote-root "$REMOTE_ROOT"`,
		"",
	)
	return strings.Join(lines, "\n")
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }

func (s Service) List(ctx context.Context) ([]Runtime, error) {
	var runtimes []Runtime
	err := s.Store.withLock(func(store Store, current *state) error {
		changed := false
		ids := make([]string, 0, len(current.Runtimes))
		for id := range current.Runtimes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			runtime := current.Runtimes[id]
			if reconcile(runtime.State) {
				state, err := s.reconcileRuntime(ctx, runtime)
				if err != nil {
					message := err.Error()
					if runtime.ReconcileError != message {
						runtime.ReconcileError, runtime.UpdatedAt, changed = message, s.now(), true
					}
				} else {
					if state != runtime.State || runtime.ReconcileError != "" {
						runtime.State, runtime.ReconcileError, runtime.UpdatedAt, changed = state, "", s.now(), true
					}
				}
			}
			runtimes = append(runtimes, *runtime)
		}
		if changed {
			return store.save(current)
		}
		return nil
	})
	return runtimes, err
}

func (s Service) Get(ctx context.Context, id string) (*Runtime, error) {
	if !idPattern.MatchString(id) {
		return nil, errors.New("invalid runtime ID")
	}
	var result *Runtime
	err := s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[id]
		if runtime == nil {
			return errors.New("runtime not found")
		}
		if reconcile(runtime.State) {
			state, err := s.reconcileRuntime(ctx, runtime)
			if err != nil {
				return err
			}
			if state != runtime.State {
				runtime.State, runtime.ReconcileError, runtime.UpdatedAt = state, "", s.now()
				if err := store.save(current); err != nil {
					return err
				}
			}
		}
		copy := *runtime
		result = &copy
		return nil
	})
	return result, err
}

func (s Service) Stop(ctx context.Context, id string) (*Runtime, error) {
	if !idPattern.MatchString(id) {
		return nil, errors.New("invalid runtime ID")
	}
	var result *Runtime
	err := s.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[id]
		if runtime == nil {
			return errors.New("runtime not found")
		}
		if reconcile(runtime.State) {
			if runtime.State == "SUBMITTING" {
				state, err := s.reconcileRuntime(ctx, runtime)
				if err != nil {
					return err
				}
				runtime.State = state
			}
			if _, err := s.Runner.run(ctx, runtime.SSH, "scancel --jobid "+runtime.JobID, nil); err != nil {
				return err
			}
			runtime.State = "STOPPING"
			if state, err := s.remoteState(ctx, runtime); err == nil {
				runtime.State = state
			}
			runtime.UpdatedAt = s.now()
			if err := store.save(current); err != nil {
				return err
			}
		}
		copy := *runtime
		result = &copy
		return nil
	})
	return result, err
}

func reconcile(state string) bool {
	switch state {
	case "SUBMITTING", "PENDING", "RUNNING", "CONFIGURING", "COMPLETING", "RESIZING",
		"REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SIGNALING", "STAGE_OUT", "SUSPENDED",
		"STOPPING", "UNKNOWN":
		return true
	default:
		return false
	}
}

func (s Service) reconcileRuntime(ctx context.Context, runtime *Runtime) (string, error) {
	if runtime.State != "SUBMITTING" {
		return s.remoteState(ctx, runtime)
	}
	output, err := s.Runner.run(ctx, runtime.SSH, "squeue --noheader --name="+runtime.JobName+" --format=%i|%T", nil)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if line != "" {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 || !jobPattern.MatchString(strings.TrimSpace(parts[0])) {
			return "", errors.New("invalid squeue response while reconciling submit intent")
		}
		runtime.JobID = strings.TrimSpace(parts[0])
		return normalizeState(parts[1]), nil
	}

	output, err = s.Runner.run(ctx, runtime.SSH, "sacct --noheader -X --name="+runtime.JobName+" --format=JobIDRaw,State,JobName --parsable2", nil)
	if err != nil {
		return "", err
	}
	for _, record := range strings.Split(output, "\n") {
		parts := strings.Split(record, "|")
		if len(parts) < 3 {
			continue
		}
		jobID := strings.TrimSpace(parts[0])
		if !jobPattern.MatchString(jobID) || strings.TrimSpace(parts[2]) != runtime.JobName {
			continue
		}
		runtime.JobID = jobID
		return normalizeState(parts[1]), nil
	}
	return "", fmt.Errorf("submission outcome for %s is unresolved: no matching job in squeue or sacct", runtime.JobName)
}

func (s Service) remoteState(ctx context.Context, runtime *Runtime) (string, error) {
	if !jobPattern.MatchString(runtime.JobID) {
		return "", errors.New("invalid stored job ID")
	}
	output, err := s.Runner.run(ctx, runtime.SSH, "squeue --noheader --jobs="+runtime.JobID+" --format=%T", nil)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if line != "" {
		return normalizeState(line), nil
	}
	output, err = s.Runner.run(ctx, runtime.SSH, "sacct --noheader -X --jobs="+runtime.JobID+" --format=State --parsable2", nil)
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	return normalizeState(strings.SplitN(line, "|", 2)[0]), nil
}

func normalizeState(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "UNKNOWN"
	}
	value = strings.TrimSuffix(strings.ToUpper(fields[0]), "+")
	if strings.HasPrefix(value, "CANCELLED") {
		return "CANCELLED"
	}
	switch value {
	case "STOPPED":
		return "SUSPENDED"
	case "PENDING", "RUNNING", "CONFIGURING", "COMPLETING", "RESIZING", "REQUEUED",
		"REQUEUE_FED", "REQUEUE_HOLD", "SIGNALING", "STAGE_OUT", "SUSPENDED",
		"BOOT_FAIL", "COMPLETED", "DEADLINE", "FAILED", "NODE_FAIL", "OUT_OF_MEMORY",
		"PREEMPTED", "REVOKED", "SPECIAL_EXIT", "TIMEOUT":
		return value
	default:
		return "UNKNOWN"
	}
}
