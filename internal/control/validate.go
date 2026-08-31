package control

import (
	"context"
	"errors"
	pathpkg "path"
	"strings"
	"unicode/utf8"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

// Every workspace refusal carries one code, so a client can act on the class of
// failure while the message names the particular one.
func invalidRootFolder(message string) error {
	return apierr.New("invalid_root_folder", message, 400)
}

func validatePartitionResources(values []Partition, name string, resources Resources) error {
	matches := make([]Partition, 0, 1)
	for _, value := range values {
		if value.Name == name {
			matches = append(matches, value)
		}
	}
	if len(matches) == 0 {
		return apierr.New("invalid_partition", "SLURM partition was not discovered for this host", 400)
	}

	gpuRequested := resources.GPUCount != 0 || resources.GPUType != ""
	if gpuRequested && (resources.GPUCount < 1 || !namePattern.MatchString(resources.GPUType)) {
		return apierr.New("invalid_gpu", "gpuType and positive gpuCount must be supplied together", 400)
	}
	if !gpuRequested {
		for _, partition := range matches {
			if !hasGPU(partition) && resourcesFit(resources, partition) {
				return nil
			}
		}
		return apierr.New("invalid_resource", "no CPU variant of the selected partition supports the requested resources", 400)
	}

	gpuAvailable := false
	for _, partition := range matches {
		if gpuSupports(partition, resources.GPUType, resources.GPUCount) {
			gpuAvailable = true
			if resourcesFit(resources, partition) {
				return nil
			}
		}
	}
	if gpuAvailable {
		return apierr.New("invalid_resource", "requested CPU or memory exceeds the matching GPU partition capacity", 400)
	}
	return apierr.New("invalid_gpu", "requested GPU is not available in the selected partition", 400)
}

func resourcesFit(resources Resources, partition Partition) bool {
	return resources.Cores <= partition.CPUCount && resources.MemoryMB <= partition.MemoryMB
}

func hasGPU(partition Partition) bool {
	for _, gres := range partition.GRES {
		if gres.Name == "gpu" || strings.HasPrefix(gres.Name, "gpu:") {
			return true
		}
	}
	return false
}

func gpuSupports(partition Partition, gpuType string, gpuCount int) bool {
	for _, gres := range partition.GRES {
		if gres.Count < gpuCount {
			continue
		}
		if gres.Name == "gpu" || strings.TrimPrefix(gres.Name, "gpu:") == gpuType {
			return true
		}
	}
	return false
}

func validateCreate(request *CreateRequest) error {
	if request.ID == "" && request.IdempotencyKey == "" {
		return apierr.New("invalid_idempotency_key", "idempotencyKey is required", 400)
	}
	if !sshconfig.ValidAlias(request.SSHHost) {
		return sshconfig.ErrInvalidAlias
	}
	if !namePattern.MatchString(request.Partition) {
		return apierr.New("invalid_partition", "invalid partition", 400)
	}
	if request.Account != "" && !namePattern.MatchString(request.Account) {
		return apierr.New("invalid_account", "invalid account", 400)
	}
	if !validWorkspaceExpression(request.RootFolder) {
		return invalidRootFolder("rootFolder must be a safe absolute, home-relative, or environment-relative POSIX path")
	}
	if request.Resources.Cores < MinCores || request.Resources.Cores > 4096 {
		return apierr.New("invalid_resources", "cores must be between 2 and 4096", 400)
	}
	if request.Resources.MemoryMB < MinMemoryMB || request.Resources.MemoryMB > 100_000_000 {
		return apierr.New("invalid_resources", "memoryMb is out of range", 400)
	}
	if request.Resources.WallMinutes < 1 || request.Resources.WallMinutes > 525600 {
		return apierr.New("invalid_resources", "wallMinutes is out of range", 400)
	}
	if request.IdempotencyKey != "" && (len(request.IdempotencyKey) > 128 || strings.ContainsAny(request.IdempotencyKey, "\x00\r\n")) {
		return apierr.New("invalid_idempotency_key", "invalid idempotency key", 400)
	}
	return nil
}

func validWorkspaceExpression(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\\\x00\r\n") {
		return false
	}
	if value == "." || value == "~" || value == "$HOME" || value == "${HOME}" {
		return true
	}
	if strings.HasPrefix(value, "/") {
		return safeRemotePath(value)
	}
	if strings.HasPrefix(value, "~/") {
		return safeWorkspaceSuffix(strings.TrimPrefix(value, "~/"))
	}
	if match := workspaceVar.FindStringSubmatch(value); match != nil {
		if strings.HasSuffix(value, "/") {
			return false
		}
		name := match[1]
		if name == "" {
			name = match[2]
		}
		return len(name) <= 64 && (match[3] == "" || safeWorkspaceSuffix(match[3]))
	}
	return safeWorkspaceSuffix(value)
}

func safeWorkspaceSuffix(value string) bool {
	if value == "" || pathpkg.Clean(value) != value || strings.HasPrefix(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || !workspaceSegment.MatchString(part) {
			return false
		}
	}
	return true
}

func (s Service) resolveWorkspaceRoot(ctx context.Context, alias, home, expression string) (string, error) {
	if !validWorkspaceExpression(expression) || !safeRemotePath(home) {
		return "", invalidRootFolder("workspace expression is invalid")
	}
	base, suffix := home, ""
	switch {
	case expression == "." || expression == "~" || expression == "$HOME" || expression == "${HOME}":
	case strings.HasPrefix(expression, "/"):
		base = expression
	case strings.HasPrefix(expression, "~/"):
		suffix = strings.TrimPrefix(expression, "~/")
	case workspaceVar.MatchString(expression):
		match := workspaceVar.FindStringSubmatch(expression)
		name := match[1]
		if name == "" {
			name = match[2]
		}
		suffix = match[3]
		if name != "HOME" {
			output, err := s.Runner.Run(ctx, alias, nil, "printenv", name)
			if err != nil {
				return "", invalidRootFolder("workspace environment variable " + name + " is unavailable")
			}
			base, err = oneRemotePath(output)
			if err != nil {
				return "", invalidRootFolder("workspace environment variable " + name + " must contain one absolute safe path")
			}
		}
	default:
		suffix = expression
	}
	resolved := base
	if suffix != "" {
		resolved = pathpkg.Join(base, suffix)
	}
	if !safeRemotePath(resolved) {
		return "", invalidRootFolder("workspace resolves to an unsafe path")
	}
	return resolved, nil
}

func validateWorkspacePrivateLayout(home, workspace, privateRoot, runtimeID, expression string) error {
	if workspace == privateRoot || strings.HasPrefix(workspace, privateRoot+"/") {
		return invalidRootFolder("workspace resolves inside the private runtime directory")
	}
	if !strings.HasPrefix(privateRoot, workspace+"/") {
		return nil
	}
	// HOME is an explicitly supported workspace. Its private state is safe only
	// at the exact hidden runtime path.
	expected := pathpkg.Join(home, ".cybershuttle", "runtimes", runtimeID)
	if workspace == home && homeRootExpression(expression) && privateRoot == expected {
		return nil
	}
	return invalidRootFolder("workspace may contain private runtime state only at $HOME/.cybershuttle/runtimes/{runtimeId}")
}

func oneRemotePath(output string) (string, error) {
	value := strings.TrimSuffix(output, "\n")
	if value == "" || strings.ContainsAny(value, "\r\n") || !safeRemotePath(value) {
		return "", errors.New("not one safe absolute path")
	}
	return value, nil
}

func safeRemotePath(value string) bool {
	return remotePathPattern.MatchString(value) && pathpkg.Clean(value) == value && value != "/"
}

// A remote executable may be anchored at $HOME, so one setting serves hosts
// whose accounts do not share a home directory. Discovery resolves the anchor
// before the path reaches a script.
func safeRemoteExecutable(value string) bool {
	if rest, anchored := strings.CutPrefix(value, "$HOME/"); anchored {
		return safeRemotePath("/" + rest)
	}
	return safeRemotePath(value) && strings.HasPrefix(value, "/")
}

func resolveRemoteExecutable(value, home string) string {
	rest, anchored := strings.CutPrefix(value, "$HOME/")
	if !anchored {
		return value
	}
	return pathpkg.Join(home, rest)
}

func homeRootExpression(value string) bool {
	switch value {
	case ".", "~", "$HOME", "${HOME}":
		return true
	default:
		return false
	}
}

func boundedOptionalRuntimeError(err error) string {
	if err == nil {
		return ""
	}
	return boundedRuntimeError(err)
}

func boundedRuntimeError(err error) string {
	return truncateUTF8(strings.ToValidUTF8(err.Error(), "�"), maxRuntimeError)
}

// truncateUTF8 cuts value to at most limit bytes without splitting a rune.
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
