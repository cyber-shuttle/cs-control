// Validation that does not touch the network: resource fit, request fields, and workspace path grammar.
// Everything here is a pure predicate or refusal.
// The one check needing SSH lives beside prepareSession in lifecycle.go instead.
//
//	invalidRootFolder
//	resourcesFit, hasGPU, gpuSupports
//	safeRemotePath, homeRootExpression
//	resolveRemoteExecutable
//	safeWorkspaceSuffix, validatePartitionResources, oneRemotePath
//	safeRemoteExecutable
//	boundedSessionError, validWorkspaceExpression
//	validateCreate
//	validateWorkspacePrivateLayout
package control

import (
	"errors"
	"net/http"
	pathpkg "path"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

func invalidRootFolder(message string) error {
	return apierr.New("invalid_root_folder", message, http.StatusBadRequest)
}

func resourcesFit(resources resources, partition partition) bool {
	return resources.Cores <= partition.CPUCount && resources.MemoryMB <= partition.MemoryMB
}

func hasGPU(partition partition) bool {
	for _, gres := range partition.GRES {
		if gres.Name == "gpu" || strings.HasPrefix(gres.Name, "gpu:") {
			return true
		}
	}
	return false
}

func gpuSupports(partition partition, gpuType string, gpuCount int) bool {
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

func safeRemotePath(value string) bool {
	return remotePathPattern.MatchString(value) && pathpkg.Clean(value) == value && value != "/"
}

func homeRootExpression(value string) bool {
	switch value {
	case ".", "~", "$HOME", "${HOME}":
		return true
	default:
		return false
	}
}

func resolveRemoteExecutable(value, home string) string {
	rest, anchored := strings.CutPrefix(value, "$HOME/")
	if !anchored {
		return value
	}
	return pathpkg.Join(home, rest)
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

func validatePartitionResources(values []partition, name string, resources resources) error {
	matches := make([]partition, 0, 1)
	for _, value := range values {
		if value.Name == name {
			matches = append(matches, value)
		}
	}
	if len(matches) == 0 {
		return apierr.New("invalid_partition", "Slurm partition was not discovered for this host", http.StatusBadRequest)
	}

	gpuRequested := resources.GPUCount != 0 || resources.GPUType != ""
	if gpuRequested && (resources.GPUCount < 1 || !sshconfig.SafeName(resources.GPUType, 64)) {
		return apierr.New("invalid_gpu", "gpuType and positive gpuCount must be supplied together", http.StatusBadRequest)
	}
	if !gpuRequested {
		for _, partition := range matches {
			if !hasGPU(partition) && resourcesFit(resources, partition) {
				return nil
			}
		}
		return apierr.New("invalid_resource", "no CPU variant of the selected partition supports the requested resources", http.StatusBadRequest)
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
		return apierr.New("invalid_resource", "requested CPU or memory exceeds the matching GPU partition capacity", http.StatusBadRequest)
	}
	return apierr.New("invalid_gpu", "requested GPU is not available in the selected partition", http.StatusBadRequest)
}

func oneRemotePath(output string) (string, error) {
	value := strings.TrimSuffix(output, "\n")
	if value == "" || strings.ContainsAny(value, "\r\n") || !safeRemotePath(value) {
		return "", errors.New("not one safe absolute path")
	}
	return value, nil
}

func safeRemoteExecutable(value string) bool {
	if rest, anchored := strings.CutPrefix(value, "$HOME/"); anchored {
		return safeRemotePath("/" + rest)
	}
	return safeRemotePath(value) && strings.HasPrefix(value, "/")
}

func boundedSessionError(err error) string {
	return apierr.TruncateUTF8(strings.ToValidUTF8(err.Error(), "�"), maxSessionError)
}

func validWorkspaceExpression(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\\\x00\r\n") {
		return false
	}
	if homeRootExpression(value) {
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

func validateCreate(request *createRequest) error {
	if request.ID == "" && request.IdempotencyKey == "" {
		return apierr.New("invalid_idempotency_key", "idempotencyKey is required", http.StatusBadRequest)
	}
	if !sshconfig.ValidAlias(request.SSHHost) {
		return sshconfig.ErrInvalidAlias
	}
	if !sshconfig.SafeName(request.Partition, 64) {
		return apierr.New("invalid_partition", "invalid partition", http.StatusBadRequest)
	}
	if request.Account != "" && !sshconfig.SafeName(request.Account, 64) {
		return apierr.New("invalid_account", "invalid account", http.StatusBadRequest)
	}
	if !validWorkspaceExpression(request.RootFolder) {
		return invalidRootFolder("rootFolder must be a safe POSIX path: absolute, relative to the home, or under $HOME or $VAR")
	}
	if request.Resources.Cores < minCores || request.Resources.Cores > 4096 {
		return apierr.New("invalid_resources", "cores must be between 2 and 4096", http.StatusBadRequest)
	}
	if request.Resources.MemoryMB < minMemoryMB || request.Resources.MemoryMB > 100_000_000 {
		return apierr.New("invalid_resources", "memoryMb is out of range", http.StatusBadRequest)
	}
	if request.Resources.WallMinutes < 1 || request.Resources.WallMinutes > 525600 {
		return apierr.New("invalid_resources", "wallMinutes is out of range", http.StatusBadRequest)
	}
	if request.IdempotencyKey != "" && (len(request.IdempotencyKey) > 128 || strings.ContainsAny(request.IdempotencyKey, "\x00\r\n")) {
		return apierr.New("invalid_idempotency_key", "invalid idempotency key", http.StatusBadRequest)
	}
	return nil
}

func validateWorkspacePrivateLayout(home, workspace, privateRoot, sessionID, expression string) error {
	if workspace == privateRoot || strings.HasPrefix(workspace, privateRoot+"/") {
		return invalidRootFolder("workspace resolves inside the private session directory")
	}
	if !strings.HasPrefix(privateRoot, workspace+"/") {
		return nil
	}
	expected := pathpkg.Join(home, defaultSessionBase, sessionID)
	if workspace == home && homeRootExpression(expression) && privateRoot == expected {
		return nil
	}
	return invalidRootFolder("workspace may contain private session state only at $HOME/.cybershuttle/sessions/{sessionId}")
}
