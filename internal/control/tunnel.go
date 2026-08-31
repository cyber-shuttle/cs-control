package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
)

func newGeneration() (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "g-" + hex.EncodeToString(value[:]), nil
}

func allocationTunnelID(runtimeID, generation string) (string, error) {
	value := runtimeID + "-" + generation
	if !idPattern.MatchString(runtimeID) || !generationPattern.MatchString(generation) || !devtunnel.ValidID(value) {
		return "", errors.New("allocation tunnel identity is invalid")
	}
	return value, nil
}

// newJupyterToken mints the Jupyter Server identity token. It is the only credential the
// browser needs, is stored beside the connect token in the mode-0600 generation credential,
// and reaches the allocation through the job environment rather than the script.
func newJupyterToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate Jupyter token")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (s Service) RuntimeAccess(ctx context.Context, runtime Runtime) (*RuntimeAccessResponse, error) {
	// Naming the reason is what makes a refusal actionable: the causes below are
	// distinct failures that otherwise arrive as one indistinguishable 409.
	unavailable := func(reason string) (*RuntimeAccessResponse, error) {
		return nil, apierr.New("runtime_access_unavailable", "Linkspan access is unavailable: "+reason, 409)
	}
	if s.Tunnels == nil || !idPattern.MatchString(runtime.ID) || !generationPattern.MatchString(runtime.Generation) {
		return unavailable("the runtime is not addressable")
	}
	if runtime.State != "READY" {
		return unavailable("the runtime is " + strings.ToLower(runtime.State))
	}
	credential, err := s.Credentials.Get(runtime.ID, runtime.Generation)
	if err != nil {
		return unavailable("this allocation generation has no stored credential")
	}
	record, err := s.Tunnels.Get(ctx, devtunnel.GetRequest{AccessToken: credential.ConnectToken, TunnelID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID})
	if err != nil {
		return unavailable("the allocation tunnel could not be reached")
	}
	// The service extends a hosted tunnel's expiration, so the live record is the
	// only authoritative one; the persisted value is a creation-time record and
	// drifts as soon as Linkspan starts serving traffic.
	if !record.ExpiresAt.After(s.now()) {
		return unavailable("the allocation tunnel has expired")
	}
	uri, err := allocationPortURI(record, runtime.Tunnel, jupyterPortDescription)
	if err != nil {
		return unavailable(err.Error())
	}
	return &RuntimeAccessResponse{
		RuntimeID: runtime.ID, Generation: runtime.Generation, ExpiresAt: record.ExpiresAt.UTC(),
		Jupyter: RuntimeJupyterAccess{URI: uri, Token: credential.JupyterToken},
	}, nil
}

func (s Service) createAllocationTunnel(ctx context.Context, runtime *Runtime, auth authn.TunnelAuthorization) (devtunnel.Record, string, error) {
	if s.Tunnels == nil || s.Credentials.Dir == "" {
		return devtunnel.Record{}, "", errors.New("Dev Tunnel lifecycle dependencies are unavailable")
	}
	generation, err := newGeneration()
	if err != nil {
		return devtunnel.Record{}, "", err
	}
	tunnelID, err := allocationTunnelID(runtime.ID, generation)
	if err != nil {
		return devtunnel.Record{}, "", err
	}
	requestedAt := s.now().UTC()
	durationSeconds := allocationTunnelDurationSeconds(runtime.Resources.WallMinutes)
	ports := allocationPorts(runtime.ID, generation)
	record, err := s.Tunnels.Create(ctx, devtunnel.CreateRequest{
		OAuthToken: auth.OAuthToken, TunnelID: tunnelID, DurationSeconds: durationSeconds,
		Ports: []devtunnel.PortSpec{
			{PortNumber: ports.control, Description: controlPortDescription},
			// Anonymous at the tunnel layer so a static browser app reaches it without Dev Tunnel
			// identity cookies; Jupyter Server's own identity token is the authorization.
			{PortNumber: ports.jupyter, Description: jupyterPortDescription, Anonymous: true},
		},
	})
	if err != nil {
		createErr := devtunnel.SafeError("create allocation Dev Tunnel", err, auth.OAuthToken)
		cleanupErr := s.releaseAllocationTunnel(auth, runtime.ID, generation, TunnelMetadata{ID: tunnelID})
		return devtunnel.Record{}, "", errors.Join(createErr, cleanupErr)
	}
	if record.ID != tunnelID || !devtunnel.ValidClusterID(record.ClusterID) || !devtunnel.ValidToken(record.HostToken) || !devtunnel.ValidToken(record.ConnectToken) || !record.ExpiresAt.After(requestedAt) {
		cleanupErr := s.releaseAllocationTunnel(auth, runtime.ID, generation, TunnelMetadata{ID: record.ID, ClusterID: record.ClusterID})
		return devtunnel.Record{}, "", errors.Join(errors.New("created Dev Tunnel metadata is invalid"), cleanupErr)
	}
	jupyterToken, err := newJupyterToken()
	if err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.releaseAllocationTunnel(auth, runtime.ID, generation, TunnelMetadata{ID: record.ID, ClusterID: record.ClusterID}))
	}
	candidate := *runtime
	candidate.Generation = generation
	candidate.JobName = jobName(runtime.ID, generation)
	candidate.Owner = auth.Principal
	candidate.Tunnel = TunnelMetadata{ID: record.ID, ClusterID: record.ClusterID, ExpiresAt: record.ExpiresAt.UTC()}
	credential := GenerationCredential{ConnectToken: record.ConnectToken, JupyterToken: jupyterToken}
	if err := s.Credentials.Put(runtime.ID, generation, credential); err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.releaseAllocationTunnel(auth, runtime.ID, generation, TunnelMetadata{ID: record.ID, ClusterID: record.ClusterID}))
	}
	*runtime = candidate
	return record, jupyterToken, nil
}

type portPair struct{ control, jupyter uint16 }

// allocationPorts derives both listening ports from the generation, so cs-control can declare them
// on the tunnel before the job starts and the job can bind exactly what was declared.
// ponytail: two random high ports; a collision on a shared compute node fails the allocation
// visibly — probe free ports from inside the job if that ever bites.
func allocationPorts(runtimeID, generation string) portPair {
	sum := sha256.Sum256([]byte(runtimeID + "/" + generation))
	base := 20000 + int(binary.BigEndian.Uint16(sum[:2]))%20000
	return portPair{control: uint16(base), jupyter: uint16(base + 1)}
}

func allocationTunnelDurationSeconds(wallMinutes int) uint32 {
	duration := time.Duration(wallMinutes)*time.Minute + tunnelCleanupGrace
	duration = min(max(duration, time.Duration(devtunnel.MinDurationSeconds)*time.Second), time.Duration(devtunnel.MaxDurationSeconds)*time.Second)
	return uint32(duration / time.Second)
}

// releaseAllocationTunnel gives back one generation's tunnel and the credential
// stored beside it, in that order. An uncertain create names no cluster, because
// the response that would have carried one never arrived; the delete is
// idempotent either way, as is deleting a credential that was never written.
func (s Service) releaseAllocationTunnel(auth authn.TunnelAuthorization, runtimeID, generation string, tunnel TunnelMetadata) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.Runner.EffectiveTimeout())
	defer cancel()
	var deleteErr error
	if s.Tunnels != nil && tunnel.ID != "" {
		if err := s.Tunnels.Delete(ctx, devtunnel.DeleteRequest{OAuthToken: auth.OAuthToken, TunnelID: tunnel.ID, ClusterID: tunnel.ClusterID}); err != nil {
			deleteErr = devtunnel.SafeError("compensate allocation Dev Tunnel", err, auth.OAuthToken)
		}
	}
	return errors.Join(deleteErr, s.Credentials.Delete(runtimeID, generation))
}

func allocationPortURI(record devtunnel.Record, tunnel TunnelMetadata, description string) (string, error) {
	// Only the identity is stable across a tunnel's life: the management service
	// slides the expiration forward while the tunnel is hosted, so comparing it
	// to the value stored at creation refuses every healthy allocation.
	if record.ID != tunnel.ID || record.ClusterID != tunnel.ClusterID {
		return "", errors.New("the allocation tunnel identity does not match the runtime")
	}
	result := ""
	for _, port := range record.Ports {
		if port.Description != description {
			continue
		}
		if port.Protocol != "http" || port.PortNumber == 0 || len(port.PortForwardingURIs) != 1 {
			return "", errors.New("Dev Tunnel allocation port is invalid")
		}
		candidate := strings.TrimSuffix(port.PortForwardingURIs[0], "/")
		if err := devtunnel.ValidatePublicURI(candidate); err != nil || result != "" && result != candidate {
			return "", errors.New("Dev Tunnel allocation URI is invalid")
		}
		result = candidate
	}
	if result == "" {
		return "", errors.New("Dev Tunnel allocation port is unavailable")
	}
	return result, nil
}
