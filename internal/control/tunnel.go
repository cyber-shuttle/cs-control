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
	unavailable := func() (*RuntimeAccessResponse, error) {
		return nil, apierr.New("runtime_access_unavailable", "Linkspan access is unavailable", 409)
	}
	if s.Tunnels == nil || !idPattern.MatchString(runtime.ID) || !generationPattern.MatchString(runtime.Generation) || runtime.State != "READY" || !runtime.Tunnel.ExpiresAt.After(s.now()) {
		return unavailable()
	}
	credential, err := s.Credentials.Get(runtime.ID, runtime.Generation)
	if err != nil {
		return unavailable()
	}
	record, err := s.Tunnels.Get(ctx, devtunnel.GetRequest{AccessToken: credential.ConnectToken, TunnelID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID})
	if err != nil {
		return unavailable()
	}
	uri, err := allocationPortURI(record, runtime.Tunnel, jupyterPortDescription)
	if err != nil {
		return unavailable()
	}
	return &RuntimeAccessResponse{
		RuntimeID: runtime.ID, Generation: runtime.Generation, ExpiresAt: runtime.Tunnel.ExpiresAt.UTC(),
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
		cleanupErr := s.deletePotentiallyCreatedTunnel(ctx, auth, tunnelID)
		return devtunnel.Record{}, "", errors.Join(createErr, cleanupErr)
	}
	if record.ID != tunnelID || !devtunnel.ValidClusterID(record.ClusterID) || !devtunnel.ValidToken(record.HostToken) || !devtunnel.ValidToken(record.ConnectToken) || !record.ExpiresAt.After(requestedAt) {
		cleanupErr := s.cleanupUncommittedTunnel(ctx, auth, runtime.ID, generation, record)
		return devtunnel.Record{}, "", errors.Join(errors.New("created Dev Tunnel metadata is invalid"), cleanupErr)
	}
	jupyterToken, err := newJupyterToken()
	if err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.cleanupUncommittedTunnel(ctx, auth, runtime.ID, generation, record))
	}
	candidate := *runtime
	candidate.Generation = generation
	candidate.Owner = auth.Principal
	candidate.Tunnel = TunnelMetadata{ID: record.ID, ClusterID: record.ClusterID, ExpiresAt: record.ExpiresAt.UTC()}
	credential := GenerationCredential{ConnectToken: record.ConnectToken, JupyterToken: jupyterToken}
	if err := s.Credentials.Put(runtime.ID, generation, credential); err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.cleanupUncommittedTunnel(ctx, auth, runtime.ID, generation, record))
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

func (s Service) deletePotentiallyCreatedTunnel(ctx context.Context, auth authn.TunnelAuthorization, tunnelID string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.Runner.EffectiveTimeout())
	defer cancel()
	if err := s.Tunnels.Delete(cleanupCtx, devtunnel.DeleteRequest{OAuthToken: auth.OAuthToken, TunnelID: tunnelID}); err != nil {
		return devtunnel.SafeError("compensate uncertain Dev Tunnel create", err, auth.OAuthToken)
	}
	return nil
}

func (s Service) cleanupUncommittedTunnel(ctx context.Context, auth authn.TunnelAuthorization, runtimeID, generation string, record devtunnel.Record) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.Runner.EffectiveTimeout())
	defer cancel()
	credentialErr := s.Credentials.Delete(runtimeID, generation)
	deleteErr := s.Tunnels.Delete(cleanupCtx, devtunnel.DeleteRequest{OAuthToken: auth.OAuthToken, TunnelID: record.ID, ClusterID: record.ClusterID})
	return errors.Join(credentialErr, deleteErr)
}

func (s Service) compensateAllocationTunnel(auth authn.TunnelAuthorization, runtime Runtime) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.Runner.EffectiveTimeout())
	defer cancel()
	var deleteErr error
	if s.Tunnels != nil && runtime.Tunnel.ID != "" {
		deleteErr = s.Tunnels.Delete(ctx, devtunnel.DeleteRequest{OAuthToken: auth.OAuthToken, TunnelID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID})
	}
	return errors.Join(deleteErr, s.Credentials.Delete(runtime.ID, runtime.Generation))
}

func allocationPortURI(record devtunnel.Record, tunnel TunnelMetadata, description string) (string, error) {
	if record.ID != tunnel.ID || record.ClusterID != tunnel.ClusterID || record.ExpiresAt.Sub(tunnel.ExpiresAt) > time.Second || tunnel.ExpiresAt.Sub(record.ExpiresAt) > time.Second {
		return "", errors.New("Dev Tunnel metadata does not match the runtime")
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
