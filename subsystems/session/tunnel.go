// Session tunnels are part of the session state machine: deterministic ports, requested lifetime, remote tunnel
// validation, compensation, and the private per-seq capability all derive from session identity and state. The
// Dev Tunnels manager supplies vendor operations and TunnelCredentials supplies the owner's linked account; no
// transport subsystem owns or persists session lifecycle state.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/security"
)

const (
	maxSessionCapability = 64 << 10
	tunnelCleanupGrace   = 15 * time.Minute
)

type TunnelCredentials interface {
	Credential(context.Context, security.Principal) (devtunnel.Credential, error)
}

type sessionPorts struct {
	Control uint16
	Jupyter uint16
}

type sessionCapability struct {
	ConnectToken string `json:"connectToken"`
	JupyterToken string `json:"jupyterToken"`
}

type tunnelEndpoint struct {
	URI          string
	ConnectToken string
	JupyterToken string
	ExpiresAt    time.Time
}

func ports(sessionID string, seq int) sessionPorts {
	sum := sha256.Sum256([]byte(sessionID + "/" + strconv.Itoa(seq)))
	base := 20000 + int(binary.BigEndian.Uint16(sum[:2]))%20000
	return sessionPorts{Control: uint16(base), Jupyter: uint16(base + 1)}
}

func capabilityPath(dir, sessionID string, seq int) (string, error) {
	if !filepath.IsAbs(dir) || !idPattern.MatchString(sessionID) || seq < 1 {
		return "", errors.New("capability store identity is invalid")
	}
	return filepath.Join(dir, sessionID+"-"+strconv.Itoa(seq)+".token"), nil
}

func validCapability(capability sessionCapability) bool {
	decoded, ok := security.DecodeBase64URL(capability.JupyterToken)
	return security.ValidCredential(capability.ConnectToken) && ok && len(decoded) == 32
}

func putCapability(dir, sessionID string, seq int, capability sessionCapability) error {
	location, err := capabilityPath(dir, sessionID, seq)
	if err != nil {
		return err
	}
	if !validCapability(capability) {
		return errors.New("session capability is invalid")
	}
	encoded, err := json.Marshal(capability)
	if err != nil {
		return errors.New("encode session capability")
	}
	if err := security.EnsurePrivateDir(dir); err != nil {
		return err
	}
	return security.ReplaceFile(location, encoded)
}

func getCapability(dir, sessionID string, seq int) (sessionCapability, error) {
	location, err := capabilityPath(dir, sessionID, seq)
	if err != nil {
		return sessionCapability{}, err
	}
	if err := security.PrivateDir(dir); err != nil {
		return sessionCapability{}, err
	}
	data, err := security.ReadPrivateFile(location, maxSessionCapability)
	if err != nil {
		return sessionCapability{}, err
	}
	var capability sessionCapability
	if err := security.DecodeStrict(bytes.NewReader(data), &capability); err != nil || !validCapability(capability) {
		return sessionCapability{}, errors.New("stored session capability is invalid")
	}
	return capability, nil
}

func deleteCapability(dir, sessionID string, seq int) error {
	location, err := capabilityPath(dir, sessionID, seq)
	if err != nil {
		return err
	}
	if err := security.RemoveFile(location); err != nil {
		return errors.New("delete session capability")
	}
	return nil
}

func sessionTunnelDuration(wallMinutes int) uint32 {
	duration := time.Duration(wallMinutes)*time.Minute + tunnelCleanupGrace
	duration = min(max(duration, time.Duration(devtunnel.MinDurationSeconds)*time.Second), time.Duration(devtunnel.MaxDurationSeconds)*time.Second)
	return uint32(duration / time.Second)
}

func (s Service) sessionEndpoint(ctx context.Context, session Session, number uint16) (tunnelEndpoint, error) {
	capability, err := getCapability(s.capabilityDir, session.ID, session.Seq)
	if err != nil {
		return tunnelEndpoint{}, errors.New("this session seq has no stored capability")
	}
	record, err := s.tunnelManager.Get(ctx, devtunnel.GetRequest{
		AccessToken: capability.ConnectToken, TunnelID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID,
	})
	if err != nil {
		return tunnelEndpoint{}, errors.New("the session tunnel could not be reached")
	}
	if !record.ExpiresAt.After(s.utcNow()) {
		return tunnelEndpoint{}, errors.New("the session tunnel has expired")
	}
	if record.ID != session.Tunnel.ID || record.ClusterID != session.Tunnel.ClusterID {
		return tunnelEndpoint{}, errors.New("the session tunnel identity does not match the session")
	}
	uri, err := record.HTTPURI(number)
	if err != nil {
		return tunnelEndpoint{}, errors.New("Dev Tunnel session port is invalid")
	}
	return tunnelEndpoint{URI: uri, ConnectToken: capability.ConnectToken, JupyterToken: capability.JupyterToken, ExpiresAt: record.ExpiresAt.UTC()}, nil
}

func (s Service) sessionAccess(ctx context.Context, session Session) (*sessionAccessResponse, error) {
	unavailable := func(reason string) (*sessionAccessResponse, error) {
		return nil, security.New("session_access_unavailable", "Session access is unavailable: "+reason, http.StatusConflict)
	}
	if session.State != "READY" {
		return unavailable("the session is " + strings.ToLower(session.State))
	}
	endpoint, err := s.sessionEndpoint(ctx, session, ports(session.ID, session.Seq).Jupyter)
	if err != nil {
		return unavailable(err.Error())
	}
	return &sessionAccessResponse{
		SessionID: session.ID, Seq: session.Seq, ExpiresAt: endpoint.ExpiresAt,
		Jupyter: sessionJupyterAccess{URI: endpoint.URI, Token: endpoint.JupyterToken},
	}, nil
}

func (s Service) createSessionTunnel(ctx context.Context, session *Session, principal security.Principal, credential devtunnel.Credential, seq int) (devtunnel.Record, string, error) {
	tunnelID := session.ID + "-" + strconv.Itoa(seq)
	if !idPattern.MatchString(session.ID) || seq < 1 || !devtunnel.ValidID(tunnelID) {
		return devtunnel.Record{}, "", errors.New("session tunnel identity is invalid")
	}
	requestedAt := s.utcNow()
	portNumbers := ports(session.ID, seq)
	record, err := s.tunnelManager.Create(ctx, devtunnel.CreateRequest{
		Scheme: credential.Scheme, OAuthToken: credential.Token, TunnelID: tunnelID,
		DurationSeconds: sessionTunnelDuration(session.Resources.WallMinutes),
		Ports: []devtunnel.PortSpec{
			{PortNumber: portNumbers.Control, Description: "cybershuttle-control"},
			{PortNumber: portNumbers.Jupyter, Description: "cybershuttle-jupyter", Anonymous: true},
		},
	})
	if err != nil {
		return devtunnel.Record{}, "", errors.Join(security.Redact("create session Dev Tunnel", err, credential.Token), s.releaseTunnel(credential, session.ID, seq, tunnelMetadata{ID: tunnelID}))
	}
	tunnel := tunnelMetadata{ID: record.ID, ClusterID: record.ClusterID, ExpiresAt: record.ExpiresAt.UTC()}
	if record.ID != tunnelID || !devtunnel.ValidClusterID(record.ClusterID) || !security.ValidCredential(record.HostToken) || !security.ValidCredential(record.ConnectToken) || !record.ExpiresAt.After(requestedAt) {
		return devtunnel.Record{}, "", errors.Join(errors.New("created Dev Tunnel metadata is invalid"), s.releaseTunnel(credential, session.ID, seq, tunnel))
	}
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	jupyterToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
	if err := putCapability(s.capabilityDir, session.ID, seq, sessionCapability{ConnectToken: record.ConnectToken, JupyterToken: jupyterToken}); err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.releaseTunnel(credential, session.ID, seq, tunnel))
	}
	candidate := *session
	candidate.Seq, candidate.JobName, candidate.Owner, candidate.Tunnel = seq, jobName(session.ID, seq), principal, tunnel
	*session = candidate
	return record, jupyterToken, nil
}

func (s Service) releaseTunnel(credential devtunnel.Credential, sessionID string, seq int, tunnel tunnelMetadata) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.tunnelTimeout)
	defer cancel()
	var deleteErr error
	if tunnel.ID != "" && credential.Token != "" {
		if err := s.tunnelManager.Delete(ctx, devtunnel.DeleteRequest{
			Scheme: credential.Scheme, OAuthToken: credential.Token, TunnelID: tunnel.ID, ClusterID: tunnel.ClusterID,
		}); err != nil {
			deleteErr = security.Redact("compensate session Dev Tunnel", err, credential.Token)
		}
	}
	return errors.Join(deleteErr, deleteCapability(s.capabilityDir, sessionID, seq))
}
