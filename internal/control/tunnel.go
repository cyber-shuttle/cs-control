// One creator-owned Dev Tunnel per session seq, declaring both control and Jupyter ports at creation.
// Ports are derived from the session ID and seq, so they can be bound before the job starts.
// createSessionTunnel and releaseSessionTunnel are always used together to compensate a partial create.
//
//	sessionTunnelID, newJupyterToken
//	portPair, sessionPorts
//	sessionTunnelDurationSeconds
//	sessionPortURI
//	tunnelEndpoint
//	Service
//	sessionEndpoint, sessionAccess
//	createSessionTunnel
//	releaseSessionTunnel
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
)

func sessionTunnelID(sessionID string, seq int) (string, error) {
	value := sessionID + "-" + strconv.Itoa(seq)
	if !idPattern.MatchString(sessionID) || seq < 1 || !devtunnel.ValidID(value) {
		return "", errors.New("session tunnel identity is invalid")
	}
	return value, nil
}

func newJupyterToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate Jupyter token")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

type portPair struct{ control, jupyter uint16 }

func sessionPorts(sessionID string, seq int) portPair {
	sum := sha256.Sum256([]byte(sessionID + "/" + strconv.Itoa(seq)))
	base := 20000 + int(binary.BigEndian.Uint16(sum[:2]))%20000
	return portPair{control: uint16(base), jupyter: uint16(base + 1)}
}

func sessionTunnelDurationSeconds(wallMinutes int) uint32 {
	duration := time.Duration(wallMinutes)*time.Minute + tunnelCleanupGrace
	duration = min(max(duration, time.Duration(devtunnel.MinDurationSeconds)*time.Second), time.Duration(devtunnel.MaxDurationSeconds)*time.Second)
	return uint32(duration / time.Second)
}

func sessionPortURI(record devtunnel.Record, tunnel tunnelMetadata, number uint16) (string, error) {
	if record.ID != tunnel.ID || record.ClusterID != tunnel.ClusterID {
		return "", errors.New("the session tunnel identity does not match the session")
	}
	index := slices.IndexFunc(record.Ports, func(port devtunnel.PortRecord) bool { return port.PortNumber == number })
	if index < 0 {
		return "", errors.New("Dev Tunnel session port is unavailable")
	}
	port := record.Ports[index]
	if port.Protocol != "http" || port.PortNumber == 0 || len(port.PortForwardingURIs) != 1 {
		return "", errors.New("Dev Tunnel session port is invalid")
	}
	candidate := strings.TrimSuffix(port.PortForwardingURIs[0], "/")
	if err := devtunnel.ValidatePublicURI(candidate); err != nil {
		return "", errors.New("Dev Tunnel session URI is invalid")
	}
	return candidate, nil
}

type tunnelEndpoint struct {
	uri        string
	credential credentialstore.Credential
	expiresAt  time.Time
}

func (s Service) sessionEndpoint(ctx context.Context, session Session, number uint16) (tunnelEndpoint, error) {
	if s.Tunnels == nil || !idPattern.MatchString(session.ID) || session.Seq < 1 {
		return tunnelEndpoint{}, errors.New("the session is not addressable")
	}
	credential, err := s.Credentials.Get(session.ID, session.Seq)
	if err != nil {
		return tunnelEndpoint{}, errors.New("this session seq has no stored credential")
	}
	record, err := s.Tunnels.Get(ctx, devtunnel.GetRequest{AccessToken: credential.ConnectToken, TunnelID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID})
	if err != nil {
		return tunnelEndpoint{}, errors.New("the session tunnel could not be reached")
	}
	if !record.ExpiresAt.After(s.now()) {
		return tunnelEndpoint{}, errors.New("the session tunnel has expired")
	}
	uri, err := sessionPortURI(record, session.Tunnel, number)
	if err != nil {
		return tunnelEndpoint{}, err
	}
	return tunnelEndpoint{uri: uri, credential: credential, expiresAt: record.ExpiresAt.UTC()}, nil
}

func (s Service) sessionAccess(ctx context.Context, session Session) (*sessionAccessResponse, error) {
	unavailable := func(reason string) (*sessionAccessResponse, error) {
		return nil, apierr.New("session_access_unavailable", "Session access is unavailable: "+reason, http.StatusConflict)
	}
	if session.State != "READY" {
		return unavailable("the session is " + strings.ToLower(session.State))
	}
	endpoint, err := s.sessionEndpoint(ctx, session, sessionPorts(session.ID, session.Seq).jupyter)
	if err != nil {
		return unavailable(err.Error())
	}
	return &sessionAccessResponse{
		SessionID: session.ID, Seq: session.Seq, ExpiresAt: endpoint.expiresAt,
		Jupyter: sessionJupyterAccess{URI: endpoint.uri, Token: endpoint.credential.JupyterToken},
	}, nil
}

func (s Service) createSessionTunnel(ctx context.Context, session *Session, auth authn.TunnelAuthorization, seq int) (devtunnel.Record, string, error) {
	if s.Tunnels == nil || s.Credentials.Dir == "" {
		return devtunnel.Record{}, "", errors.New("Dev Tunnel lifecycle dependencies are unavailable")
	}
	tunnelID, err := sessionTunnelID(session.ID, seq)
	if err != nil {
		return devtunnel.Record{}, "", err
	}
	requestedAt := s.now().UTC()
	durationSeconds := sessionTunnelDurationSeconds(session.Resources.WallMinutes)
	ports := sessionPorts(session.ID, seq)
	record, err := s.Tunnels.Create(ctx, devtunnel.CreateRequest{
		Scheme: auth.Scheme, OAuthToken: auth.OAuthToken, TunnelID: tunnelID, DurationSeconds: durationSeconds,
		Ports: []devtunnel.PortSpec{
			{PortNumber: ports.control, Description: controlPortDescription},
			{PortNumber: ports.jupyter, Description: jupyterPortDescription, Anonymous: true},
		},
	})
	if err != nil {
		createErr := apierr.Redact("create session Dev Tunnel", err, auth.OAuthToken)
		cleanupErr := s.releaseSessionTunnel(auth, session.ID, seq, tunnelMetadata{ID: tunnelID})
		return devtunnel.Record{}, "", errors.Join(createErr, cleanupErr)
	}
	if record.ID != tunnelID || !devtunnel.ValidClusterID(record.ClusterID) || !devtunnel.ValidToken(record.HostToken) || !devtunnel.ValidToken(record.ConnectToken) || !record.ExpiresAt.After(requestedAt) {
		cleanupErr := s.releaseSessionTunnel(auth, session.ID, seq, tunnelMetadata{ID: record.ID, ClusterID: record.ClusterID})
		return devtunnel.Record{}, "", errors.Join(errors.New("created Dev Tunnel metadata is invalid"), cleanupErr)
	}
	jupyterToken, err := newJupyterToken()
	if err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.releaseSessionTunnel(auth, session.ID, seq, tunnelMetadata{ID: record.ID, ClusterID: record.ClusterID}))
	}
	candidate := *session
	candidate.Seq = seq
	candidate.JobName = jobName(session.ID, seq)
	candidate.Owner = auth.Principal
	candidate.Tunnel = tunnelMetadata{ID: record.ID, ClusterID: record.ClusterID, ExpiresAt: record.ExpiresAt.UTC()}
	credential := credentialstore.Credential{ConnectToken: record.ConnectToken, JupyterToken: jupyterToken}
	if err := s.Credentials.Put(session.ID, seq, credential); err != nil {
		return devtunnel.Record{}, "", errors.Join(err, s.releaseSessionTunnel(auth, session.ID, seq, tunnelMetadata{ID: record.ID, ClusterID: record.ClusterID}))
	}
	*session = candidate
	return record, jupyterToken, nil
}

func (s Service) releaseSessionTunnel(auth authn.TunnelAuthorization, sessionID string, seq int, tunnel tunnelMetadata) error {
	ctx, cancel := s.ownTimeout()
	defer cancel()
	var deleteErr error
	if s.Tunnels != nil && tunnel.ID != "" {
		if err := s.Tunnels.Delete(ctx, devtunnel.DeleteRequest{Scheme: auth.Scheme, OAuthToken: auth.OAuthToken, TunnelID: tunnel.ID, ClusterID: tunnel.ClusterID}); err != nil {
			deleteErr = apierr.Redact("compensate session Dev Tunnel", err, auth.OAuthToken)
		}
	}
	return errors.Join(deleteErr, s.Credentials.Delete(sessionID, seq))
}
