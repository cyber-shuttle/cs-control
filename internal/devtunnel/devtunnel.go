// Package devtunnel is the Dev Tunnels management client. It creates, reads, and deletes the per-session tunnel.
// It validates every host and URI the service returns, so no other subsystem parses a response directly.
//
//	Record, PortRecord, PortSpec, CreateRequest, GetRequest, DeleteRequest, Manager, client
//	createTunnelBody, createTunnelPort, tunnelAccessControl, tunnelAccessEntry, tunnelOptions, tunnelResponse,
//	tunnelPortResponse
//	isAPIHost, safeRedirect, newClientForBase, isPublicHost, validatePublicURI,
//	validTunnelProtocol, validateTunnelPorts, safeError, validToken
//	createTunnelPorts, ParseBaseURL, ParseProductionBaseURL, NewClient
//	GuardedClient, SafeError, ValidToken, ValidatePublicURI
//	ValidID, ValidClusterID
package devtunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const (
	MaxToken   = 16 << 10
	APIVersion = "2023-09-27-preview"

	maxDevTunnelBody      int64 = 64 << 10
	maxDevTunnelError           = 2048
	maxTunnelURI                = 2048
	maxTunnelPorts              = 256
	maxPortForwardingURIs       = 16
	devTunnelTimeout            = 15 * time.Second
	MinDurationSeconds          = uint32(60 * 60)
	MaxDurationSeconds          = uint32(30 * 24 * 60 * 60)
)

var (
	devTunnelIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$`)
	clusterIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type Record struct {
	ID           string
	ClusterID    string
	ConnectToken string
	HostToken    string
	Ports        []PortRecord
	ExpiresAt    time.Time
}

type PortRecord struct {
	PortNumber         uint16
	Protocol           string
	PortForwardingURIs []string
}

type PortSpec struct {
	PortNumber  uint16
	Description string
	Anonymous   bool
}

type CreateRequest struct {
	OAuthToken      string
	TunnelID        string
	DurationSeconds uint32
	Ports           []PortSpec
}

type GetRequest struct {
	AccessToken string
	TunnelID    string
	ClusterID   string
}

type DeleteRequest struct {
	OAuthToken string
	TunnelID   string
	ClusterID  string
}

type Manager interface {
	Create(context.Context, CreateRequest) (Record, error)
	Get(context.Context, GetRequest) (Record, error)
	Delete(context.Context, DeleteRequest) error
}

type client struct {
	baseURL *url.URL
	client  *http.Client
}

type createTunnelBody struct {
	TunnelID         string             `json:"tunnelId"`
	CustomExpiration uint32             `json:"customExpiration"`
	Options          tunnelOptions      `json:"options"`
	Ports            []createTunnelPort `json:"ports,omitempty"`
}

type createTunnelPort struct {
	PortNumber    uint16               `json:"portNumber"`
	Protocol      string               `json:"protocol"`
	Description   string               `json:"description"`
	AccessControl *tunnelAccessControl `json:"accessControl,omitempty"`
}

type tunnelAccessControl struct {
	Entries []tunnelAccessEntry `json:"entries"`
}

type tunnelAccessEntry struct {
	Type     string   `json:"type"`
	Subjects []string `json:"subjects"`
	Scopes   []string `json:"scopes"`
}

type tunnelOptions struct {
	IsInspectionEnabled bool `json:"isInspectionEnabled"`
}

type tunnelResponse struct {
	TunnelID     string               `json:"tunnelId"`
	ClusterID    string               `json:"clusterId"`
	AccessTokens map[string]string    `json:"accessTokens"`
	Ports        []tunnelPortResponse `json:"ports,omitempty"`
	Expiration   time.Time            `json:"expiration"`
}

type tunnelPortResponse struct {
	PortNumber         uint16   `json:"portNumber"`
	Description        string   `json:"description,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	PortForwardingURIs []string `json:"portForwardingUris"`
}

func isAPIHost(host string) bool {
	host = strings.ToLower(host)
	const suffix = ".rel.tunnels.api.visualstudio.com"
	clusterID := strings.TrimSuffix(host, suffix)
	return host == "global.rel.tunnels.api.visualstudio.com" || clusterID != host && clusterIDPattern.MatchString(clusterID)
}

func safeRedirect(from, to *url.URL) bool {
	if httpx.SameOriginRedirect(from, to) {
		return true
	}
	return from != nil && to != nil && from.Scheme == "https" && to.Scheme == "https" && isAPIHost(from.Hostname()) && isAPIHost(to.Hostname())
}

func newClientForBase(base *url.URL, httpClient *http.Client) *client {
	return &client{baseURL: base, client: httpx.GuardedClient(httpClient, devTunnelTimeout, safeRedirect)}
}

func isPublicHost(host string) bool {
	host = strings.ToLower(host)
	const suffix = ".devtunnels.ms"
	return len(host) > len(suffix) && len(host) <= 253 && strings.HasSuffix(host, suffix)
}

func validatePublicURI(raw string) error {
	if raw == "" || len(raw) > maxTunnelURI {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Host != parsed.Hostname() || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || !isPublicHost(parsed.Hostname()) {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	return nil
}

func validTunnelProtocol(protocol string) bool {
	return slices.Contains([]string{"auto", "tcp", "udp", "ssh", "rdp", "http", "https"}, protocol)
}

func validateTunnelPorts(values []tunnelPortResponse) ([]PortRecord, error) {
	if len(values) > maxTunnelPorts {
		return nil, errors.New("Dev Tunnel response has too many ports")
	}
	ports := make([]PortRecord, 0, len(values))
	seenPorts := make(map[uint16]struct{}, len(values))
	for _, port := range values {
		if port.PortNumber == 0 || !validTunnelProtocol(port.Protocol) || len(port.Description) > 1024 || strings.ContainsFunc(port.Description, func(r rune) bool { return r < 0x20 || r == 0x7f }) || len(port.PortForwardingURIs) > maxPortForwardingURIs {
			return nil, errors.New("Dev Tunnel response port is invalid")
		}
		if _, duplicate := seenPorts[port.PortNumber]; duplicate {
			return nil, errors.New("Dev Tunnel response has duplicate ports")
		}
		seenPorts[port.PortNumber] = struct{}{}
		seenURIs := make(map[string]struct{}, len(port.PortForwardingURIs))
		for _, candidate := range port.PortForwardingURIs {
			if err := validatePublicURI(candidate); err != nil {
				return nil, errors.New("Dev Tunnel response port is invalid")
			}
			if _, duplicate := seenURIs[candidate]; duplicate {
				return nil, errors.New("Dev Tunnel response port is invalid")
			}
			seenURIs[candidate] = struct{}{}
		}
		ports = append(ports, PortRecord{
			PortNumber:         port.PortNumber,
			Protocol:           port.Protocol,
			PortForwardingURIs: append([]string(nil), port.PortForwardingURIs...),
		})
	}
	return ports, nil
}

func safeError(operation string, err error, secrets ...string) error {
	message := operation + ": " + err.Error()
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return errors.New(apierr.TruncateUTF8(message, maxDevTunnelError))
}

func validToken(token string) bool {
	return token != "" && len(token) <= MaxToken && !strings.ContainsAny(token, " \t\r\n\x00")
}

func (m *client) newRequest(ctx context.Context, method string, endpoint *url.URL, token string, body io.Reader) (*http.Request, error) {
	request, err := httpx.NewRequest(ctx, method, endpoint.String(), token, body)
	if err != nil {
		return nil, errors.New("create Dev Tunnel request")
	}
	return request, nil
}

func (m *client) tunnelURL(tunnelID, clusterID string, includeTokens, includePorts bool) *url.URL {
	endpoint := *m.baseURL
	if clusterID != "" && endpoint.Hostname() == "global.rel.tunnels.api.visualstudio.com" {
		endpoint.Host = clusterID + ".rel.tunnels.api.visualstudio.com"
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/tunnels/" + url.PathEscape(tunnelID)
	query := url.Values{}
	query.Add("api-version", APIVersion)
	if includeTokens {
		query.Add("tokenScopes", "host manage:ports")
		query.Add("tokenScopes", "connect")
	}
	if includePorts {
		query.Add("includePorts", "true")
	}
	endpoint.RawQuery = query.Encode()
	return &endpoint
}

func (m *client) doRecord(request *http.Request, token, expectedID string, requireTokens bool) (Record, error) {
	body, status, err := httpx.Do(m.client, request, maxDevTunnelBody)
	if err != nil {
		return Record{}, safeError("request Dev Tunnel", err, token)
	}
	if status < 200 || status >= 300 {
		return Record{}, fmt.Errorf("Dev Tunnel request failed: HTTP %d", status)
	}
	var result tunnelResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&result); err != nil {
		return Record{}, errors.New("parse Dev Tunnel response")
	}
	if err := decoder.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("parse Dev Tunnel response")
	}
	if result.TunnelID != expectedID || !clusterIDPattern.MatchString(result.ClusterID) || result.Expiration.IsZero() {
		return Record{}, errors.New("Dev Tunnel response identity is invalid")
	}
	hostToken := result.AccessTokens["host manage:ports"]
	connectToken := result.AccessTokens["connect"]
	if requireTokens && (!validToken(hostToken) || !validToken(connectToken)) {
		return Record{}, errors.New("Dev Tunnel response omitted required access tokens")
	}
	ports, err := validateTunnelPorts(result.Ports)
	if err != nil {
		return Record{}, err
	}
	return Record{
		ID: result.TunnelID, ClusterID: result.ClusterID,
		HostToken: hostToken, ConnectToken: connectToken, Ports: ports,
		ExpiresAt: result.Expiration.UTC(),
	}, nil
}

func createTunnelPorts(specs []PortSpec) []createTunnelPort {
	ports := make([]createTunnelPort, 0, len(specs))
	for _, spec := range specs {
		port := createTunnelPort{PortNumber: spec.PortNumber, Protocol: "http", Description: spec.Description}
		if spec.Anonymous {
			port.AccessControl = &tunnelAccessControl{Entries: []tunnelAccessEntry{{Type: "Anonymous", Subjects: []string{}, Scopes: []string{"connect"}}}}
		}
		ports = append(ports, port)
	}
	return ports
}

func (m *client) Create(ctx context.Context, req CreateRequest) (Record, error) {
	if req.DurationSeconds < MinDurationSeconds || req.DurationSeconds > MaxDurationSeconds {
		return Record{}, errors.New("Dev Tunnel create request is invalid")
	}
	body, err := json.Marshal(createTunnelBody{
		TunnelID:         req.TunnelID,
		CustomExpiration: req.DurationSeconds,
		Options:          tunnelOptions{IsInspectionEnabled: false},
		Ports:            createTunnelPorts(req.Ports),
	})
	if err != nil {
		return Record{}, errors.New("marshal Dev Tunnel create request")
	}
	endpoint := m.tunnelURL(req.TunnelID, "", true, false)
	request, err := m.newRequest(ctx, http.MethodPut, endpoint, req.OAuthToken, bytes.NewReader(body))
	if err != nil {
		return Record{}, err
	}
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	return m.doRecord(request, req.OAuthToken, req.TunnelID, true)
}

func (m *client) Get(ctx context.Context, req GetRequest) (Record, error) {
	request, err := m.newRequest(ctx, http.MethodGet, m.tunnelURL(req.TunnelID, req.ClusterID, false, true), "", nil)
	if err != nil {
		return Record{}, err
	}
	request.Header.Set("Authorization", "tunnel "+req.AccessToken)
	return m.doRecord(request, req.AccessToken, req.TunnelID, false)
}

func (m *client) Delete(ctx context.Context, req DeleteRequest) error {
	request, err := m.newRequest(ctx, http.MethodDelete, m.tunnelURL(req.TunnelID, req.ClusterID, false, false), req.OAuthToken, nil)
	if err != nil {
		return err
	}
	_, status, err := httpx.Do(m.client, request, maxDevTunnelBody)
	if err != nil {
		return safeError("delete Dev Tunnel", err, req.OAuthToken)
	}
	if status == http.StatusNotFound || status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("delete Dev Tunnel: HTTP %d", status)
}

func ParseBaseURL(raw, subject string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("%s is invalid", subject)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func ParseProductionBaseURL(raw string) (*url.URL, error) {
	parsed, err := ParseBaseURL(raw, "Dev Tunnels base URL")
	if err != nil || parsed.Scheme != "https" || parsed.Host != parsed.Hostname() || !isAPIHost(parsed.Hostname()) || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("Dev Tunnels base URL must be a recognized HTTPS management endpoint")
	}
	return parsed, nil
}

func NewClient(baseURL string, httpClient *http.Client) (*client, error) {
	base, err := ParseProductionBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return newClientForBase(base, httpClient), nil
}

func GuardedClient(client *http.Client, fallback time.Duration) *http.Client {
	return httpx.GuardedClient(client, fallback, safeRedirect)
}

func SafeError(operation string, err error, secrets ...string) error {
	return safeError(operation, err, secrets...)
}

func ValidToken(token string) bool { return validToken(token) }

func ValidatePublicURI(raw string) error { return validatePublicURI(raw) }

func ValidID(value string) bool { return devTunnelIDPattern.MatchString(value) }

func ValidClusterID(value string) bool { return clusterIDPattern.MatchString(value) }
