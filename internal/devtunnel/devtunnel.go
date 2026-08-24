// Package devtunnel is the Microsoft Dev Tunnels management client. It creates,
// reads and deletes the per-allocation tunnel and validates every host and URI
// the service returns, so no other subsystem parses a Dev Tunnels response.
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
	// MinDurationSeconds and MaxDurationSeconds bound a tunnel's lifetime so it
	// cannot outlive the allocation it fronts by an unbounded margin.
	MinDurationSeconds = uint32(60 * 60)
	MaxDurationSeconds = uint32(30 * 24 * 60 * 60)
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
	Description        string
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

type Client struct {
	baseURL *url.URL
	client  *http.Client
}

func NewClient(baseURL string, client *http.Client) (*Client, error) {
	base, err := ParseProductionBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return newClientForBase(base, client), nil
}

func newClient(baseURL string, client *http.Client) (*Client, error) {
	base, err := httpx.ParseBaseURL(baseURL, "Dev Tunnels base URL")
	if err != nil {
		return nil, err
	}
	return newClientForBase(base, client), nil
}

func newClientForBase(base *url.URL, client *http.Client) *Client {
	return &Client{baseURL: base, client: BoundedClient(client, devTunnelTimeout)}
}

func SafeRedirect(from, to *url.URL) bool {
	if from == nil || to == nil || to.User != nil {
		return false
	}
	if from.Scheme == to.Scheme && from.Host == to.Host {
		return true
	}
	return from.Scheme == "https" && to.Scheme == "https" && IsAPIHost(from.Hostname()) && IsAPIHost(to.Hostname())
}

func IsAPIHost(host string) bool {
	host = strings.ToLower(host)
	const suffix = ".rel.tunnels.api.visualstudio.com"
	clusterID := strings.TrimSuffix(host, suffix)
	return host == "global.rel.tunnels.api.visualstudio.com" || clusterID != host && clusterIDPattern.MatchString(clusterID)
}

func (m *Client) Create(ctx context.Context, req CreateRequest) (Record, error) {
	if err := validateTunnelIdentity(req.OAuthToken, req.TunnelID, ""); err != nil || req.DurationSeconds < MinDurationSeconds || req.DurationSeconds > MaxDurationSeconds {
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
	requestCtx, cancel := context.WithTimeout(ctx, m.client.Timeout)
	defer cancel()
	endpoint := m.tunnelURL(req.TunnelID, "", true, false)
	request, err := m.newRequest(requestCtx, http.MethodPut, endpoint, req.OAuthToken, bytes.NewReader(body))
	if err != nil {
		return Record{}, err
	}
	request.Header.Set("If-Not-Match", "*")
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	return m.doRecord(request, req.OAuthToken, req.TunnelID, true)
}

func (m *Client) Get(ctx context.Context, req GetRequest) (Record, error) {
	if err := validateTunnelIdentity(req.AccessToken, req.TunnelID, req.ClusterID); err != nil {
		return Record{}, errors.New("Dev Tunnel get request is invalid")
	}
	requestCtx, cancel := context.WithTimeout(ctx, m.client.Timeout)
	defer cancel()
	request, err := m.newRequest(requestCtx, http.MethodGet, m.tunnelURL(req.TunnelID, req.ClusterID, false, true), req.AccessToken, nil)
	if err != nil {
		return Record{}, err
	}
	request.Header.Set("Authorization", "tunnel "+req.AccessToken)
	return m.doRecord(request, req.AccessToken, req.TunnelID, false)
}

func (m *Client) Delete(ctx context.Context, req DeleteRequest) error {
	if err := validateTunnelIdentity(req.OAuthToken, req.TunnelID, req.ClusterID); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, m.client.Timeout)
	defer cancel()
	request, err := m.newRequest(requestCtx, http.MethodDelete, m.tunnelURL(req.TunnelID, req.ClusterID, false, false), req.OAuthToken, nil)
	if err != nil {
		return err
	}
	_, status, err := httpx.Do(m.client, request, maxDevTunnelBody)
	if err != nil {
		return SafeError("delete Dev Tunnel", err, req.OAuthToken)
	}
	if status == http.StatusNotFound || status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("delete Dev Tunnel: HTTP %d", status)
}

func validateTunnelIdentity(token, tunnelID, clusterID string) error {
	if token == "" || len(token) > MaxToken || strings.ContainsAny(token, "\x00\r\n") || !devTunnelIDPattern.MatchString(tunnelID) || clusterID != "" && !clusterIDPattern.MatchString(clusterID) {
		return errors.New("Dev Tunnel request is invalid")
	}
	return nil
}

func (m *Client) newRequest(ctx context.Context, method string, endpoint *url.URL, token string, body io.Reader) (*http.Request, error) {
	request, err := httpx.NewRequest(ctx, method, endpoint.String(), token, body)
	if err != nil {
		return nil, errors.New("create Dev Tunnel request")
	}
	return request, nil
}

func (m *Client) tunnelURL(tunnelID, clusterID string, includeTokens, includePorts bool) *url.URL {
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

func (m *Client) doRecord(request *http.Request, token, expectedID string, requireTokens bool) (Record, error) {
	body, status, err := httpx.Do(m.client, request, maxDevTunnelBody)
	if err != nil {
		return Record{}, SafeError("request Dev Tunnel", err, token)
	}
	if status < 200 || status >= 300 {
		return Record{}, fmt.Errorf("Dev Tunnel request failed: HTTP %d", status)
	}
	var result tunnelResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&result); err != nil {
		return Record{}, errors.New("parse Dev Tunnel response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("parse Dev Tunnel response")
	}
	if result.TunnelID != expectedID || !devTunnelIDPattern.MatchString(result.TunnelID) || !clusterIDPattern.MatchString(result.ClusterID) || result.Expiration.IsZero() {
		return Record{}, errors.New("Dev Tunnel response identity is invalid")
	}
	hostToken := result.AccessTokens["host manage:ports"]
	connectToken := result.AccessTokens["connect"]
	if requireTokens && (!ValidToken(hostToken) || !ValidToken(connectToken)) {
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

func ValidToken(token string) bool {
	return token != "" && len(token) <= MaxToken && !strings.ContainsAny(token, " \t\r\n\x00")
}

func validateTunnelPorts(values []tunnelPortResponse) ([]PortRecord, error) {
	if len(values) > maxTunnelPorts {
		return nil, errors.New("Dev Tunnel response has too many ports")
	}
	ports := make([]PortRecord, 0, len(values))
	seenPorts := make(map[uint16]struct{}, len(values))
	for _, port := range values {
		if port.PortNumber == 0 || !validTunnelProtocol(port.Protocol) || !validBoundedTunnelText(port.Description, 1024, true) || len(port.PortForwardingURIs) > maxPortForwardingURIs {
			return nil, errors.New("Dev Tunnel response port is invalid")
		}
		if _, duplicate := seenPorts[port.PortNumber]; duplicate {
			return nil, errors.New("Dev Tunnel response has duplicate ports")
		}
		seenPorts[port.PortNumber] = struct{}{}
		seenURIs := make(map[string]struct{}, len(port.PortForwardingURIs))
		for _, candidate := range port.PortForwardingURIs {
			if err := ValidatePublicURI(candidate); err != nil {
				return nil, errors.New("Dev Tunnel response port is invalid")
			}
			if _, duplicate := seenURIs[candidate]; duplicate {
				return nil, errors.New("Dev Tunnel response port is invalid")
			}
			seenURIs[candidate] = struct{}{}
		}
		ports = append(ports, PortRecord{
			PortNumber: port.PortNumber, Protocol: port.Protocol, Description: port.Description,
			PortForwardingURIs: append([]string(nil), port.PortForwardingURIs...),
		})
	}
	return ports, nil
}

func validTunnelProtocol(protocol string) bool {
	return slices.Contains([]string{"auto", "tcp", "udp", "ssh", "rdp", "http", "https"}, protocol)
}

func validBoundedTunnelText(value string, limit int, allowEmpty bool) bool {
	if len(value) > limit || !allowEmpty && value == "" {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func ValidatePublicURI(raw string) error {
	if raw == "" || len(raw) > maxTunnelURI {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Host != parsed.Hostname() || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || !isPublicHost(parsed.Hostname()) {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	return nil
}

func isPublicHost(host string) bool {
	host = strings.ToLower(host)
	const suffix = ".devtunnels.ms"
	return len(host) > len(suffix) && len(host) <= 253 && strings.HasSuffix(host, suffix)
}

func SafeError(operation string, err error, secrets ...string) error {
	message := operation + ": " + err.Error()
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	if len(message) > maxDevTunnelError {
		message = message[:maxDevTunnelError]
	}
	return errors.New(message)
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

// tunnelOptions carries the one option this control plane sets. The field has
// no omitempty so that disabling inspection is stated on the wire rather than
// left to the service default.
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

func ParseProductionBaseURL(raw string) (*url.URL, error) {
	parsed, err := httpx.ParseBaseURL(raw, "Dev Tunnels base URL")
	if err != nil || parsed.Scheme != "https" || parsed.Host != parsed.Hostname() || !IsAPIHost(parsed.Hostname()) || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("Dev Tunnels base URL must be a recognized HTTPS management endpoint")
	}
	return parsed, nil
}

func BoundedClient(client *http.Client, fallback time.Duration) *http.Client {
	bounded := httpx.BoundedClient(client, fallback)
	bounded.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || len(via) == 0 || !SafeRedirect(via[0].URL, request.URL) {
			return http.ErrUseLastResponse
		}
		request.Header.Set("Authorization", via[len(via)-1].Header.Get("Authorization"))
		return nil
	}
	return bounded
}

// ValidID and ValidClusterID report whether a stored identifier still matches
// what the management API is allowed to have issued.
func ValidID(value string) bool { return devTunnelIDPattern.MatchString(value) }

func ValidClusterID(value string) bool { return clusterIDPattern.MatchString(value) }
