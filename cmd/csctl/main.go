// Package main is csctl, a single binary that runs on a researcher's own machine and binds to loopback.
// run is the composition root and builds the one control.Service every subcommand shares.
// runServe owns the listener's lifetime and closes every component it built on any failure.
//
//	Version
//	init
//	stringList, printUsage, usageError, defaultStateDir, envOr
//	serveComponents, newServeComponents
//	runServe, run, main
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/control"
	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/gateway"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const (
	Version                       = "0.1.0"
	defaultDevTunnelManagementURL = "https://global.rel.tunnels.api.visualstudio.com"
	defaultOIDCIssuer             = "https://cilogon.org"
	sshTimeout                    = 20 * time.Second
	serveReadHeaderTimeout        = 10 * time.Second
	serveShutdownTimeout          = 25 * time.Second
)

func init() { httpx.UserAgent = "cs-control/" + Version }

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  csctl [global options] serve --oidc-client-id CLIENT_ID --custos-url URL \
      --allowed-origin ORIGIN [--allowed-origin ORIGIN ...]
  csctl help
  csctl version

Identity (Custos login):
  --oidc-issuer ISSUER (default https://cilogon.org)
  --oidc-client-id CLIENT_ID (required)
  --custos-url URL (required), e.g. https://custos.cybershuttle.org
  CSCTL_OIDC_CLIENT_SECRET=SECRET (required, for the sign-in relay's token exchange)

Trusted session configuration:
  --linkspan PATH or CSCTL_LINKSPAN=PATH
  --devtunnel-management-url URL or CSCTL_DEVTUNNEL_MANAGEMENT_URL=URL
  Linkspan defaults to `+control.DefaultLinkspanPath+`, which each host resolves
  against its own home and which creating a session installs when missing.`)
}

func usageError() error {
	printUsage()
	return errors.New("invalid command")
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cs-control"
	}
	return filepath.Join(home, ".cybershuttle", "control")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

type serveComponents struct {
	handler http.Handler
	closers []func()
}

func (components *serveComponents) close() {
	if components == nil {
		return
	}
	for _, closer := range components.closers {
		closer()
	}
}

func newServeComponents(service control.Service, allowedOrigins []string, oidcIssuer, oidcClientID, custosURL, oidcClientSecret string) (*serveComponents, error) {
	validator, err := authn.NewValidator(custosURL, oidcIssuer, oidcClientID, nil)
	if err != nil {
		return nil, err
	}
	key, err := authn.LoadOrCreateTunnelLinkKey(filepath.Join(service.Store.Dir, authn.TunnelLinkKeyFileName))
	if err != nil {
		return nil, err
	}
	linkBroker, err := authn.NewLinkBroker(service.Config.HostsDir, key, nil)
	if err != nil {
		return nil, err
	}
	service.TunnelLinks = linkBroker
	auth := gateway.NewSSHAuthManager(service.Runner)
	api := control.NewHTTPHandler(service, auth)
	components := &serveComponents{closers: []func(){linkBroker.Close, auth.Close, api.Close}}
	oauthHandler, err := authn.NewOAuthBoundary(api, validator, allowedOrigins)
	if err != nil {
		components.close()
		return nil, err
	}
	handler, err := authn.NewSignInRoutes(oauthHandler, validator, oidcClientSecret, allowedOrigins)
	if err != nil {
		components.close()
		return nil, err
	}
	components.handler = handler
	return components, nil
}

func runServe(ctx context.Context, service control.Service, args []string, listen func(string, string) (net.Listener, error)) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listenAddress := flags.String("listen", "127.0.0.1:8045", "loopback listen address")
	oidcIssuer := flags.String("oidc-issuer", defaultOIDCIssuer, "OIDC issuer validated against its own discovery document and JWKS")
	oidcClientID := flags.String("oidc-client-id", "", "OIDC client ID pinned as the ID token audience")
	custosURL := flags.String("custos-url", "", "Custos base URL resolving a validated ID token to a user via GET {custos-url}/me")
	var allowedOrigins stringList
	flags.Var(&allowedOrigins, "allowed-origin", "exact browser origin allowed to call the API (repeatable)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := control.ValidateLoopbackListen(*listenAddress); err != nil {
		return err
	}
	if strings.TrimSpace(*oidcClientID) == "" {
		return errors.New("--oidc-client-id is required")
	}
	if strings.TrimSpace(*custosURL) == "" {
		return errors.New("--custos-url is required")
	}
	oidcClientSecret := os.Getenv("CSCTL_OIDC_CLIENT_SECRET")
	if strings.TrimSpace(oidcClientSecret) == "" {
		return errors.New("CSCTL_OIDC_CLIENT_SECRET is required")
	}
	if err := safeio.EnsurePrivateDir(service.Store.Dir); err != nil {
		return err
	}
	components, err := newServeComponents(service, allowedOrigins, *oidcIssuer, *oidcClientID, *custosURL, oidcClientSecret)
	if err != nil {
		return err
	}
	listener, err := listen("tcp", *listenAddress)
	if err != nil {
		components.close()
		return err
	}
	server := &http.Server{
		Handler:           components.handler,
		ReadHeaderTimeout: serveReadHeaderTimeout,
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()

	var result error
	select {
	case <-ctx.Done():
	case serveErr := <-serveErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			result = serveErr
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), serveShutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	components.close()
	return errors.Join(result, shutdownErr)
}

func run(ctx context.Context, args []string) error {
	global := flag.NewFlagSet("csctl", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	global.Usage = printUsage
	linkspan := global.String("linkspan", envOr("CSCTL_LINKSPAN", control.DefaultLinkspanPath), "remote Linkspan path, absolute or anchored at $HOME/; a missing one is installed there")
	devTunnelManagementURL := global.String("devtunnel-management-url", envOr("CSCTL_DEVTUNNEL_MANAGEMENT_URL", defaultDevTunnelManagementURL), "recognized HTTPS Dev Tunnels management endpoint")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		return usageError()
	}
	tunnelManager, err := devtunnel.NewClient(*devTunnelManagementURL, nil)
	if err != nil {
		return err
	}
	stateDir := defaultStateDir()
	credentialDir, err := filepath.Abs(filepath.Join(stateDir, "credentials"))
	if err != nil {
		return fmt.Errorf("resolve credential directory: %w", err)
	}
	service := control.Service{
		Runner: sshexec.Runner{Timeout: sshTimeout, ControlNamespace: stateDir},
		Store:  control.Store{Dir: stateDir},
		Config: control.Config{LinkspanPath: *linkspan, HostsDir: filepath.Join(stateDir, "hosts")},
		Logs:   control.NewSessionLogs(), Metrics: control.NewSessionMetrics(), Tunnels: tunnelManager,
		Credentials: credentialstore.Store{Dir: credentialDir}, HostPreparations: &sync.Map{},
	}
	switch args[0] {
	case "serve":
		return runServe(ctx, service, args[1:], net.Listen)
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "version":
		if len(args) != 1 {
			return usageError()
		}
		fmt.Println(Version)
		return nil
	default:
		return usageError()
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "csctl:", err)
		os.Exit(1)
	}
}
