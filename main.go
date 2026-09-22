// Package main is csctl, a single binary that runs on a researcher's own machine and binds to loopback.
// run dispatches the CLI; serve validates before listening. newServeComponents composes authentication, SSH,
// session, and tunnel-link owners over one state directory and closes them on failure or shutdown.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/db"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/security"
	"github.com/cyber-shuttle/cs-control/internal/ssh"
	"github.com/cyber-shuttle/cs-control/subsystems/oauth"
	"github.com/cyber-shuttle/cs-control/subsystems/session"
	sshapi "github.com/cyber-shuttle/cs-control/subsystems/ssh"
	"github.com/cyber-shuttle/cs-control/subsystems/telemetry"
	"github.com/cyber-shuttle/cs-control/subsystems/tunnel"
)

const (
	Version                       = "0.1.0"
	defaultDevTunnelManagementURL = "https://global.rel.tunnels.api.visualstudio.com"
	defaultOIDCIssuer             = "https://cilogon.org"
	sshTimeout                    = 20 * time.Second
	serveReadHeaderTimeout        = 10 * time.Second
	serveShutdownTimeout          = 25 * time.Second
)

func init() { security.UserAgent = "cs-control/" + Version }

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

State:
  CSCTL_DATABASE_URL=URL (required), a Postgres URL whose search_path names the schema csctl owns

Trusted session configuration:
  --linkspan PATH or CSCTL_LINKSPAN=PATH
  --devtunnel-management-url URL or CSCTL_DEVTUNNEL_MANAGEMENT_URL=URL
  Linkspan defaults to `+session.DefaultLinkspanPath+`, which each host resolves
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

type services struct {
	DatabaseURL   string
	Configs       ssh.Configurations
	SessionStore  session.Store
	LinkspanPath  string
	TunnelManager session.TunnelManager
	CapabilityDir string
	TunnelTimeout time.Duration
}

type serveComponents struct {
	handler http.Handler
	closers []func()
}

// close releases components in reverse construction order.
func (components *serveComponents) close() {
	for _, closer := range slices.Backward(components.closers) {
		closer()
	}
}

func newServeComponents(svcs services, authentication *oauth.Service) (*serveComponents, error) {
	database, err := db.Open(svcs.DatabaseURL, svcs.SessionStore.Dir, session.Schema+sshapi.Schema)
	if err != nil {
		return nil, err
	}
	components := &serveComponents{closers: []func(){func() { _ = database.Close() }}}
	fail := func(err error) (*serveComponents, error) {
		components.close()
		return nil, err
	}
	svcs.SessionStore.Database = database
	controlManager := ssh.NewControlManager()
	components.closers = append(components.closers, controlManager.Close)
	sshService, err := sshapi.NewService(database, svcs.Configs, controlManager)
	if err != nil {
		return fail(err)
	}
	tunnelService, err := tunnel.NewService(svcs.SessionStore.Dir, svcs.Configs.Dir, nil)
	if err != nil {
		return fail(err)
	}
	components.closers = append(components.closers, tunnelService.Close)
	sessionService := session.NewService(svcs.Configs, svcs.SessionStore, svcs.LinkspanPath, svcs.TunnelManager, tunnelService, svcs.CapabilityDir, svcs.TunnelTimeout)
	components.closers = append(components.closers, sessionService.Close)
	registryRoutes, err := router.New(
		authentication.Routes(),
		sshService.Routes(),
		sessionService.Routes(),
		telemetry.Service{Sessions: sessionService}.Routes(),
		tunnelService.Routes(),
	)
	if err != nil {
		return fail(err)
	}
	components.handler = authentication.Protect(registryRoutes)
	return components, nil
}

func validateLoopbackListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("csctl serve only listens on an explicit loopback address")
	}
	return nil
}

func runServe(ctx context.Context, svcs services, args []string, listen func(string, string) (net.Listener, error)) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listenAddress := flags.String("listen", "127.0.0.1:8045", "loopback listen address")
	oidcIssuer := flags.String("oidc-issuer", defaultOIDCIssuer, "OIDC issuer validated against its own discovery document and JWKS")
	oidcClientID := flags.String("oidc-client-id", "", "OIDC client ID pinned as the ID token audience")
	custosURL := flags.String("custos-url", "", "Custos base URL resolving a validated ID token to a user via GET {custos-url}/me")
	var allowedOrigins []string
	flags.Func("allowed-origin", "exact browser origin allowed to call the API (repeatable)", func(value string) error {
		allowedOrigins = append(allowedOrigins, value)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateLoopbackListen(*listenAddress); err != nil {
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
	svcs.DatabaseURL = os.Getenv("CSCTL_DATABASE_URL")
	if strings.TrimSpace(svcs.DatabaseURL) == "" {
		return errors.New("CSCTL_DATABASE_URL is required")
	}
	authentication, err := oauth.NewService(*custosURL, *oidcIssuer, *oidcClientID, oidcClientSecret, allowedOrigins, nil)
	if err != nil {
		return err
	}
	if err := security.EnsurePrivateDir(svcs.SessionStore.Dir); err != nil {
		return err
	}
	components, err := newServeComponents(svcs, authentication)
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
	linkspan := global.String("linkspan", cmp.Or(os.Getenv("CSCTL_LINKSPAN"), session.DefaultLinkspanPath), "remote Linkspan path, absolute or anchored at $HOME/; a missing one is installed there")
	devTunnelManagementURL := global.String("devtunnel-management-url", cmp.Or(os.Getenv("CSCTL_DEVTUNNEL_MANAGEMENT_URL"), defaultDevTunnelManagementURL), "recognized HTTPS Dev Tunnels management endpoint")
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
	switch args[0] {
	case "serve":
		tunnelManager, err := devtunnel.NewClient(*devTunnelManagementURL, nil)
		if err != nil {
			return err
		}
		stateDir := defaultStateDir()
		credentialDir, err := filepath.Abs(filepath.Join(stateDir, "credentials"))
		if err != nil {
			return fmt.Errorf("resolve credential directory: %w", err)
		}
		principalDir := filepath.Join(stateDir, "hosts")
		configs := ssh.Configurations{
			Dir:      principalDir,
			Template: ssh.Runner{Timeout: sshTimeout, ControlNamespace: stateDir},
		}
		return runServe(ctx, services{
			Configs: configs, SessionStore: session.Store{Dir: stateDir}, LinkspanPath: *linkspan,
			TunnelManager: tunnelManager, CapabilityDir: credentialDir, TunnelTimeout: sshTimeout,
		}, args[1:], net.Listen)
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
