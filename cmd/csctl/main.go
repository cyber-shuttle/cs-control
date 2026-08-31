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
	"syscall"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/control"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/gateway"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

const (
	defaultDevTunnelManagementURL = "https://global.rel.tunnels.api.visualstudio.com"
	csctlVersion                  = "0.1.0"
	sshTimeout                    = 20 * time.Second
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "csctl:", err)
		os.Exit(1)
	}
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
		Runner: sshexec.Runner{Timeout: sshTimeout, ControlDir: filepath.Join(stateDir, "ssh"),
			Hosts: sshconfig.Config{UserPath: defaultUserSSHConfig(), SystemPath: "/etc/ssh/ssh_config"}},
		Store:  control.Store{Dir: stateDir},
		Config: control.Config{LinkspanPath: *linkspan},
		Logs:   control.NewRuntimeLogs(), Tunnels: tunnelManager,
		Credentials: control.CredentialStore{Dir: credentialDir},
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
		fmt.Println(csctlVersion)
		return nil
	default:
		return usageError()
	}
}

const (
	serveReadHeaderTimeout = 10 * time.Second
	serveShutdownTimeout   = 25 * time.Second
)

type serveComponents struct {
	handler http.Handler
	closers []func()
}

// listen is a parameter so a test can prove the configuration is rejected
// before anything binds a port.
func runServe(ctx context.Context, service control.Service, args []string, listen func(string, string) (net.Listener, error)) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listenAddress := flags.String("listen", "127.0.0.1:8045", "loopback listen address")
	oauthAuthority := flags.String("oauth-authority", "", "tenant-specific Microsoft Entra authority used for device authorization and OIDC discovery")
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
	if strings.TrimSpace(*oauthAuthority) == "" {
		return errors.New("--oauth-authority is required")
	}
	// The state directory holds every credential this daemon persists, so it is
	// proved private here once rather than re-checked on each file operation.
	if _, err := safeio.EnsurePrivateDir(service.Store.Dir); err != nil {
		return err
	}
	if err := safeio.PrivateDir(service.Store.Dir); err != nil {
		return err
	}
	components, err := newServeComponents(service, allowedOrigins, *oauthAuthority)
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

func newServeComponents(service control.Service, allowedOrigins []string, oauthAuthority string) (*serveComponents, error) {
	validator, err := authn.NewMicrosoftOAuthValidator(defaultDevTunnelManagementURL, oauthAuthority, authn.DevTunnelsNativeClientID, nil)
	if err != nil {
		return nil, err
	}
	auth := gateway.NewSSHAuthManager(service.Runner)
	api := control.NewHTTPHandler(service, auth)
	// One closer stack, unwound on any construction failure and again on shutdown.
	components := &serveComponents{closers: []func(){auth.Close, api.Close}}
	oauthHandler, err := authn.NewOAuthBoundary(api, validator, allowedOrigins)
	if err != nil {
		components.close()
		return nil, err
	}
	broker, err := authn.NewDeviceCodeBroker(oauthAuthority, allowedOrigins, nil)
	if err != nil {
		components.close()
		return nil, err
	}
	components.closers = append([]func(){broker.Close}, components.closers...)
	handler, err := authn.NewDeviceCodeRoutes(oauthHandler, broker)
	if err != nil {
		components.close()
		return nil, err
	}
	components.handler = handler
	return components, nil
}

func (components *serveComponents) close() {
	if components == nil {
		return
	}
	for _, closer := range components.closers {
		closer()
	}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cs-control"
	}
	return filepath.Join(home, ".cybershuttle", "control")
}

func defaultUserSSHConfig() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh/config"
	}
	return filepath.Join(home, ".ssh", "config")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func usageError() error {
	printUsage()
	return errors.New("invalid command")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  csctl [global options] serve --oauth-authority AUTHORITY --allowed-origin ORIGIN [--allowed-origin ORIGIN ...]
  csctl help
  csctl version

Trusted runtime configuration:
  --linkspan PATH or CSCTL_LINKSPAN=PATH
  --devtunnel-management-url URL or CSCTL_DEVTUNNEL_MANAGEMENT_URL=URL
  Linkspan defaults to `+control.DefaultLinkspanPath+`, which each host resolves
  against its own home and which creating a runtime installs when missing.`)
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}
