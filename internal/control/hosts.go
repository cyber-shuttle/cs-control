// The SSH host CRUD and connectivity test routes, each a thin caller-scoped call into sshconfig.
// A pasted ssh command is parsed server-side, never composed by the browser.
// An alias is always the caller's own, so two principals may reuse the same name for different hosts.
//
//	addHostRequest
//	hostTest
//	Service
//	addHost
//	updateHostRequest
//	updateHost
//	removeHost
//	testHost
package control

import (
	"context"
	"errors"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

type addHostRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type hostTest struct {
	Host    string `json:"host"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (s Service) addHost(request addHostRequest) (sshconfig.Host, error) {
	host, err := sshconfig.ParseCommand(strings.TrimSpace(request.Name), request.Command)
	if err != nil {
		return sshconfig.Host{}, err
	}
	if err := s.sshConfig().Add(host); err != nil {
		return sshconfig.Host{}, err
	}
	host.Managed = true
	return host, nil
}

type updateHostRequest struct {
	Command string `json:"command"`
}

func (s Service) updateHost(alias string, request updateHostRequest) (sshconfig.Host, error) {
	host, err := sshconfig.ParseCommand(alias, request.Command)
	if err != nil {
		return sshconfig.Host{}, err
	}
	if err := s.sshConfig().Update(host); err != nil {
		return sshconfig.Host{}, err
	}
	host.Managed = true
	return host, nil
}

func (s Service) removeHost(alias string) (sshconfig.Host, error) {
	if err := s.sshConfig().Remove(alias); err != nil {
		return sshconfig.Host{}, err
	}
	return sshconfig.Host{Name: alias, ExtraDirectives: []string{}}, nil
}

func (s Service) testHost(ctx context.Context, alias string) (hostTest, error) {
	if !sshconfig.ValidAlias(alias) {
		return hostTest{}, sshconfig.ErrInvalidAlias
	}
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	if _, err := s.Runner.Run(ctx, alias, nil, "true"); err != nil {
		var classified *apierr.APIError
		if errors.As(err, &classified) && classified.Code == "ssh_authentication_required" {
			return hostTest{Host: alias, Message: "The host answered but wants an interactive login. Authenticate it first."}, nil
		}
		if ctx.Err() != nil {
			return hostTest{Host: alias, Message: "The host did not answer in time."}, nil
		}
		return hostTest{Host: alias, Message: strings.TrimSpace(err.Error())}, nil
	}
	return hostTest{Host: alias, OK: true, Message: "Connected."}, nil
}
