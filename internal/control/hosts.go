package control

import (
	"context"
	"errors"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

// AddHostRequest carries the ssh command a user already knows works. The server
// parses it, so the browser never composes configuration text.
type AddHostRequest struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// HostTest is the outcome of one bounded connection attempt. A host that only
// wants an interactive login is a reportable state, not a failure of the call.
type HostTest struct {
	Host    string `json:"host"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (s Service) AddHost(request AddHostRequest) (sshconfig.Host, error) {
	host, err := sshconfig.ParseCommand(strings.TrimSpace(request.Name), request.Command)
	if err != nil {
		return sshconfig.Host{}, err
	}
	if err := s.SSHConfig().Add(host); err != nil {
		return sshconfig.Host{}, err
	}
	host.Managed = true
	return host, nil
}

// UpdateHostRequest carries the ssh command that should now describe an alias.
// The alias comes from the route, so an edit cannot rename what it edits.
type UpdateHostRequest struct {
	Command string `json:"command"`
}

// UpdateHost re-parses a pasted command over an entry this API wrote, so a
// login that changed is corrected in place rather than removed and re-added.
func (s Service) UpdateHost(alias string, request UpdateHostRequest) (sshconfig.Host, error) {
	host, err := sshconfig.ParseCommand(alias, request.Command)
	if err != nil {
		return sshconfig.Host{}, err
	}
	if err := s.SSHConfig().Update(host); err != nil {
		return sshconfig.Host{}, err
	}
	host.Managed = true
	return host, nil
}

func (s Service) RemoveHost(alias string) (sshconfig.Host, error) {
	if err := s.SSHConfig().Remove(alias); err != nil {
		return sshconfig.Host{}, err
	}
	return sshconfig.Host{Name: alias}, nil
}

// TestHost runs the cheapest remote command there is. Its value is the same
// ControlMaster every later operation reuses, so a passing test is a warm one.
func (s Service) TestHost(ctx context.Context, alias string) (HostTest, error) {
	if !sshconfig.ValidAlias(alias) {
		return HostTest{}, sshconfig.ErrInvalidAlias
	}
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	if _, err := s.Runner.Run(ctx, alias, nil, "true"); err != nil {
		var classified *apierr.APIError
		if errors.As(err, &classified) && classified.Code == "ssh_authentication_required" {
			return HostTest{Host: alias, Message: "The host answered but wants an interactive login. Add a runtime on it to sign in."}, nil
		}
		if ctx.Err() != nil {
			return HostTest{Host: alias, Message: "The host did not answer in time."}, nil
		}
		return HostTest{Host: alias, Message: strings.TrimSpace(err.Error())}, nil
	}
	return HostTest{Host: alias, OK: true, Message: "Connected."}, nil
}
