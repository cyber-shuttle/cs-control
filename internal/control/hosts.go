package control

import (
	"context"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
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
		message := strings.TrimSpace(err.Error())
		if sshexec.AuthenticationFailure(message) {
			return HostTest{Host: alias, Message: "The host answered but wants an interactive login. Add a runtime on it to sign in."}, nil
		}
		if ctx.Err() != nil {
			return HostTest{Host: alias, Message: "The host did not answer in time."}, nil
		}
		return HostTest{Host: alias, Message: message}, nil
	}
	return HostTest{Host: alias, OK: true, Message: "Connected."}, nil
}
