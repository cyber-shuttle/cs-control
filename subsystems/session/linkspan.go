// Linkspan's launch contract, owned here so the rest of preparation never spells its CLI: the release floor,
// the tunnel modes a session may select, the flags a session job execs Linkspan with for them, and the sbatch
// exports those flags read. The flags reference exported variables rather than values so the script text stays
// free of secrets and per-run identity; the link and Dev Tunnel host tokens reach Linkspan only through its own
// environment names, and each is exported only when its mode is selected.
package session

import (
	"slices"
	"strings"
)

const linkspanFloor = "0.21.0"

const (
	modeDevtunnel = "devtunnel"
	modeWebsocket = "websocket"
)

var linkspanModeArgs = map[string]string{
	modeDevtunnel: `--tunnel-devtunnel-args "--id $CS_TUNNEL_ID --cluster $CS_TUNNEL_CLUSTER"`,
	modeWebsocket: `--tunnel-websocket-args "--url $CS_LINK_URL"`,
}

func linkspanTunnelArgs(modes []string) string {
	args := "--tunnel-enable --tunnel-mode " + strings.Join(modes, ",")
	for _, mode := range modes {
		args += " " + linkspanModeArgs[mode]
	}
	return args
}

func linkspanEnvironment(modes []string, linkURL, linkToken string, tunnel tunnelMetadata, hostToken string) map[string]string {
	environment := map[string]string{}
	if slices.Contains(modes, modeWebsocket) {
		environment["CS_LINK_URL"], environment["LINKSPAN_LINK_TOKEN"] = linkURL, linkToken
	}
	if slices.Contains(modes, modeDevtunnel) {
		environment["CS_TUNNEL_ID"], environment["CS_TUNNEL_CLUSTER"], environment["LINKSPAN_TUNNEL_HOST_TOKEN"] = tunnel.ID, tunnel.ClusterID, hostToken
	}
	return environment
}
