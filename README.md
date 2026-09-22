# CyberShuttle Plane

[![CI](https://github.com/cyber-shuttle/cs-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-shuttle/cs-plane/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/cyber-shuttle/cs-plane)](go.mod)
[![License](https://img.shields.io/github/license/cyber-shuttle/cs-plane?color=blue)](LICENSE)

CyberShuttle is the ARTISAN group's toolset for running interactive work — a Jupyter server today — on the
compute nodes of an HPC (high-performance computing) cluster, reachable from a browser or editor on your own
machine. cs-plane is the local daemon that does that work: it submits the [Slurm](https://slurm.schedmd.com/)
job, prepares the login node, and creates a tunnel the compute node hosts outbound, so a session is reachable
without the cluster opening an inbound port.

A session is the record a client creates and polls; a Slurm job serves it, and one session can outlive
several. Everything happens as you: your own SSH host configuration, your SSH credentials, your Slurm
account. cs-plane binds to loopback only and never proxies session traffic — once a session is running,
the browser reaches it directly over the tunnel.

## Status

Pre-release. There are no published binaries; `cs version` prints the build's hardcoded version constant.
The `/api/v1` surface is not yet stable. [CHANGELOG.md](CHANGELOG.md) records what has changed on `main`.

## Requirements

- **macOS or Linux**, with an OpenSSH client on `PATH`. CI covers Linux only.
- **Go 1.26 or newer.** Building from source is the only install path.
- **A [CILogon](https://www.cilogon.org/) client, or another OIDC issuer configured the same way.** The
  client must have PKCE and the device flow enabled: cs-plane finishes a browser's PKCE flow and an editor's
  device-code flow. `--oidc-issuer` defaults to `https://cilogon.org`; the client ID
  goes on `--oidc-client-id` and the client secret in `CS_OIDC_CLIENT_SECRET`, since only the daemon holds
  it.
- **A Postgres server** with a schema cs-plane owns. `CS_DATABASE_URL` names it through `search_path`, for
  example `postgres:///cybershuttle?host=/var/run/postgresql&search_path=cs_plane`; cs-plane creates its tables in that
  schema while it is empty, and refuses one it did not create.
- **A [Custos](https://custos.cyberinfrastructure.org/) instance** the resolved identity is checked against:
  `--custos-url` names it, and the daemon calls `GET {custos-url}/me` with the caller's bearer to resolve the
  principal.
- **A Microsoft or GitHub account entitled to
  [Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview),** linked once through
  `POST /api/v1/tunnel/authorizations` and kept sealed under the caller's principal. Sessions run over that account;
  a caller with no link is refused at session creation.
- **An SSH-reachable Linux Slurm cluster** whose login node provides `sacctmgr`, `sinfo`, `sbatch`, `squeue`,
  `sacct`, `scancel`, `curl`, `tar`, `base64`, `od`, `install`, `printenv`, `sed` and `sort -V`, and whose
  nodes run Linux `x86_64` or `arm64` with `curl`.
- **[Linkspan](https://github.com/cyber-shuttle/linkspan) 0.19.0 or newer**, the release whose workflow
  document is `tasks`; cs-plane installs the latest release on a host that has none.
- **Outbound internet.** From the login node to `github.com`; from the compute node to `astral.sh`,
  `github.com` and `pypi.org`, which Linkspan installs `uv`, its Python and packages from, and to
  `tunnelsassetsprod.blob.core.windows.net`, which Linkspan fetches Microsoft's `devtunnel` CLI from, and to
  `*.rel.tunnels.api.visualstudio.com` and `*.devtunnels.ms`, which it hosts the tunnel through; and from
  your own machine to the configured OIDC issuer, the configured Custos URL, `*.rel.tunnels.api.visualstudio.com`
  and `*.devtunnels.ms`, plus `login.microsoftonline.com` or `github.com` while linking Dev Tunnels. See
  [what it runs on the cluster](#what-it-runs-on-the-cluster).

## Install

```bash
git clone https://github.com/cyber-shuttle/cs-plane.git
cd cs-plane
go build -o cs .
```

## Quick start

```bash
export CS_OIDC_CLIENT_SECRET=...
cs serve \
  --listen 127.0.0.1:8045 \
  --oidc-client-id cilogon:/client_id/<id> \
  --custos-url https://custos.cybershuttle.org \
  --allowed-origin https://workspace.example.edu
```

`--oidc-client-id`, `--custos-url` and `CS_OIDC_CLIENT_SECRET` are required; `--oidc-issuer` defaults to
`https://cilogon.org`. Both service URLs must use HTTPS, and the discovered issuer must match exactly.
`--allowed-origin` is repeatable and at least one is required; HTTPS origins and loopback HTTP origins are
accepted, wildcards are not. `--listen` defaults to `127.0.0.1:8045` and must be an explicit loopback address.

There are no CLI commands for keys, hosts, or sessions — a client drives the daemon over the API. Its routes are
under `/api/v1/oauth`, `/api/v1/ssh`, `/api/v1/tunnel`, `/api/v1/sessions`, and `/api/v1/telemetry`; see the
[API reference](docs/API.md). Confirm it is listening and that authentication is in front:

```console
$ curl -si http://127.0.0.1:8045/api/v1/sessions | head -1
HTTP/1.1 401 Unauthorized
```

`cs help` prints the commands and the global flags; `cs serve -h` prints the serve flags.

## Configuration

| Flag | Environment | Default |
| --- | --- | --- |
| `serve --listen` | — | `127.0.0.1:8045` |
| `serve --oidc-issuer` | — | `https://cilogon.org` |
| `serve --oidc-client-id` | — | required |
| `serve --custos-url` | — | required |
| — | `CS_OIDC_CLIENT_SECRET` | required |
| `serve --allowed-origin` (repeatable) | — | required |
| `--linkspan` | `CS_LINKSPAN` | `$HOME/.cybershuttle/bin/linkspan` |
| `--devtunnel-management-url` | `CS_DEVTUNNEL_MANAGEMENT_URL` | `https://global.rel.tunnels.api.visualstudio.com` |

Global flags precede the command. `--linkspan` is a remote path, absolute or anchored at `$HOME/`, resolved per
host. Set `--devtunnel-management-url` to a regional `*.rel.tunnels.api.visualstudio.com` endpoint when the
global cluster's tunnel quota is exhausted; it changes tunnel management only. Management redirects retain
authorization only between recognized HTTPS management hosts.

## What it runs on the cluster

Creating a session prepares the login node over SSH before it submits anything. In one connection, as your
account, it:

- downloads a [Linkspan](https://github.com/cyber-shuttle/linkspan) release tarball from GitHub into
  `$HOME/.cybershuttle/bin`, unless the installed one is current, and refuses the host if that Linkspan is
  older than 0.19.0;
- writes the workflow document the job will run, under `$HOME/.cybershuttle/sessions/<session id>`.

Linkspan is the CyberShuttle agent that runs as the batch job's main process: it hosts the tunnel, installs
`uv`, builds the Python environment under `$HOME/.cybershuttle` and starts Jupyter Server on the compute node.
Nothing runs as root and nothing is installed outside `$HOME/.cybershuttle`. cs-plane keeps a multiplexed OpenSSH connection to the
login node open between operations and starts no other long-lived process there; the session itself runs on
a compute node. The batch script redirects the job's stdout and stderr to
`$HOME/.cybershuttle/logs/<session id>-<seq>.out` and `.err`; nothing prunes them. The flags and outputs
cs-plane depends on are listed in
[Linkspan's compatibility document](https://github.com/cyber-shuttle/linkspan/blob/main/docs/COMPATIBILITY.md).

## Local state

`~/.cybershuttle/control`, created and verified at mode `0700`:

- `credentials/` — per-seq Dev Tunnel and Jupyter capabilities, mode `0600`
- `hosts/<principal>/config` — each caller's own SSH host entries, rendered from the database, mode `0600`
- `hosts/<principal>/keys/<name>` — login keys the caller uploaded, mode `0600`
- `hosts/<principal>/tunnel-link` — the caller's linked Dev Tunnels credential, sealed, mode `0600`
- `tunnel-link.key` — the 32-byte key sealing every `tunnel-link` file, created at mode `0600` on first boot

Scheduler, session, tunnel, SSH host and login key metadata live in the Postgres schema. Each caller's SSH host
entries are rendered to that caller's `hosts/<principal>/config`
for `ssh -F`; startup regenerates these files from committed rows and resolves interrupted key writes and deletions.
The API never reads or writes `~/.ssh/config` for the account cs-plane runs as. A schema holding tables without
cs-plane's format marker is refused before anything else is touched.

## Documentation

- [docs/API.md](docs/API.md) — the loopback HTTP and WebSocket API a client drives
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layering, session lifecycle, trust boundaries

## Related projects

- **[cs-jupyter](https://github.com/cyber-shuttle/cs-jupyter)** — the browser client that drives this API: it
  signs in, creates and polls sessions, and connects to a `READY` one.
- **[linkspan](https://github.com/cyber-shuttle/linkspan)** — the compute-node agent cs-plane installs and
  submits as the job's main process.

## Getting help

Bug reports and feature requests go to [GitHub Issues](https://github.com/cyber-shuttle/cs-plane/issues).
Report a vulnerability privately instead — see [SECURITY.md](SECURITY.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup, the commands CI runs, and the pull-request
workflow. Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
