# CyberShuttle Control

[![CI](https://github.com/cyber-shuttle/cs-control/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-shuttle/cs-control/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/cyber-shuttle/cs-control)](go.mod)
[![License](https://img.shields.io/github/license/cyber-shuttle/cs-control?color=blue)](LICENSE)

CyberShuttle is the ARTISAN group's toolset for running interactive work — a Jupyter server today — on the
compute nodes of an HPC (high-performance computing) cluster, reachable from a browser or editor on your own
machine. `csctl` is the local daemon that does that work: it submits the [Slurm](https://slurm.schedmd.com/)
job, prepares the login node, and creates a tunnel the compute node hosts outbound, so a session is reachable
without the cluster opening an inbound port.

A session is the record a client creates and polls; a Slurm job serves it, and one session can outlive
several. Everything happens as you: your own SSH host configuration, your SSH credentials, your Slurm
account. `csctl` binds to loopback only and never proxies session traffic — once a session is running,
the browser reaches it directly over the tunnel.

## Status

Pre-release. There are no published binaries; `csctl version` prints the build's hardcoded version constant.
The `/api/v1` surface is not yet stable. [CHANGELOG.md](CHANGELOG.md) records what has changed on `main`.

## Requirements

- **macOS or Linux**, with an OpenSSH client on `PATH`. CI covers Linux only.
- **Go 1.24 or newer.** Building from source is the only install path.
- **A Microsoft Entra tenant.** `--oauth-authority` accepts only `https://login.microsoftonline.com/<tenant>/`
  with no port; the multi-tenant aliases `common`, `consumers` and `organizations` are rejected.
- **A Microsoft or GitHub account entitled to
  [Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview).** Sign-in uses the
  Dev Tunnels first-party clients, through the tenant above or through GitHub, and each session creates a
  tunnel against that account.
- **An SSH-reachable Linux Slurm cluster** whose login node provides `sacctmgr`, `sinfo`, `sbatch`, `squeue`,
  `sacct`, `scancel`, `curl`, `tar`, `base64`, `od`, `install`, `printenv`, `sed` and `sort -V`, and whose
  nodes run Linux `x86_64` or `arm64` with `curl`.
- **[Linkspan](https://github.com/cyber-shuttle/linkspan) 0.19.0 or newer**, the release whose workflow
  document is `tasks`; `csctl` installs the latest release on a host that has none.
- **Outbound internet.** From the login node to `github.com`; from the compute node to `astral.sh`,
  `github.com` and `pypi.org`, which Linkspan installs `uv`, its Python and packages from, and to
  `tunnelsassetsprod.blob.core.windows.net`, which Linkspan fetches Microsoft's `devtunnel` CLI from, and to
  `*.rel.tunnels.api.visualstudio.com` and `*.devtunnels.ms`, which it hosts the tunnel through; and from
  your own machine to `login.microsoftonline.com`, `*.rel.tunnels.api.visualstudio.com` and
  `*.devtunnels.ms`. See
  [what it runs on the cluster](#what-it-runs-on-the-cluster).

## Install

```bash
go install github.com/cyber-shuttle/cs-control/cmd/csctl@latest
```

`@latest` resolves to the newest tagged release. From a clone:

```bash
git clone https://github.com/cyber-shuttle/cs-control.git
cd cs-control
go build ./cmd/csctl
```

## Quick start

```bash
csctl serve \
  --listen 127.0.0.1:8045 \
  --oauth-authority https://login.microsoftonline.com/<tenant>/ \
  --allowed-origin https://workspace.example.edu
```

`--oauth-authority` is required. `--allowed-origin` is repeatable and at least one is required; HTTPS origins
and loopback HTTP origins are accepted, wildcards are not. `--listen` defaults to `127.0.0.1:8045` and must be
an explicit loopback address.

There are no CLI commands for hosts or sessions — a client drives the daemon over the API. Confirm it is
listening and that the authentication boundary is in front of it:

```console
$ curl -si http://127.0.0.1:8045/api/v1/sessions | head -1
HTTP/1.1 401 Unauthorized
```

`csctl help` prints the commands and the global flags; `csctl serve -h` prints the serve flags.

## Configuration

| Flag | Environment | Default |
| --- | --- | --- |
| `serve --listen` | — | `127.0.0.1:8045` |
| `serve --oauth-authority` | — | required |
| `serve --allowed-origin` (repeatable) | — | required |
| `--linkspan` | `CSCTL_LINKSPAN` | `$HOME/.cybershuttle/bin/linkspan` |
| `--devtunnel-management-url` | `CSCTL_DEVTUNNEL_MANAGEMENT_URL` | `https://global.rel.tunnels.api.visualstudio.com` |

Global flags precede the command. `--linkspan` is a remote path, absolute or anchored at `$HOME/`, resolved per
host. Set `--devtunnel-management-url` to a regional `*.rel.tunnels.api.visualstudio.com` endpoint when the
global cluster's tunnel quota is exhausted; it changes tunnel management only.

## What it runs on the cluster

Creating a session prepares the login node over SSH before it submits anything. In one connection, as your
account, it:

- downloads a [Linkspan](https://github.com/cyber-shuttle/linkspan) release tarball from GitHub into
  `$HOME/.cybershuttle/bin`, unless the installed one is current, and refuses the host if that Linkspan is
  older than 0.19.0;
- writes the workflow document the job will run, under `$HOME/.cybershuttle/sessions/<session id>`.

Linkspan is the CyberShuttle agent that runs as the batch job's main process: it hosts the tunnel, installs
`uv`, builds the Python environment under `$HOME/.cybershuttle` and starts Jupyter Server on the compute node.
Nothing runs as root and nothing is installed outside `$HOME/.cybershuttle`. `csctl` keeps a multiplexed OpenSSH connection to the
login node open between operations and starts no other long-lived process there; the session itself runs on
a compute node. The batch script redirects the job's stdout and stderr to
`$HOME/.cybershuttle/logs/<session id>-<seq>.out` and `.err`; nothing prunes them. The flags and outputs
`csctl` depends on are listed in
[Linkspan's compatibility document](https://github.com/cyber-shuttle/linkspan/blob/main/docs/COMPATIBILITY.md).

## Local state

`~/.cybershuttle/control`, created and verified at mode `0700`:

- `state.json` — non-secret scheduler, session and tunnel metadata
- `credentials/` — the per-seq Dev Tunnel connect token and Jupyter token, mode `0600`
- `hosts/<principal>/config` — each caller's own managed SSH host entries, mode `0600`
- `hosts/<principal>/keys/<name>` — login keys the caller uploaded, mode `0600`

Each caller's SSH host entries live in their own `hosts/<principal>/config` inside a managed block; the API
never reads or writes `~/.ssh/config` for the account `csctl` runs as.

## Documentation

- [docs/API.md](docs/API.md) — the loopback HTTP and WebSocket API a client drives
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layering, session lifecycle, trust boundaries

## Related projects

- **[cs-jupyter](https://github.com/cyber-shuttle/cs-jupyter)** — the browser client that drives this API: it
  signs in, creates and polls sessions, and connects to a `READY` one.
- **[linkspan](https://github.com/cyber-shuttle/linkspan)** — the compute-node agent `csctl` installs and
  submits as the job's main process.

## Getting help

Bug reports and feature requests go to [GitHub Issues](https://github.com/cyber-shuttle/cs-control/issues).
Report a vulnerability privately instead — see [SECURITY.md](SECURITY.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup, the commands CI runs, and the pull-request
workflow. Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
