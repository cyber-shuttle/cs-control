# CyberShuttle Control

[![CI](https://github.com/cyber-shuttle/cs-control/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-shuttle/cs-control/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/cyber-shuttle/cs-control)](go.mod)
[![License](https://img.shields.io/github/license/cyber-shuttle/cs-control?color=blue)](LICENSE)

CyberShuttle is the ARTISAN group's toolset for running interactive work — a Jupyter server today — on the
compute nodes of an HPC (high-performance computing) cluster, reachable from a browser or editor on your own
machine. `csctl` is the local daemon that does that work: it submits the [Slurm](https://slurm.schedmd.com/)
job, prepares the login node, and creates a tunnel the compute node hosts outbound, so a session is reachable
without the cluster opening an inbound port.

A runtime is the record a client creates and polls; the allocation is the Slurm job that serves it, and one
runtime can outlive several. Everything happens as you: your `~/.ssh/config`, your SSH credentials, your Slurm
allocation. `csctl` binds to loopback only and never proxies session traffic — once an allocation is running,
the browser reaches it directly over the tunnel.

## Status

Pre-release. There are no tagged versions and no published binaries; `csctl version` prints a constant string
that corresponds to no release. The `/api/v1` surface is not yet stable. [CHANGELOG.md](CHANGELOG.md) records
what has changed on `main`.

## Requirements

- **macOS or Linux**, with an OpenSSH client on `PATH`. CI covers Linux only.
- **Go 1.23 or newer.** Building from source is the only install path.
- **A Microsoft Entra tenant.** `--oauth-authority` accepts only `https://login.microsoftonline.com/<tenant>/`
  with no port; the multi-tenant aliases `common`, `consumers` and `organizations` are rejected.
- **A Microsoft account entitled to
  [Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview).** Sign-in uses the
  Dev Tunnels first-party client, and each allocation creates a tunnel against that account.
- **An SSH-reachable Linux Slurm cluster** whose login node provides `sacctmgr`, `sinfo`, `sbatch`, `squeue`,
  `sacct`, `scancel`, `curl` and `tar`, and whose nodes run Linux `x86_64` or `arm64`.
- **[Linkspan](https://github.com/cyber-shuttle/linkspan) 0.16.0 or newer**, the release that added
  `--tunnel-host-token`; `csctl` installs the latest release on a host that has none.
- **Outbound internet.** From the login node to `astral.sh` and `github.com`; from the compute node to
  `tunnelsassetsprod.blob.core.windows.net`, which Linkspan fetches Microsoft's `devtunnel` CLI from before it
  hosts the tunnel; and from your own machine to `login.microsoftonline.com`,
  `*.rel.tunnels.api.visualstudio.com` and `*.devtunnels.ms`. See
  [what it runs on the cluster](#what-it-runs-on-the-cluster).

## Install

```bash
go install github.com/cyber-shuttle/cs-control/cmd/csctl@latest
```

There are no tags, so `@latest` resolves to the current `main` commit. From a clone:

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

There are no CLI commands for hosts or runtimes — a client drives the daemon over the API. Confirm it is
listening and that the authentication boundary is in front of it:

```console
$ curl -si http://127.0.0.1:8045/api/v1/runtimes | head -1
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

Creating a runtime prepares the login node over SSH before it submits anything. In one connection, as your
account, it:

- installs [uv](https://docs.astral.sh/uv/) into `$HOME/.local/bin` by piping `https://astral.sh/uv/install.sh`
  into `sh`, unless a `uv` is already present;
- downloads a [Linkspan](https://github.com/cyber-shuttle/linkspan) release tarball from GitHub into
  `$HOME/.cybershuttle/bin`, unless the installed one is current, and refuses the host if that Linkspan does
  not accept `--tunnel-host-token`;
- writes the workflow document the job will run, under `$HOME/.cybershuttle/runtimes/<runtime id>`.

Linkspan is the CyberShuttle agent that runs as the batch job's main process: it hosts the tunnel, builds the
Python environment and starts Jupyter Server on the compute node. Nothing runs as root and nothing is installed
outside `$HOME/.cybershuttle` and `$HOME/.local/bin`. `csctl` keeps a multiplexed OpenSSH connection to the
login node open between operations and starts no other long-lived process there; the allocation itself runs on
a compute node. The flags and outputs `csctl` depends on are listed in
[Linkspan's compatibility document](https://github.com/cyber-shuttle/linkspan/blob/main/docs/COMPATIBILITY.md).

## Local state

`~/.cybershuttle/control`, created and verified at mode `0700`:

- `state.json` — non-secret scheduler, allocation and tunnel metadata
- `credentials/` — the per-allocation Dev Tunnel connect token and Jupyter token, mode `0600`
- `ssh/` — OpenSSH `ControlMaster` sockets

The API adds SSH host entries to `~/.ssh/config` inside its own managed block, and reads but never rewrites
anything outside it.

## Documentation

- [docs/API.md](docs/API.md) — the loopback HTTP and WebSocket API a client drives
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layering, allocation lifecycle, trust boundaries

## Related projects

- **[cs-jupyter](https://github.com/cyber-shuttle/cs-jupyter)** — the browser client that drives this API: it
  signs in, creates and polls runtimes, and connects to a `READY` one.
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
