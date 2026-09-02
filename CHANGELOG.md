# Changelog

Notable changes to CyberShuttle Control. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

No version has been released: the repository has no tags and no published binaries, and `csctl version` prints
a constant `0.1.0` that names no release. Everything below has landed on `main`, which is what building from
source gives you.

## [Unreleased]

### Added

- `csctl serve`: a loopback-only JSON HTTP and WebSocket API, `127.0.0.1:8045` by default, requiring a
  single-tenant Microsoft Entra `--oauth-authority` and at least one exact `--allowed-origin`.
- Brokered Microsoft device-code sign-in; every other route requires a Dev Tunnels access token and a Microsoft
  ID token, and answers only for the calling principal.
- SSH host routes: add a host from an `ssh` command line that already works, test it, remove the entries this
  API wrote, and discover the cluster's Slurm accounts, partitions and home directory; abandoning a discovery
  terminates the remote process group.
- Interactive SSH authentication over a WebSocket, which establishes the multiplexed control master every later
  operation reuses.
- Runtime routes: validate a request with `sbatch --test-only` against the script create submits, then create,
  list, get, stop and delete; `access` returns the owner's Jupyter URI and token over the allocation's tunnel.
- `POST /api/v1/runtimes/{id}/start`, which runs a terminal runtime again on the same record under a new
  generation, tunnel and job.
- Login-node preparation before submission: uv and a Linkspan release installed under `$HOME`, and the workflow
  document the job runs. A host whose Linkspan cannot host the allocation's tunnel is refused.
- Owner-filtered status narration and allocation output in the runtime list, bounded and redacted.
- Reconciliation that retires a runtime the scheduler has stopped answering for, and ends one that reaches its
  walltime as stopped rather than failed.
- Local state under `~/.cybershuttle/control` at mode `0700`, with per-allocation credentials at `0600`.

### Changed

- Runtime state is one scheduler-derived vocabulary: `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`,
  `STOPPED`, `FAILED`.
- The polled `GET /api/v1/runtimes` carries a strong `ETag` over the owner-filtered body, and answers a poll
  whose `If-None-Match` still matches with `304 Not Modified`.
- `--oauth-authority` accepts one tenant only: `common`, `consumers` and `organizations` are refused
  everywhere.
- The smallest allocation a request may ask for is 2 cores and 4096 MB.

### Removed

- `POST /api/v1/runtimes/script`, whose candidate script `POST /api/v1/runtimes/validate` already returns.

### Fixed

- Running a finished runtime again no longer adopts the previous run's accounting record: the Slurm job name
  carries the runtime's generation.
- A submission that completes against an already-terminal record cancels the job it created instead of leaving
  it running.
- A host that wants an interactive login is reported as a login owed, not as a preparation failure.
- `sacct` is asked for a window relative to the cluster's own clock, so a cluster in another timezone no longer
  rejects every status check.
- Device sign-in accepts a bodyless request however a proxy framed it; a browser previously got `400` where
  `curl` succeeded.
- Interactive SSH prompts and banners render non-ASCII as sent — a login QR code arrived as octal escapes —
  because an `ssh` child that inherits no UTF-8 locale is given one, as an `LC_ALL` that replaces any existing
  entry rather than following it.
