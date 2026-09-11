# Changelog

Notable changes to CyberShuttle Control. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `PUT /api/v1/ssh/{alias}`: replace a managed host with what a pasted `ssh` command now says, so a login whose
  host, port, user or jump changed is corrected in place instead of being removed and re-added.
- `startedAt` on the runtime record: when Slurm was first seen running the allocation, absent until it starts.
  With `resources.wallMinutes` it is the deadline a client counts down to.
- `GET /api/v1/runtimes/{id}/metrics`: the last twenty CPU, memory and GPU samples, read from Linkspan over the
  control port of the allocation's own tunnel every five seconds.
- `GET /api/v1/runtimes/history`: what this caller's finished allocations did. A run is frozen when the
  allocation ends, named by the generation that ran it, and outlives both the relaunch and the delete of the
  card it belonged to. Slurm's accounting — peak RSS, CPU and memory efficiency — is filled in as it flushes.

### Changed

- **SSH hosts are per caller.** Each principal now has a private host configuration under
  `<state>/hosts/<principal>/config`, and `ssh` is invoked with `-F` naming it, so an alias resolves through
  the configuration of whoever added it. The account `csctl` runs as no longer has standing in the API: its
  `~/.ssh/config` is neither read nor written. The control master is keyed by configuration as well as alias,
  so one caller authenticating a host cannot hand another an authenticated session, and reconciliation, log
  tailing and accounting run as each runtime's own owner.

  **Breaking.** Hosts previously visible from the daemon account's `~/.ssh/config` are no longer listed;
  re-add the ones you want by pasting their `ssh` command. An `IdentityFile` may still name any path the
  daemon account can read — isolation is of configuration and connections, not of the filesystem.

### Changed

- A run record now carries the runtime's narration, and the live tail is dropped when the run is frozen. A
  runtime that is no longer running therefore has no log tail in `GET /api/v1/runtimes`: what an allocation
  said belongs to the run that said it, and a card outlives its runs.

### Fixed

- A run was stamped as ending when it was recorded, not when it ended. A card that stopped days ago and was
  then run again or deleted had its previous run frozen with `endedAt` set to that moment, so a long-finished
  run read as one that had just stopped — and, beside a card that was running again, as the live session
  itself. The terminal transition's own time is used instead.

- The wall-time anchor was reset to the poll on every observation of a running job: `squeue` is asked for four
  fields and reports no elapsed time, but its row wins over the accounting row that does. A countdown built on
  `startedAt` would have restarted from the full walltime on every round.

## [0.1.0] - 2026-09-07

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
- An Apache-2.0 `LICENSE`, contribution and security policies, and reference documentation for the routes
  (`docs/API.md`) and for the package layering, allocation lifecycle and trust boundaries
  (`docs/ARCHITECTURE.md`).

### Changed

- Runtime state is one scheduler-derived vocabulary: `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`,
  `STOPPED`, `FAILED`.
- The polled `GET /api/v1/runtimes` carries a strong `ETag` over the owner-filtered body, and answers a poll
  whose `If-None-Match` still matches with `304 Not Modified`.
- `--oauth-authority` accepts one tenant only: `common`, `consumers` and `organizations` are refused
  everywhere.
- The smallest allocation a request may ask for is 2 cores and 4096 MB.
- `POST /api/v1/runtimes` requires an `idempotencyKey`, which the runtime ID is derived from; a request without
  one is refused rather than given a generated ID.

### Removed

- `POST /api/v1/runtimes/script`, whose candidate script `POST /api/v1/runtimes/validate` already returns.
- `refreshing` from the `GET /api/v1/runtimes` body; the read still starts the reconciliation it reported.
- The `--state-dir`, `--ssh-bin`, `--timeout`, `--runtime-base`, `--user-ssh-config` and `--system-ssh-config`
  global flags, and the `CSCTL_SSH_BIN`, `CSCTL_RUNTIME_BASE`, `CSCTL_USER_SSH_CONFIG` and
  `CSCTL_SYSTEM_SSH_CONFIG` environment variables that set them. `--linkspan` and `--devtunnel-management-url`
  are the global flags that remain, and each SSH command times out after a fixed 20 seconds.

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
- A failure the API did not classify answers `500 internal_error` with a fixed message: the underlying text is
  logged by the server rather than returned to the caller.

[Unreleased]: https://github.com/cyber-shuttle/cs-control/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cyber-shuttle/cs-control/releases/tag/v0.1.0
