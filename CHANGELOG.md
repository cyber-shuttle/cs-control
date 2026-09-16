# Changelog

Notable changes to CyberShuttle Control. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **Generation is seq.** A session's attempt counter is a plain integer: `seq` replaces the random
  `generation` string (`g-<16 hex>`) everywhere it appeared -- the `seq` field on a session, a run and the
  access response, remote log basenames (`<id>-<seq>`), and the Slurm job name (`cs-<id>-<seq>`). `seq` starts
  at 1 on create and increments by 1 on every `start` under the same session id; the session record owns the
  counter and nothing is randomly generated or pattern-validated anymore.

  **Breaking.** The state file is version 7 and one from before is refused. `docs/API.md` examples and the
  `generation` JSON field are updated to `seq`; a caller reading `generation` must read `seq` instead.
- Preparation requires Linkspan 0.19.0 or newer, the release that reads the `tasks` workflow document, and
  refuses an older one before submitting; the `--tunnel-host-token` probe is gone with it. **Breaking** for a
  host holding an older Linkspan by hand.
- **A runtime is a session.** The record a client creates and polls is named for what the user sees in
  cs-jupyter: routes are `/api/v1/sessions`, `/sessions/validate`, `/sessions/history`, `/sessions/{id}` and
  its `/start`, `/stop`, `/access` and `/metrics`; the list key is `sessions`, the field `sessionId`; ids
  match `s-[a-f0-9]{12}`; error codes are `session_*` and `invalid_session_id`; status lines say `Session`,
  where some said `Allocation`.

  **Breaking.** The state file is version 6 and one from before is refused; a session's private state on a host
  is under `~/.cybershuttle/sessions`. cs-jupyter must match.

- **SSH hosts are per caller.** Each principal now has a private host configuration under
  `<state>/hosts/<principal>/config`, and `ssh` is invoked with `-F` naming it, so an alias resolves through
  the configuration of whoever added it. The account `csctl` runs as no longer has standing in the API: its
  `~/.ssh/config` is neither read nor written. The control master is keyed by configuration as well as alias,
  so one caller authenticating a host cannot hand another an authenticated SSH login, and reconciliation, log
  tailing and accounting run as each session's own owner.

  **Breaking.** Hosts previously visible from the daemon account's `~/.ssh/config` are no longer listed;
  re-add the ones you want by pasting their `ssh` command. An `IdentityFile` may still name any path the
  daemon account can read — isolation is of configuration and connections, not of the filesystem.

- A run record now carries the session's narration, and the live tail is dropped when the run is frozen. A
  session therefore has no log tail in `GET /api/v1/sessions` once its run is frozen: what a job
  said belongs to the run that said it, and a session record outlives its runs.

### Added

- `PUT /api/v1/ssh/{alias}`: replace a managed host with what a pasted `ssh` command now says, so a login whose
  host, port, user or jump changed is corrected in place instead of being removed and re-added.
- `startedAt` on the session record: when Slurm was first seen running the job, absent until it starts.
  With `resources.wallMinutes` it is the deadline a client counts down to.
- `GET /api/v1/sessions/{id}/metrics`: the last twenty CPU, memory and GPU samples, read from Linkspan over the
  control port of the job's own tunnel every five seconds.
- `GET /api/v1/sessions/history`: what this caller's finished sessions did. A run is frozen when the
  job ends, named by the seq that ran it, and outlives both the relaunch and the delete of the
  session record it belonged to. Slurm's accounting — peak RSS, CPU and memory efficiency — is filled in as it flushes.

### Fixed

- The session log tail round parsed its framed output without tolerating a login banner ahead of the first
  marker, unlike the scheduler round; a banner failed the whole read, so `MergeRemote` never ran and a
  `STARTING` session never promoted. The tail round now tolerates a banner the same way. The discovery round
  had the same gap: a banner ahead of the first marker failed the SSH call every create and validate makes.
  All three rounds now share one tolerant framing, and `sections` no longer takes a `preamble` flag to say
  otherwise.
- The remote stdout/stderr log files were named by session id alone, so relaunching a session let its first
  `STARTING` poll read the prior generation's finished log and promote to `READY` before the new job wrote
  anything. Both the batch script's redirect and the tail script's lookup now key the log files by session id
  and generation together, matching how `jobName` already does.
- `cancelUnsavedJob` ran its compensating `scancel` on the request's own context, so a client that
  disconnected between `sbatch` succeeding and the failed state save left the job running with no record:
  the request context was already cancelled by the time compensation needed it. It now runs on its own
  timeout, as `cancelSupersededJob` already did.
- A create or validate that failed before a session record was persisted, including discovery, account or
  partition validation, workspace resolution, `sbatch --test-only` and tunnel creation, kept its log tail and
  metrics window; since a session's id derives from its idempotency key, retrying the same create inherited
  the failed attempt's narration instead of starting with an empty tail.
- A session still `SUBMITTING` when the propagation window elapsed had no job ID yet, so reconciliation
  retired it to `STOPPED` while provisioning was still preparing the host; the submission that followed then
  read as superseded and `scancel`led the job that had just succeeded. Reconciliation now skips a session
  with no job ID for up to the provisioning timeout, since it cannot be missing from a scheduler it was never
  given to; past that timeout, an ambiguous `sbatch` outcome or a daemon restart between persisting the submit
  intent and submitting must not pin a session in `SUBMITTING` forever, so it is retired instead. A `STOPPING`
  session with no scheduler observation is retired the same way: held for the provisioning timeout while it
  still has no job ID, or for the shorter propagation window once it does, rather than pinned there
  indefinitely.
- `createSessionTunnel` ran inside the session store's lock, so one slow Dev Tunnels create stalled every
  list, poll, reconcile and metric tick. The tunnel is now created before the lock is taken, with the record
  re-checked once the lock is held and the tunnel released if it changed underneath.
- A second `POST /sessions/{id}/stop` on an already-stopped session rebuilt its live log tail: `recordRun`
  dedupes by generation, so the run freeze that clears the tail on the first stop never ran again to clear the
  rebuilt one. Both status lines `stop` writes are now skipped once the session is already terminal.
- Alias resolution for the control master ran `ssh -G` without `-F`, so it read the daemon account's own
  SSH configuration instead of the caller's; a retargeted alias could reuse the master to the old host.
- Stopping a session never froze its run: history stayed empty and the live log tail outlived the session.
- A run was stamped as ending when it was recorded, not when it ended. A session that stopped days ago and was
  then run again or deleted had its previous run frozen with `endedAt` set to that moment, so a long-finished
  run read as one that had just stopped — and, beside a session that was running again, as the live session
  itself. The terminal transition's own time is used instead.

- The wall-time anchor was reset to the poll on every observation of a running job: `squeue` is asked for four
  fields and reports no elapsed time, but its row wins over the accounting row that does. A countdown built on
  `startedAt` would have restarted from the full walltime on every round.
- A session retired to `STOPPED` without a scheduler observation - by walltime or by going missing from the
  scheduler - kept its generation credential on disk, since only the observed path deleted it. Credential
  deletion now runs in `freezeIfTerminal`, the one place a session is first seen terminal, regardless of how
  it got there.
- A scheduler failure or cancellation diagnostic was stored on the session unbounded, up to the 1 MiB an SSH
  failure can carry; both are now passed through the same bound applied elsewhere.
- `cleanupFailedAttempt` never cancelled the aborted SSH authentication attempt's context, so its input
  writer goroutine blocked forever on that context's `Done` channel: every abort but the ready and
  full-queue exits leaked one goroutine per socket.
- `freezeIfTerminal` swallowed a failed credential delete behind a `false` return with no error, so `start`
  relaunched over the unfrozen run - orphaning the old generation's credential - and `stop` could report
  `STOPPING` while the mutation marking cleanup as pending went unsaved. The error now propagates through
  `freezeRun` and `stop`.
- `collectStartingSessionLogs` marked a session's log tail collected once its SSH round returned, empty tail
  included, so the first reconcile after Slurm reported the job running promoted it to `READY` before
  Linkspan had written a byte. `MergeRemote` now reports whether the merged tail is non-empty, and only that
  result promotes a `STARTING` session.
- Reusing a live control master for SSH authentication never cancelled the attempt's own context, so every
  such reuse leaked a child of the manager's context for the process's lifetime. That path now cancels the
  attempt the same way a freshly authenticated one already does.
- The log tail round's worst case - four targets, two streams each, at the old 64 KiB tail - landed exactly
  at the 1 MiB SSH output cap once hex-encoded and marked up, so a chunk that size failed the whole read and
  no `STARTING` session in it could promote. The remote tail is now capped at 16 KiB.
- Dev Tunnels create sent `If-Not-Match` instead of `If-None-Match`, so the create-only precondition was
  never applied and a create could silently overwrite an existing tunnel.
- Closing the session refresher while a reconciliation was in flight let that reconciliation run out its own
  60-second timeout on a context `Close` had no way to cancel, so shutdown could block that long past the
  25-second deadline. The reconcile context is now derived from one `Close` cancels.
- `readRunStats` asked `sacct` for a job's usage with no `--starttime`, so it defaulted to midnight today; a
  run that ended before midnight was never completed once its accounting window lapsed. It now passes a
  lookback reaching the run's own start, the way the scheduler round already does.
- The sampler shared one five-second budget across every pending run's accounting query, so a run behind a
  slow one on the same tick starved before its own `sacct` call could run. Each run now gets its own timeout,
  and the query runs off the sampler's tick on a goroutine that skips a tick already in flight rather than
  piling one atop another; `Close` waits for it to finish.
- A brief Dev Tunnels outage during `stop` answered `errors.Join` of the release failure and the (nil) save
  error, so a session that had in fact stopped and saved came back as a 500 instead of its record, and the
  `delete` that followed hit the same failure again instead of reporting `session_not_stopped`. The release
  failure is now recorded on the session instead of returned, and reconciliation retries the release later.
- `hostConfigPath` returned an empty path when no hosts directory was configured, so `ssh` ran with no `-F`
  and fell back to whatever configuration the daemon account happened to have - the isolation `-F` exists for
  failed open instead of closed. An unconfigured hosts directory now resolves to `/dev/null`, so every alias
  is refused.
- Discovery failures - a login node with no `sinfo`, for one - surfaced as a plain 500 `internal_error`
  instead of naming the operation that failed. They now carry their own `slurm_discovery_failed` code at 502.
- An unresolvable SSH alias also surfaced discovery as a plain 500 `internal_error`: the classified
  `ssh_host_not_found` from resolving it was discarded in favor of the unclassified error from parsing the
  empty output that followed. The classified error now wins.
- `create` built the submitted batch script before the session had a generation, so it redirected its log to
  the session id alone while the tail script read the id-and-generation basename; the two never met, no
  `STARTING` session promoted to `READY`, and every relaunch overwrote one shared log file. The script is now
  rebuilt with the real generation once the tunnel step assigns one, right before submission.
- The metrics sampler's client had no `CheckRedirect`, so Go copied its `X-Tunnel-Authorization` header —
  carrying the tunnel's connect token — to every redirect hop, including a cross-origin one; a compromised or
  malicious tunnel endpoint could 302 the token to a host of its choosing. It now uses `httpx.GuardedClient`
  with `httpx.SameOriginRedirect`, the same policy other outbound clients already use.
- `stop` was not idempotent: once a session's tunnel was already released, re-entering its cleanup branch on a
  second `stop` reassigned an already-empty tunnel and bumped `UpdatedAt` anyway, so a second `stop` on a
  `STOPPED` session invalidated every poller's ETag and `delete` always paid an extra write. The branch now
  only clears the tunnel when there was one to clear; a failed release still records its error regardless.
- `create` checked idempotency twice with two different answers: `reusableSession`'s upfront check and a
  second check under the later lock disagreed on a key reused for a mismatched request, the second answering
  `session_exists` instead of `idempotency_conflict` in the window between the two locks. Both now share the
  same predicate and error.

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
