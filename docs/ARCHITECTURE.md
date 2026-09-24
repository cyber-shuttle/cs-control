# Architecture

`cs` is one binary; `cs serve` runs the HTTP API that browser and editor clients drive. Each subsystem exports a
route table; `internal/router` unions them, refuses duplicate method-and-path pairs, and answers JSON 404 and 405.
`oauth.Service` contributes the five public sign-in routes and wraps the registry in its identity boundary. Routes
are one-line adapters over service operations that take the acting principal as a parameter and check ownership
themselves.

## Packages

A subsystem imports `internal/*` only, never another subsystem. A cross-subsystem need is an interface the consumer
declares (`session.RunnerProvider`, `session.TunnelCredentials`, `session.TunnelManager`), which `main.go` satisfies
with `ssh.Configurations`, `tunnel.Service` and the Dev Tunnels client. Shared code goes in the lowest `internal/`
package that can hold it.

```
internal/testutil    shared test helpers
internal/router      route-table union, duplicate detection, method dispatch, JSON route failures
internal/security    API errors, strict JSON, Principal context, origin policy, protected files, bounded HTTP
                     clients, name predicates
internal/db          Postgres connection: schema creation, format check, locking, transactions, unlocked reads
internal/identity    OIDC discovery, validation and grants; Custos identity lookup
internal/ssh         bounded SSH execution, principal-scoped runners, PTY/WebSocket bridge, control masters
internal/slurm       Slurm command construction, framed output parsing, scheduler value types
internal/devtunnel   Dev Tunnels authorization and management protocols, wire types, URI policy

subsystems/oauth     sign-in routes, CORS, bearer extraction, principal resolution
subsystems/ssh       per-principal SSH hosts and keys, config rendering, live probe, authentication
subsystems/tunnel    Dev Tunnels account linking, sealed credential store, refresh
subsystems/session   session state, Slurm and tunnel lifecycles, capabilities, reconciliation, logs, metrics,
                     run records

main.go              composition root
```

## Session lifecycle

A session is the durable record; each `start` launches one Slurm job under the next `seq`, named
`cs-<session id>-<seq>`. `POST /sessions` records a session at seq 0 without touching a host.

A launch runs in this order:

1. Discovery (`id`, `sacctmgr`, `sinfo`, `printenv HOME`) and `sbatch --test-only` against the candidate script.
2. A creator-owned Dev Tunnel for the seq from the owner's linked Dev Tunnels account; then the seq capability
   written to disk and the record persisted as `SUBMITTING`.
3. Login-node preparation: Linkspan and the workflow document, in one constant script.
4. `sbatch` with the job name and the session environment on the command line.

The record is durable before preparation, so preparation narrates into the log tail the client already polls. A
conclusive submission failure releases the tunnel and capability and marks the session `FAILED`. An ambiguous one,
anything other than a refusal `sbatch` reported, stays durable for reconciliation because the job may be queued. A
submission that returns after the session was stopped cancels its job. A seq is never reused.

### Preparation

Preparation installs Linkspan into the account, not the session: one `$HOME/.cybershuttle` per account. It refuses
a Linkspan older than 0.19.0, the first release that reads the `tasks` document. It runs on
the service's context, so an abandoned request leaves no half-built state. Preparation is keyed on the caller's
config file plus alias; a concurrent launch on the same key is refused `session_provisioning_in_progress`, while
another caller's preparation of the same host proceeds.

The batch script execs Linkspan and names no application. The workflow, one `on: start` task with a
`jupyter.sessions.start` step, carries only validated paths and the Jupyter port. Secrets never enter script text:
`JUPYTER_TOKEN`, `CS_CONTROL_PORT`, `CS_TUNNEL_ID`, `CS_TUNNEL_CLUSTER` and `CS_TUNNEL_HOST_TOKEN` travel in
`sbatch --export`. The control and Jupyter ports are derived from session ID and seq, so the tunnel can declare both
before the job starts.

### States and reconciliation

States: `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED`, `FAILED`. A Slurm state outside this
vocabulary is treated as no observation. `STARTING` becomes `READY` once the job runs and its log has output. Slurm
is otherwise authoritative, including for the end of a run.

Reconciliation runs in the background every 30 seconds, one pass at a time, so no read waits on SSH. A session
unknown to the scheduler past a two-minute propagation window becomes `STOPPED`, as does one whose scheduler is
unreachable ten minutes past its walltime.

### Samples and run records

Samples are served on their own route so they do not churn the `GET /sessions` ETag. When a session first reaches a
terminal state, cs-plane freezes a run record keyed by `(session id, seq)` holding the final sample window and log
tail, then drops both buffers.

## Dev Tunnels

Linking is required: `start` answers `409 tunnel_link_required` before anything is provisioned while the caller has
linked nothing. The broker runs a Microsoft or GitHub device-code authorization bound to the caller's principal,
then seals the resulting credential with `nacl/secretbox` under `tunnel-link.key`. The credential is loaded and, when
it has a refresh token, refreshed within two minutes of expiry on use; the request's own bearer is never used for
Dev Tunnels.

Each session seq gets one creator-owned tunnel declaring the control and Jupyter ports, with anonymous connect only on
the Jupyter port, whose authorization is Jupyter Server's own token, and traffic inspection disabled. `customExpiration` is walltime plus 15 minutes, clamped to one hour
through 30 days; expiry is the cleanup backstop. Any create error deletes the deterministic tunnel ID before
returning. `stop` releases best-effort, skipping the Dev Tunnels call without a usable credential. `/access`
reads the tunnel with `Authorization: tunnel <connect token>` and answers the Jupyter port's URI with the live
expiration; metrics reach Linkspan's control port with the connect token in `X-Tunnel-Authorization`.

## SSH configuration

A principal's hosts live in `ssh_hosts`; after each mutation, under the same lock, they are rendered whole to
`hosts/<principal>/config`, where `<principal>` is a hash of subject and tenant. `ssh` always runs with `-F` naming
that file, so an alias resolves only through its owner's configuration, and aliases never collide across callers.
Control masters are keyed by configuration and alias, so one caller's authentication never serves another. The
account cs-plane runs as has no standing: its `~/.ssh/config` is ignored.

A pasted `ssh` command is parsed server-side into host, user, port, identity file, `ProxyJump` and allowlisted `-o`
options; nothing that runs a local program or includes other configuration is accepted. A host uses an uploaded key
named by `keyId`, stored as its `IdentityFile` with `IdentitiesOnly yes`, or an explicit `-i` path the account cs-plane
runs as can read. Key creation stages the file, commits metadata, then promotes the file; deletion renames the file
to a tombstone before committing. Startup resolves either interruption from committed metadata.

## Persistence

The Postgres schema holds `schema_meta` plus each subsystem's `schema.sql` tables: `sessions` and `runs` (JSON
payload keyed by session ID or `(session_id, seq)`), `ssh_hosts` (keyed by `(principal, host)`, alias unique ignoring
case) and `ssh_keys` (keyed by `(principal, name)`). `internal/db` uses one connection and serializes
read-modify-write cycles behind a process lock and a file lock in the state directory. Session reads are single
statements outside the lock. DDL runs only in an empty schema; a non-empty schema without the current format marker
is refused before any credential file is created. Nothing is migrated. Startup recovers interrupted key changes and
re-renders every SSH config. Files on disk are listed in the [README](../README.md#local-state).

## Trust boundaries

- **Loopback only.** `serve` refuses a non-loopback listen address before binding.
- **Exact origins.** One policy, `security.Origins`, covers every route, the SSH authentication WebSocket included: a
  present `Origin` must be allowlisted; an absent one is a native client. `oauth/config` and
  `oauth/exchange` also require one.
- **One bearer, one identity authority.** The ID token is validated against the issuer's discovery document and JWKS,
  with exact issuer and audience pinned to the client ID. Custos `GET /me`, called with the same bearer over a client
  that follows only same-origin redirects, names the principal under tenant `custos`.
- **Ownership.** Every session, log tail, run, host, key and tunnel link is scoped to the principal.
- **No ambient authentication.** No cookies, token URLs or static files. Outside the bearer boundary are only the
  sign-in routes.
- **Sign-in relay.** Holds the client secret and never returns it; `redirectUri` must be on an allowed origin; issuer
  errors are not echoed.
- **Dev Tunnels broker.** Device codes stay in bounded process memory, polling intervals are enforced, and no
  response carries the linked token.
- **OIDC key refresh.** Coalesced and outside the cache lock; an unknown `kid` forces at most one refresh per 30
  seconds.
- **Validation precedes construction.** Aliases, scheduler values, node names, paths, tunnel metadata and ports are
  validated before reaching a command line or state; remote scripts are constants taking arguments.
- **Redaction.** Tunnel, host, connect and Jupyter tokens are redacted from errors, logs, scripts and responses. The
  Jupyter token appears only in the job environment and the access response.
- **No proxying.** `/access` returns the session's direct Jupyter URI over its tunnel; cs-plane relays no session data
  and opens no login-node port forward.
- **Shared nodes.** Jobs are not `--exclusive`; any user on the compute node can reach Linkspan's loopback control port
  ([Linkspan security model](https://github.com/cyber-shuttle/linkspan/blob/main/SECURITY.md#security-model)).
