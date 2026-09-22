# Architecture

`csctl` is a single binary that runs on a researcher's own machine and binds to loopback. It has no CLI
commands for hosts or sessions: `serve` starts the HTTP API and a browser or editor client drives everything
over it.

Each subsystem exports its route table. `internal/router` unions them into one registry, rejects duplicate
method-and-path pairs, and preserves the API's JSON 404 and 405 responses. `oauth.Service` contributes the public
sign-in routes, including a device grant for clients that cannot host a redirect, and wraps the
registry once; every other request passes through its identity boundary.

## Packages

`internal/` holds atomic packages with no HTTP surface of their own; `subsystems/` holds domains that own their
wire shapes and logic. A subsystem imports `internal/*` only and never another subsystem: a cross-subsystem need
is an interface the consumer declares (`session.RunnerProvider`, `session.TunnelCredentials`, `session.TunnelManager`)
that `main.go` satisfies with `ssh.Configurations`, `tunnel.Service` and the Dev Tunnels client. New code goes
in the lowest layer that can hold it.

```
internal/testutil    shared test helpers
internal/router      route-table union, duplicate detection, method dispatch, and JSON route failures
internal/security    security policy for opaque API errors, strict JSON, authenticated Principal context,
                     protected files, bounded HTTP clients, and shared name predicates
internal/db          the SQLite connection: pristine schema creation, format check, locking, and transactions
internal/identity     OIDC discovery, validation and grants, plus bounded Custos identity lookup
internal/ssh          bounded SSH execution, principal-scoped runners, PTY/WebSocket translation, and control masters
internal/slurm        Slurm command construction, framed output parsing, validation, and scheduler value types
internal/devtunnel    Dev Tunnels authorization and management protocols, validated wire types, and URI policy

subsystems/oauth      inbound identity policy, sign-in routes, origins, CORS, bearer extraction, and principals
subsystems/ssh        principal SSH hosts and keys, config rendering, Slurm discovery, live probes, authentication,
                      and routes
subsystems/tunnel     Dev Tunnels account linking, sealed principal-bound authorization state, refresh, and routes
subsystems/session    session state, Slurm and tunnel lifecycles, protected capabilities, reconciliation, run
                      records, logs, metrics, and routes
subsystems/telemetry  the read-only run-history route over the session subsystem's records

main.go               composition root, the csctl binary
```

Session, SSH, and tunnel subsystems give internal mechanisms domain meaning. OAuth establishes inbound identity.
Duplication belongs in a shared `internal/` package rather than between subsystems.

## Session lifecycle

A client validates before it creates. `POST /api/v1/sessions/validate` returns the candidate batch script and
Slurm's verdict on it; `POST /api/v1/sessions` creates the session the caller reviewed. Both are
OAuth-authenticated API actions.

Create proceeds in this order:

1. SSH discovery (`id`, `sacctmgr`, `sinfo`, `printenv HOME`) and `sbatch --test-only` against the candidate
   script.
2. One creator-owned Dev Tunnel for the session seq, the seq capability written to disk, then
   the session record persisted — durable before anything slow begins.
3. Login-node preparation: Linkspan and the workflow document.
4. `sbatch`, with the job name and the session identity on the command line.

Because the record is durable before preparation starts, preparation progress streams into the log tail the
client is already polling rather than into a request that says nothing until it ends.

Conclusive submission failure compensates tunnel and capability state. Ambiguous submission — anything other
than a refusal `sbatch` itself reported — stays durable for reconciliation, because the job may already be
queued. Stop releases the session's tunnel and capability and asks the scheduler to cancel the job; the seq it
ends is never reused.

### Seq and job names

A session is the durable record; a Slurm job only serves it, and a session outlives its jobs. The job name is
`cs-<session id>-<seq>`, so the scheduler and its accounting database answer for one seq of that
record rather than for the session as a whole. Without the seq, a run that has just been submitted would
be reconciled against the accounting record of the run it replaced and would inherit that run's outcome. For the
same reason, the window that tolerates a job Slurm has not published yet is measured from the record's last
change rather than from its creation, which a relaunch keeps.

A terminal session is not resumable, so running one again (`POST /api/v1/sessions/{id}/start`) is a create
under the same session identity: it replaces the record and takes the next seq, rather than adding a second
record or a second path to keep consistent with create.

### Self-preparing sessions

The login node supplies only the binary a job cannot start without, the Linkspan release it execs, plus the
workflow document, both in one constant script during create. The binary belongs to the account rather than to
a workspace: one `$HOME/.cybershuttle` per account, whatever a session opens. The environment, its
dependencies, the server, and the wait for that server to answer all happen inside the session: the workflow
is one task on `start`, its steps holding the one `jupyter.sessions.start` step, and Linkspan builds the
environment under `$HOME/.cybershuttle`, starts the server, publishes its port, and ends the job when the
server ends.

The workflow document is the `tasks` form, so the session's Linkspan must be 0.19.0 or newer.
Preparation refuses a host whose Linkspan is older, rather than letting the session fail at startup.
Preparation outlives the request that triggered it, so a caller that goes away leaves no half-built
environment. Preparation is keyed on the caller's host configuration plus the alias: a second create for that
same key is refused with `session_provisioning_in_progress` rather than made to wait behind work it cannot
see, while a different caller's preparation on the same host proceeds independently. A host that cannot be
prepared is refused with the reason and never receives a job.

The Linkspan path may be absolute or anchored at `$HOME/`, which discovery resolves per host, so one setting
serves hosts whose accounts do not share a home directory.

### The batch script and the workflow

The batch script execs Linkspan and names no application. What runs inside a session is the workflow's
business: preparation writes the per-session `workflow.yaml` beside the session and the batch script points
Linkspan at it, so the service starts through Linkspan once Linkspan is live.

The workflow carries only validated remote paths and the Jupyter port, which is not secret. Linkspan starts
Jupyter Server with the token it inherits from `JUPYTER_TOKEN`. That, the tunnel host token, and the
tunnel's own identity — its ID and cluster — plus the control port, derived from the session's seq
rather than assigned at creation, are injected with fixed `sbatch --export` arguments, and the job is named
on the same command line with `sbatch --job-name`.

Validation and submission scripts contain no generated secret literal: nothing unknown at review time is
written into the script text. They are identical except for the log redirect, which validate builds with a
placeholder seq of 0 since no seq is assigned until create's tunnel step succeeds; create then
rebuilds the script with the real seq before submitting it, so the log path the batch job writes to
matches the one the tail script later reads. Both listening ports are derived from the session ID and
seq, so they can be declared on the tunnel before the job starts and bound exactly as declared; Linkspan
republishes the Jupyter port, anonymous as declared, when its server starts, and access looks it up by number.

### States and reconciliation

The session states are `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED` and `FAILED`. There
is one state field: a Slurm word this vocabulary does not cover is treated as no observation rather than as a
state of its own. `STARTING` becomes `READY` once the job is running and its Linkspan has written to its
log, the one sign the server is up. Scheduler state remains SSH/Slurm authoritative; Dev Tunnels management
discovery supplies session endpoint metadata and is not a second readiness owner.

Reconciliation runs on a background tick every 30 seconds, never more than once at a time, so a session whose
owner closed the tab still reaches its terminal state and no read ever waits on SSH.

There is no push channel. `GET /api/v1/sessions` is the one read a client polls: it answers from persisted
state and carries the caller's sessions and their startup log tails — filtered to the same owned set, because
a tail is as private as the session that produced it. The strong `ETag` is taken over that filtered body, so it cannot match across principals, and a poll whose
`If-None-Match` still matches is answered `304 Not Modified` with no body.

### Samples and run records

Two things about a running session are not scheduler state and are not reconciled with it.

Resource samples are read from the Linkspan the session is running, over the control port already declared
on its own tunnel, once every five seconds. They are process-local and bounded to the last twenty, held beside
the log tail rather than in `state.db`: a window on a running session is not a fact about it, and
rewriting persisted state every five seconds to hold one would be the wrong store. They are served on their
own route for the same reason the poll is cheap — samples change on every tick, so folding them into
`GET /api/v1/sessions` would defeat its `ETag` for exactly the sessions that have any. A missed sample is a
gap in a window, not a fault.

A run record is the opposite: it is the one durable trace a session leaves. Ending forgets everything else
— relaunch replaces the session record in place and delete drops it — so the reconciliation that first sees a
terminal state freezes what the session did, carrying its final sample window with it, under the same lock
that would otherwise lose it. A run is named by the seq that ran it, so a session accumulates runs rather
than overwriting them, and its history outlives the session record. Slurm's own accounting is read separately and later:
`slurmdbd` flushes step usage a beat after a job ends, so the record is completed on the sampling tick for ten
minutes and then left as it is.

## Dev Tunnels

One creator-owned tunnel per session seq, declaring both session ports at creation. Tunnel-wide
anonymous access is never requested; anonymous connect is granted only on the Jupyter port, whose authorization
is Jupyter Server's own identity token. Traffic inspection is disabled.

`customExpiration` is requested as walltime plus a 15-minute cleanup grace, floored at one hour and capped at
30 days. The returned expiration is persisted, and a past expiration is compensated. Every create error is
treated as uncertain server-side creation: the deterministic tunnel ID is idempotently deleted with the request
authority before the error is returned. Tunnel expiry is the final cleanup backstop after ungraceful process or
job failure.

Create and delete use the caller's linked Dev Tunnels credential, resolved and refreshed on use by the Dev
Tunnels link broker, never the request's own bearer. The management read behind `/access` uses
`Authorization: tunnel <connect token>`, and the metrics read reaches Linkspan on the control port with the
same connect token in `X-Tunnel-Authorization`, which is how Dev Tunnels authorizes a non-anonymous port. The
edge answers `200` with an interstitial page once the host is gone, so a body that parses is the liveness
signal rather than the status.

## Dev Tunnels link

Sessions never run over the request's own bearer: that bearer identifies the caller to Custos, nothing more.
A session instead runs over a Microsoft or GitHub Dev Tunnels account the caller links once through a device-
code authorization the broker runs on their behalf, bound to their principal from the moment it starts. The
credential the authorization produces is sealed with `nacl/secretbox` under a key generated once at
`<state>/tunnel-link.key` and held at `<state>/hosts/<principal>/tunnel-link`, under the same per-principal hash
as SSH state. The credentials broker loads and refreshes it on use. `POST /api/v1/sessions` and `.../start` fail
with 409 `tunnel_link_required` before anything is provisioned when the caller has linked nothing; `stop` and
`delete` release best-effort, skipping the Dev Tunnels call rather than failing when no usable credential is
available, and leave tunnel expiry as the backstop.

## SSH configuration

Every caller has their own host configuration, and nothing else. A principal's entries live in
`state.db`'s `ssh_hosts` table. After every mutation, under the same lock, they are rendered whole to
`<state>/hosts/<principal>/config`, written atomically at mode `0600`. The directory is named by a hash of the
subject and tenant, so an identifier from another system never becomes a path. `session` never reads the file
back. `internal/ssh` reads it only to check an alias exists before running `ssh -F` against it.

This is a boundary, not a filing convention. `ssh` is invoked with `-F` naming that file, so an alias resolves
through the configuration of the caller who added it and through no other. The account `csctl` runs as has no
standing in the API: its `~/.ssh/config` is neither read nor written, and its aliases are invisible. Two
callers may use the same alias name for different hosts. The control master is keyed by the configuration as
well as the alias, so one caller authenticating a host never hands another an authenticated SSH login, and
scheduler reconciliation, log tailing and accounting each run as the session's own owner.

A host may use an uploaded credential by name or an explicit `IdentityFile` path the daemon account can read.
Credential files are principal-scoped and protected; explicit paths remain the caller's responsibility. Creation writes
a staged key, commits its metadata, then promotes the key. Deletion first renames the key to a
tombstone, then commits its metadata and host-reference changes. Startup resolves either interruption from the
committed metadata.

A pasted `ssh` command is parsed server-side into host, user, port, identity file and an allowlisted set of
`-o` options — only how a connection authenticates or keeps itself alive. Anything that can run a local program
or include more configuration is refused, and the browser never composes configuration text.

`internal/ssh` builds fixed argument vectors rather than shell strings and owns bounded PTY/WebSocket and
control-master mechanics. `subsystems/ssh` applies caller-scoped runners and public live-probe and interactive-
authentication behavior.

## Local state

`~/.cybershuttle/control`, proved on startup to be a directory this user owns at mode `0700`:

| Path | Contents |
| --- | --- |
| `state.db` | non-secret scheduler, session, tunnel, SSH host and login key metadata, and the bounded record of what finished sessions did |
| `hosts/` | one SSH host configuration per principal, rendered from `state.db`, the login keys they uploaded under `keys/`, and each principal's sealed `tunnel-link`, mode `0600` under a `0700` directory |
| `credentials/` | per-seq session capabilities: Dev Tunnel connect and Jupyter tokens, mode `0600` under `0700` |
| `tunnel-link.key` | the 32-byte key every `tunnel-link` file is sealed with, mode `0600`, generated once at boot |

The request's own bearer, and tunnel host and manage-ports credentials, are never persisted; the linked Dev
Tunnels credential is the one third-party credential this daemon keeps, and only sealed.

`state.db` holds a `schema_meta` format marker plus the tables each subsystem declares in its `schema.sql`:
`sessions` and `runs` (JSON payload keyed by session ID or `(session_id, seq)`) and `ssh_hosts` and `ssh_keys`
(keyed by `(principal, host)`, case-insensitive, or `(principal, name)`). A host payload is the same JSON the
API returns for it. Queries live in each subsystem's `query.sql` and are compiled by sqlc; `internal/db` only opens
the one WAL connection per state directory, runs every read-modify-write cycle behind one process and directory
lock, and wraps writes in one transaction. Schema DDL runs only when no database exists; an existing database
with any other format marker is refused before any credential file is created. Startup then recovers interrupted
key writes and deletions and regenerates every rendered config from committed host rows. Nothing is migrated.

## Trust boundaries

- **Loopback only.** `serve` refuses any listen address that is not an explicit loopback IP, and it refuses
  before anything binds a port.
- **Exact origins.** At least one origin is required; HTTPS and loopback HTTP only, no wildcards. A browser
  request carrying any other `Origin` is refused. Native clients may omit `Origin` on the authenticated API,
  but the pre-authentication sign-in routes require an exact allowed browser origin.
- **One bearer, one identity authority.** Every request carries a signed OIDC ID token, cryptographically
  validated against the configured issuer's discovery document and JWKS with exact issuer equality and the
  audience pinned to the configured client ID. That is not itself the principal: the daemon calls
  `GET {custos-url}/me` over HTTPS with the same bearer, allows only same-origin redirects, and treats Custos
  as the sole authority over who that token belongs to. A token Custos does not recognise is refused
  `401 identity_not_linked`.
- **Ownership** is the Custos user id the token resolves to, under the fixed tenant `custos`. Session lists
  and their log tails are filtered to the owner; item and access reads reject a different principal.
- **No ambient authentication.** There are no cookies, browser sign-in state, token URLs or static file serving, and
  the only unauthenticated routes are the three sign-in routes.
- **The sign-in relay** holds the one client secret CILogon's token endpoint requires and never returns it;
  it validates `redirectUri` against the same allowed-origin set as everything else and maps a rejected code
  or refresh token to `400 invalid_grant` without repeating the issuer's own error text.
- **The Dev Tunnels link broker** retains the device code in bounded process memory only, enforces polling
  intervals, and never answers a poll with the linked token — only the daemon's own sealed store ever holds
  it, and only Microsoft's rotated refresh token replaces what came before.
- **OIDC key refresh** is coalesced, runs outside the cache lock, and is limited to cooldown-bounded unknown
  `kid` values; a signature failure against a known key never triggers a fetch.
- **Validation precedes construction.** SSH aliases, scheduler values, node names, paths, tunnel metadata,
  direct URIs and ports are validated before they reach a command line or persistent state. Remote scripts are
  constants and values reach them as arguments. The validated principal travels in the request context, not
  in lifecycle request or state structs; the linked Dev Tunnels credential is resolved fresh from its sealed
  store rather than carried from the request that needs it.
- **Redaction.** Dev Tunnels, host, connect and Jupyter tokens are redacted from errors, logs, scripts and
  session responses. The Jupyter token appears only in the job environment and in the session-access
  response.
- **No proxying.** The owner-authenticated `/access` response returns the session's direct Jupyter URI and
  its token; cs-control proxies no session data and creates no login-host port forward. The one WebSocket
  carries interactive SSH authentication prompts as untyped bytes and never forwards session data.
