# Architecture

`csctl` is a single binary that runs on a researcher's own machine and binds to loopback. It has no CLI
commands for hosts or runtimes: `serve` starts the HTTP API and a browser or editor client drives everything
over it.

The handler stack is `authn.NewDeviceCodeRoutes(authn.NewOAuthBoundary(control.NewHTTPHandler(...)))`. The two
device-code routes are answered by the broker in front of the OAuth boundary; every other request passes
through it.

## Packages

Each subsystem is a package and depends only downward. New code goes in the lowest layer that can hold it, and
no package imports upward.

```
apierr  safeio       error shape, private files
framed               marker-delimited remote output
httpx                bounded client/body, HTTPS base-URL policy, JSON writers
sshconfig            reads ~/.ssh/config, writes only its own managed block, never runs ssh
sshexec              argument vectors, control socket, bounded output
devtunnel            Dev Tunnels management client and its URI/host policy
authn                OAuth boundary, OIDC validation, device-code broker
gateway              SSH authentication WebSocket route and its frames
control              runtime domain, store, reconcile, discovery, HTTP
cmd/csctl            composition root
```

`control` names the SSH route interface it serves (`SSHAuthRoute`) rather than importing `gateway`; `cmd/csctl`
supplies the concrete gateway. Duplication belongs in a shared lower package rather than copied between two
subsystems.

## Allocation lifecycle

A client validates before it creates. `POST /api/v1/runtimes/validate` returns the candidate batch script and
Slurm's verdict on it; `POST /api/v1/runtimes` creates the allocation the caller reviewed. Both are
OAuth-authenticated API actions.

Create proceeds in this order:

1. SSH discovery (`id`, `sacctmgr`, `sinfo`, `printenv HOME`) and `sbatch --test-only` against the candidate
   script.
2. One creator-owned Dev Tunnel for the allocation generation, the generation credential written to disk, then
   the runtime record persisted — durable before anything slow begins.
3. Login-node preparation: uv, Linkspan and the workflow document.
4. `sbatch`, with the job name and the allocation identity on the command line.

Because the record is durable before preparation starts, preparation progress streams into the log tail the
client is already polling rather than into a request that says nothing until it ends.

Conclusive submission failure compensates tunnel and credential state. Ambiguous submission — anything other
than a refusal `sbatch` itself reported — stays durable for reconciliation, because the job may already be
queued. Stop releases the allocation's tunnel and credential and asks the scheduler to cancel the job; the
generation it ends is never reused.

### Generations and job names

The job name is `cs-<runtime id>-<generation>`, so the scheduler and its accounting database answer for one
allocation rather than for the runtime record. A record outlives its allocations: without the generation, a run
that has just been submitted is reconciled against the accounting record of the run it replaced and inherits
that run's outcome. For the same reason, the window that tolerates a job Slurm has not published yet is
measured from the record's last change rather than from its creation, which a relaunch keeps.

A terminal allocation is not resumable, so running one again (`POST /api/v1/runtimes/{id}/start`) is a create
under the same runtime identity: it replaces the record and takes a new generation, rather than adding a second
record or a second path to keep consistent with create.

### Self-preparing allocations

The login node supplies only the two binaries a job cannot start without — the Linkspan release it execs and
uv — plus the workflow document, all in one constant script during create. Both binaries belong to the account
rather than to a workspace: one `$HOME/.cybershuttle` per account, whatever a runtime opens. The environment,
its dependencies, the server, and the wait for that server to answer all happen inside the allocation, through
the workflow Linkspan runs.

An allocation hosts a tunnel this control plane created, so its Linkspan must accept `--tunnel-host-token`.
Preparation refuses a host whose Linkspan does not, rather than letting the allocation fail on its first flag.
Preparation outlives the request that triggered it, so a caller that goes away leaves no half-built
environment, and one preparation runs per host at a time: a second caller is refused with
`runtime_provisioning_in_progress` rather than made to wait behind work it cannot see. A host that cannot be
prepared is refused with the reason and never receives a job.

The Linkspan path may be absolute or anchored at `$HOME/`, which discovery resolves per host, so one setting
serves hosts whose accounts do not share a home directory.

### The batch script and the workflow

The batch script execs Linkspan and names no application. What runs inside an allocation is the workflow's
business: preparation writes the per-runtime `workflow.yaml` beside the allocation and the batch script points
Linkspan at it, so the service starts through Linkspan once Linkspan is live.

Linkspan's `shell.exec` runs without a shell and expands nothing, so the workflow carries only validated remote
paths. Jupyter Server reads its own token and port from `JUPYTER_TOKEN` and `JUPYTER_PORT`. Those, the tunnel
host token, and the allocation identity the tunnel only assigns at creation — its ID, cluster, and
generation-derived ports — are injected with fixed `sbatch --export` arguments, and the job is named on the
same command line with `sbatch --job-name`.

Validation and submission scripts are byte-identical and contain no generated secret literal: nothing unknown
at review time is written into the script text. Both listening ports are derived from the runtime ID and
generation, so they can be declared on the tunnel before the job starts and bound exactly as declared.

### States and reconciliation

The runtime states are `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED` and `FAILED`. There
is one state field: a Slurm word this vocabulary does not cover is treated as no observation rather than as a
state of its own. Scheduler state remains SSH/Slurm authoritative; Dev Tunnels management discovery supplies
allocation endpoint metadata and is not a second readiness owner.

Reconciliation is driven by reads, capped at one per second, and never runs more than once at a time. A slow
background tick every 30 seconds runs the same reconciliation when nobody is reading, so a runtime whose owner
closed the tab still reaches its terminal state.

There is no push channel. `GET /api/v1/runtimes` is the one read a client polls: it answers from persisted
state, starts a reconciliation for the next poll to collect, and carries the caller's runtimes and their
startup log tails — filtered to the same owned set, because a tail is as private as the runtime that produced
it. The strong `ETag` is taken over that filtered body, so it cannot match across principals, and a poll whose
`If-None-Match` still matches is answered `304 Not Modified` with no body.

## Dev Tunnels

One creator-owned tunnel per allocation generation, declaring both allocation ports at creation. Tunnel-wide
anonymous access is never requested; anonymous connect is granted only on the Jupyter port, whose authorization
is Jupyter Server's own identity token. Traffic inspection is disabled.

`customExpiration` is requested as walltime plus a 15-minute cleanup grace, floored at one hour and capped at
30 days. The returned expiration is persisted, and a past expiration is compensated. Every create error is
treated as uncertain server-side creation: the deterministic tunnel ID is idempotently deleted with the request
authority before the error is returned. Tunnel expiry is the final cleanup backstop after ungraceful process or
job failure.

Create and delete use the delegated OAuth bearer. The management read behind `/access` uses
`Authorization: tunnel <connect token>`.

## SSH configuration

Host entries the API creates live between `# >>> cybershuttle managed >>>` and `# <<< cybershuttle managed <<<`
in `~/.ssh/config`, written atomically at mode `0600`. Everything outside those markers is read and never
rewritten, and only a managed alias may be removed.

A pasted `ssh` command is parsed server-side into host, user, port, identity file and an allowlisted set of
`-o` options — only how a connection authenticates or keeps itself alive. Anything that can run a local program
or include more configuration is refused, and the browser never composes configuration text.

`sshexec` builds fixed argument vectors rather than shell strings and multiplexes over an OpenSSH
`ControlMaster` socket in the state directory, with bounded output and timeouts. The interactive SSH
authentication WebSocket is what establishes that master.

## Local state

`~/.cybershuttle/control`, proved on startup to be a directory this user owns at mode `0700`:

| Path | Contents |
| --- | --- |
| `state.json` | non-secret scheduler, allocation and tunnel metadata |
| `credentials/` | per-generation Dev Tunnel connect token and Jupyter token, mode `0600` under a `0700` directory |
| `ssh/` | OpenSSH `ControlMaster` sockets |

OAuth credentials and tunnel host and manage-ports credentials are never persisted.

## Trust boundaries

- **Loopback only.** `serve` refuses any listen address that is not an explicit loopback IP, and it refuses
  before anything binds a port.
- **Exact origins.** At least one origin is required; HTTPS and loopback HTTP only, no wildcards. A browser
  request carrying any other `Origin` is refused. Native clients may omit `Origin` on the authenticated API,
  but the pre-authentication device routes require an exact allowed browser origin.
- **Two independent bearers.** HTTP requests carry a Dev Tunnels access token in `Authorization` and a signed
  Microsoft ID token in `X-CyberShuttle-Identity`. The access token is a remotely validated Dev Tunnels
  capability; the cryptographically validated ID token is the sole identity bearer. No subject or `at_hash`
  binding is claimed between them.
- **Ownership** is the stable subject and tenant derived only from the validated ID token. Dev Tunnels access
  validation is an independent capability check and supplies no identity claims. Runtime lists and their log
  tails are filtered to the owner; item and access reads reject a different principal.
- **No ambient authentication.** There are no cookies, browser sessions, token URLs or static file serving, and
  the only unauthenticated routes are the two device-code routes.
- **The device-code broker** retains the device code in bounded process memory only, enforces polling
  intervals, and discards refresh tokens and terminal state. It brokers pinned Microsoft requests for exact
  allowed browser origins.
- **OIDC key refresh** is coalesced, runs outside the cache lock, and is limited to cooldown-bounded unknown
  `kid` values; a signature failure against a known key never triggers a fetch.
- **Validation precedes construction.** SSH aliases, scheduler values, node names, paths, tunnel metadata,
  direct URIs and ports are validated before they reach a command line or persistent state. Remote scripts are
  constants and values reach them as arguments. Delegated OAuth credentials and the validated principal travel
  in the request context, not in lifecycle request or state structs.
- **Redaction.** OAuth, host, connect and Jupyter tokens are redacted from errors, logs, scripts and runtime
  responses. The Jupyter token appears only in the job environment and in the runtime-access response.
- **No proxying.** The owner-authenticated `/access` response returns the allocation's direct Jupyter URI and
  its token; cs-control proxies no session data and creates no login-host port forward. The one WebSocket
  carries interactive SSH authentication prompts as untyped bytes and never forwards runtime data.
