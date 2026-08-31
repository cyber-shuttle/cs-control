# cs-control

Loopback per-user control plane for SSH/Slurm allocation enactment. It owns
scheduler operations, allocation Dev Tunnel resource creation/deletion,
owner-bound runtime state, and the narrow connect-token credential store. It
returns narrow runtime state plus owner-authenticated Jupyter access and never
proxies runtime data.

## Packages

Each subsystem is a package and depends only downward. Add code to the lowest
layer that can hold it, and never introduce an upward import.

```
apierr  safeio                        error shape, private files
httpx                                 bounded client/body, HTTPS base-URL policy, JSON writers
sshconfig                             reads ~/.ssh/config, writes only its own managed block, never runs ssh
sshexec                               argument vectors, control socket, bounded output
devtunnel                             Dev Tunnels management client and its URI/host policy
authn                                 OAuth boundary, OIDC validation, device-code broker
gateway                               SSH authentication WebSocket route and its frames
control                               runtime domain, store, reconcile, discovery, HTTP
cmd/csctl                             composition root
```

`control` names the SSH route interface it serves (`SSHAuthRoute`) rather than
importing `gateway`; `cmd/csctl` supplies the concrete gateway. Duplication belongs in a shared lower package, not copied
between two subsystems.

## Commands

```bash
go build ./...
go vet ./...
go test -race ./...
```

## Production server

Serve invocation: README.md#enactment-api.

At least one exact origin is required. Permit HTTPS or loopback HTTP only; no
wildcards. HTTP requests carry a Dev Tunnels access token plus a signed
Microsoft ID token in `X-CyberShuttle-Identity`. The one retained SSH
WebSocket route carries exactly `cybershuttle.v1`, `bearer.<base64url-access>`,
and `identity.<base64url-id-token>`. Treat them as independent bearers: the
remotely validated access token is a Dev Tunnels capability and the
cryptographically validated ID token is the sole identity bearer. There is no
subject/`at_hash` binding between them. OIDC refresh must remain coalesced,
outside cache locks, and limited to cooldown-bounded unknown `kid` values; a
known-key signature failure must not fetch. Do not add cookies, browser sessions, token URLs, static serving,
unauthenticated production routes beyond the bounded memory-only device-code
broker, or token persistence/logging.

## Allocation boundaries

- The allocation API flow is validate, caller review, then create:
  `POST /api/v1/runtimes/validate` returns the candidate script and Slurm
  validation result, and `POST /api/v1/runtimes` creates the reviewed
  allocation. Keep validation and create as OAuth-authenticated API actions.
- The batch script execs Linkspan and names no application. What runs inside
  an allocation is the workflow's business: the provisioning script writes the
  per-runtime workflow beside the allocation, and the batch script points
  Linkspan at it, so the
  service starts through Linkspan once Linkspan is live. `shell.exec` runs
  without a shell and expands nothing, so the workflow carries only validated
  remote paths; the Jupyter identity token and port reach the server through
  `JUPYTER_TOKEN` and `JUPYTER_PORT`, which it reads itself. Inject those, the
  tunnel host token, and the allocation identity the tunnel only assigns at
  creation (its ID, cluster, and generation-derived ports) with fixed
  `sbatch --export` arguments, and name the job on the same command line with
  `sbatch --job-name`. Validation and submission scripts must be
  byte-identical and contain no generated secret literal, so nothing that is
  unknown at review time may be written into the script text.
- The job name is `cs-<runtime id>-<generation>`, so the scheduler and its
  accounting database answer for one allocation rather than for the card. A
  card outlives its allocations: without the generation, a run that has just
  been submitted is reconciled against the accounting record of the run it
  replaced and inherits that run's outcome. For the same reason the window
  that tolerates a job Slurm has not published yet is measured from the
  record's last change, not from the card's creation, which a relaunch keeps.
- Create one creator-owned Dev Tunnel per allocation generation, declaring both
  allocation ports at creation. Never request tunnel-wide anonymous access;
  grant anonymous connect only on the Jupyter port, whose authorization is
  Jupyter Server's own identity token. Disable traffic inspection. Request `customExpiration` as walltime plus
  cleanup grace, floored at one hour and capped at 30 days; persist the returned
  expiration and compensate on a past expiration. Treat every Create error as
  uncertain server-side creation and idempotently delete the deterministic
  tunnel ID with the request authority before returning.
- Persist only non-secret scheduler and tunnel state in runtime storage. Store
  the allocation connect token separately in mode `0600` under a mode `0700`
  directory. Never persist OAuth or host/manage-ports credentials.
- Return the allocation's direct Jupyter URI and identity token only through
  the separate owner-authenticated runtime-access response. Never proxy runtime
  data or create a login-host runtime port forward.
- Runtime ownership is the stable subject+tenant derived only from the
  cryptographically validated ID token. Dev Tunnels access validation is an
  independent capability check and supplies no identity claims.
- Conclusive submission failure compensates tunnel and credential state;
  ambiguous submission remains durable for reconciliation. Stop must preserve
  scheduler/tunnel/credential ordering and generation invalidation. A terminal
  allocation is not resumable, so running one again is a create under the same
  runtime identity (`POST /api/v1/runtimes/{id}/start`): it replaces the record
  and takes a new generation rather than adding a second card or a second path
  to keep consistent with create.
- Tunnel expiry is the final cleanup backstop after ungraceful process or job
  failure.
- The Linkspan path may be absolute or anchored at `$HOME/`, which discovery
  resolves per host, so one setting serves hosts whose accounts do not share a
  home directory. It defaults to `$HOME/.cybershuttle/bin/linkspan`.
- An allocation prepares itself. The login node supplies only the two binaries
  a job cannot start without -- the Linkspan release it execs and uv, both
  single downloads that take seconds -- and the workflow document, all in one
  constant script during create, after the runtime is durable so its progress
  streams into the tail the browser polls. The environment, its dependencies, the server, and the
  wait for that server to answer all happen inside the allocation, through the
  workflow Linkspan runs. Both binaries belong to the account, not to a
  workspace: one `$HOME/.cybershuttle` per account, whatever a runtime opens.
  An allocation hosts a tunnel this control plane created, so its Linkspan must
  accept `--tunnel-host-token`; preparation refuses a host whose Linkspan does
  not, rather than letting the allocation fail on its first flag.
  Preparation outlives the request that triggered it, so a caller that goes away leaves no half-built
  environment, and one preparation runs per host at a time -- a second caller is refused with `runtime_provisioning_in_progress`
  rather than made to wait behind work it cannot see. A host that cannot be
  prepared is refused with the reason and never receives a job.
- Host entries the API creates live between the `cybershuttle managed`
  markers in `~/.ssh/config`, written atomically at mode `0600`. Everything
  outside those markers is read and never rewritten, and only a managed alias
  may be removed. A pasted ssh command is parsed server-side into host, user,
  port, identity, and an allowlisted set of `-o` options; anything that can run
  a local program or include more configuration is refused.
- The CLI exposes only `serve`, `help`, and `version`. Runtime and SSH
  operations use the OAuth-authenticated API; do not add delegated-token argv
  flags.

## Trust-boundary rules

- Global flags precede commands.
- Validate SSH aliases, scheduler values, node names, paths, tunnel metadata,
  direct URIs, and ports before command construction or persistence.
- Use fixed argument arrays, bounded outputs, and timeouts for SSH/Slurm.
- Carry delegated OAuth and validated principal in request context only; do not
  place them in lifecycle request/state structs.
- Use OAuth Bearer for tunnel create/delete; `Authorization: tunnel <connect
  token>` for the management Get behind `/access`.
- Redact OAuth, host, connect, and Jupyter tokens from errors, logs, scripts,
  runtime responses, and tests. The Jupyter token is allowed only in the
  job environment and the runtime-access JSON.
- Scheduler state remains SSH/Slurm authoritative. Dev Tunnel management
  discovery supplies allocation endpoint metadata; do not introduce a second
  readiness owner.
- Reconciliation is driven by reads, capped at one per second, and never runs
  more than once at a time. A slow background tick runs the same reconciliation
  when nobody is reading, so a runtime whose owner closed the tab still reaches
  its terminal state. There is no push channel:
  `GET /api/v1/runtimes` is the one read the browser polls, and it carries the
  caller's runtimes and their log tails -- filtered to the same owned set,
  because a tail is as private as the runtime that produced it. The strong
  `ETag` is taken over that filtered body, so it cannot match across principals,
  and a poll that still matches is answered `304` with no body.
