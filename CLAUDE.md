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
apierr  safeio  proc                  error shape, private files, process groups
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
go test -race ./...
go vet ./...
go build -o /tmp/csctl-final ./cmd/csctl
```

## Production server

```bash
csctl serve \
  --listen 127.0.0.1:8045 \
  --oauth-authority https://login.microsoftonline.com/<tenant>/ \
  --allowed-origin https://workspace.example.edu \
  --allowed-origin http://127.0.0.1:8000
```

Tunnel creation uses the global Dev Tunnels management endpoint by default. A
recognized cluster endpoint can be selected with
`--devtunnel-management-url` or `CSCTL_DEVTUNNEL_MANAGEMENT_URL`; OAuth access
token validation remains on the global endpoint.

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
- The batch script starts Jupyter Server in the background and then execs
  Linkspan with plain flags to host the allocation tunnel. Inject the Jupyter
  identity token, the tunnel host token, and the allocation identity the tunnel
  only assigns at creation (its ID, cluster, and generation-derived ports) with
  fixed `sbatch --export` arguments. Validation and submission scripts must be
  byte-identical and contain no generated secret literal, so nothing that is
  unknown at review time may be written into the script text.
- Create one creator-owned Dev Tunnel per allocation generation, declaring both
  allocation ports at creation. Never request tunnel-wide anonymous access;
  grant anonymous connect only on the Jupyter port, whose authorization is
  Jupyter Server's own identity token. Disable traffic inspection. Request `customExpiration` as walltime plus
  cleanup grace, floored at one hour and
  capped at 30 days. Require the response duration to match and its returned
  creation/expiration timestamps to agree within the documented one-second
  serialization tolerance; persist the returned expiration and compensate
  before committing credentials/state on any mismatch. Create may return both
  relay formats empty before Linkspan attaches; retain that pre-host state while
  submitting, queued, starting, stopping, or terminal when the job ends before
  host attachment. Require management discovery to supply and validate both
  formats before runtime access or readiness. Treat every Create error as
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
  allocation is not resumable: creating another one is the only way to run it
  again, so there is no restart path to keep consistent with create.
- Tunnel expiry is the final cleanup backstop after ungraceful process or job
  failure.
- The Linkspan path may be absolute or anchored at `$HOME/`, which discovery
  resolves per host, so one setting serves hosts whose accounts do not share a
  home directory.
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
- Use OAuth Bearer for tunnel create/delete, persisted connect-token Bearer for
  management discovery, and `X-Tunnel-Authorization: tunnel` for tunneled
  control calls.
- Redact OAuth, host, connect, and Jupyter tokens from errors, logs, scripts,
  runtime responses, and tests. The Jupyter token is allowed only in the
  job environment and the runtime-access JSON.
- Scheduler state remains SSH/Slurm authoritative. Dev Tunnel management
  discovery supplies allocation endpoint metadata; do not introduce a second
  readiness owner.
- Reconciliation is driven by reads, capped at one per second, and never runs
  more than once at a time. There is no background cadence and no push channel:
  `GET /api/v1/runtimes` is the one read the browser polls, and it carries the
  caller's runtimes, whether a refresh is in flight, and their log tails --
  filtered to the same owned set, because a tail is as private as the runtime
  that produced it.
