# CyberShuttle Control

`csctl` is the per-user SSH/SLURM enactment control plane for CyberShuttle allocations. It stores non-secret scheduler, allocation, and tunnel metadata. Dev Tunnel connect credentials are kept separately in private local credential files and are never returned by the API; generation-bound Jupyter capabilities derived from them are issued only by the owner-authenticated access endpoint.

## Build and verify

```bash
go test -race ./...
go vet ./...
go build ./cmd/csctl
```

## Enactment API

Run the API on an explicit loopback address and allow each browser origin exactly:

```bash
csctl serve \
  --listen 127.0.0.1:8045 \
  --oauth-authority https://login.microsoftonline.com/<tenant>/ \
  --allowed-origin https://workspace.example.edu \
  --allowed-origin http://127.0.0.1:8000
```

`--allowed-origin` is repeatable and at least one origin is required. HTTPS origins and loopback HTTP origins are accepted; wildcards are rejected. Browser requests from any other `Origin` are rejected. `--oauth-authority` is required and accepts only a tenant-specific `https://login.microsoftonline.com/<tenant>/` authority with the default HTTPS port. The Dev Tunnels native public client ID and scope are fixed by cs-control; no SPA registration is configured. Native clients may omit `Origin` on the authenticated enactment API, but the pre-authentication device routes require an exact allowed browser origin.

Every production HTTP request requires both `Authorization: Bearer <Dev-Tunnels-access-token>` and `X-CyberShuttle-Identity: <Microsoft-ID-token>`. On the one SSH WebSocket route (`auth`), every client offers exactly three subprotocols: `cybershuttle.v1`, `bearer.<base64url-utf8-access-token>`, and `identity.<base64url-utf8-ID-token>`. Upgrade-shaped requests to runtime, ordinary SSH, unsafe-alias, or other routes do not accept subprotocol authentication.

cs-control treats the two credentials as independent bearers. The opaque access token (including a five-segment JWE) is a capability validated with the Microsoft Dev Tunnels management API. The ID token is the sole identity bearer: cs-control separately validates its RS256 signature through bounded OIDC discovery and cached JWKS, including issuer, client audience, lifetime, `oid`, and `tid`, and derives the owner only from that ID token. There is intentionally no claimed-subject or `at_hash` binding between the capability and identity bearer.

JWKS refreshes run outside the cache lock and are coalesced. Only an unknown `kid` can request an early refresh; random unknown keys are bounded by a global cooldown and size-limited negative cache, while a bad signature for a known `kid` fails without network access. A five-minute cache lifetime bounds same-`kid` rotation pickup. The two credential subprotocols are removed before dispatch and only `cybershuttle.v1` is negotiated. Neither token is logged, persisted, echoed, or placed in a URL. CORS preflight permits only the configured exact origin, approved methods, and `Authorization`/`X-CyberShuttle-Identity`/`Content-Type` headers. The server does not issue browser cookies and has no static application, browser session, bootstrap, logout, token-file, or unauthenticated mode. The only pre-authentication routes are `POST /api/v1/oauth/device/start` and `POST /api/v1/oauth/device/poll/{opaqueHandle}`. They broker pinned Microsoft device-code requests for exact allowed browser origins, retain the device code only in bounded process memory, enforce polling intervals, and discard refresh tokens and terminal state.

Tunnel creation uses `https://global.rel.tunnels.api.visualstudio.com` by default.
When the global cluster quota is exhausted, select a recognized cluster endpoint
with the global `--devtunnel-management-url` flag or
`CSCTL_DEVTUNNEL_MANAGEMENT_URL`, for example:

```bash
export CSCTL_DEVTUNNEL_MANAGEMENT_URL=https://usw3.rel.tunnels.api.visualstudio.com
```

Only the global endpoint or a single valid cluster label under
`*.rel.tunnels.api.visualstudio.com` is accepted, over HTTPS with no alternate
port. This setting changes tunnel management only; delegated OAuth capability
validation remains on the global endpoint.

The loopback API exposes:

```text
POST     /api/v1/oauth/device/start
POST     /api/v1/oauth/device/poll/{opaqueHandle}
GET      /api/v1/ssh
POST     /api/v1/ssh
DELETE   /api/v1/ssh/{alias}
WS       /api/v1/ssh/{alias}/auth
GET      /api/v1/ssh/{alias}/slurm
POST     /api/v1/ssh/{alias}/test
GET      /api/v1/runtimes
POST     /api/v1/runtimes
POST     /api/v1/runtimes/script
POST     /api/v1/runtimes/validate
GET      /api/v1/runtimes/{id}
DELETE   /api/v1/runtimes/{id}
POST     /api/v1/runtimes/{id}/start
POST     /api/v1/runtimes/{id}/stop
GET      /api/v1/runtimes/{id}/access
```

`GET /api/v1/runtimes` is the read a browser polls: it answers from persisted
state, starts a reconciliation for the next poll to collect, and carries the
caller's runtimes and their startup tails. The one WebSocket is interactive SSH
authentication, whose prompts are untyped bytes. It never forwards runtime data.

## Runtime lifecycle

Trusted deployment settings are global flags or environment variables. Install Linkspan on the remote SSH host and configure its resolved absolute path:

```bash
export CSCTL_LINKSPAN=/home/me/.cybershuttle/bin/linkspan
```

Before submission cs-control requires the exact Linkspan allocation contract, performs SSH discovery and `sbatch --test-only`, creates a principal-owned Dev Tunnel, durably records the allocation generation and connect credential, and submits:

```bash
exec "$LINKSPAN_BIN" --port "$CS_CONTROL_PORT" --tunnel-enable \
  --tunnel-id "$CS_TUNNEL_ID" --tunnel-cluster "$CS_TUNNEL_CLUSTER" \
  --tunnel-host-token "$CS_TUNNEL_HOST_TOKEN" --workflow "$PRIVATE_ROOT/workflow.yaml"
```

The batch script names no application: what the allocation is for travels with it in the workflow document,
whose only action is `shell.exec`. Tokens and ports are passed through fixed `sbatch --export` arguments and
are redacted from errors. Conclusive submission failure compensates the tunnel and credential; ambiguous submission retains durable intent for scheduler recovery. Stop invalidates the tunnel and credential while preserving the scheduler stop state. A terminal allocation is not resumable: running it again creates a new allocation under the same runtime identity, replacing its record.

Scheduler state remains SSH/SLURM authoritative. The owner-authenticated `/access` endpoint returns the allocation's Jupyter URI and its token. cs-control does not proxy Jupyter, VS Code, or other runtime data and does not read or clean up shared Linkspan token or readiness-manifest files.

The runtime states are `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED`, and `FAILED`. There is one state field: a Slurm word this vocabulary does not cover is treated as no observation rather than a state of its own. Runtime list responses, and the log tails that travel with them, are filtered to the validated owner principal; item and access reads reject a different principal.

Tunnel creation omits `accessControl` and relies on the documented private,
creator-owner default; cs-control never requests anonymous tunnel-wide access. Linkspan only hosts the tunnel cs-control created; it never adds ports or access of its own. cs-control sends
`customExpiration` as walltime plus cleanup grace, floored at one hour and
capped at 30 days. The response must return that exact duration, and its
`created` plus duration must match `expiration` within the documented one-second
serialization tolerance without extending beyond that tolerance. The returned
expiration is persisted. Before Linkspan's host attaches, Create may return no
relay endpoint or port/SSH URI formats. That empty pair remains valid through
submitting, queued, starting, stopping, and terminal states when a job ends
before host attachment. A ready runtime still requires both valid formats, a
control URI, and control service metadata. Management discovery must return and
validate both formats before cs-control derives the control URI, reads the
catalog, or marks the runtime ready. A mismatched or past expiration is rejected and
compensated before credential or runtime state is committed. Any tunnel Create
error is treated as potentially server-side successful and triggers an
idempotent delete of the deterministic tunnel ID before returning.

The local CLI exposes only `serve`, `help`, and `version`. Runtime and SSH operations use the OAuth-authenticated enactment API; delegated tokens are not accepted through CLI arguments.

## SSH connections

The enactment API lists concrete user and system OpenSSH `Host` entries together, and never writes them: hosts come from the configuration the user maintains. Discovery uses fixed argument shapes and bounded framed output, and abandoning the request terminates the remote process group. Interactive authentication may leave a private process-local OpenSSH ControlMaster for later control operations; cs-control does not create runtime port forwards.

## Boundaries

- Global flags precede commands.
- Local state is an atomic mode-`0600` file in a mode-`0700` directory.
- Dev Tunnel connect credentials use mode-`0600` files in a mode-`0700` credential directory.
- SSH commands use fixed argument arrays, bounded output, and timeouts.
- OAuth, host, and connect credentials are never printed, persisted in runtime state, or returned as JSON. The derived Jupyter capability appears only in generated transport and the owner-authenticated access response.
- Runtime data is reached directly through allocation-owned Dev Tunnel endpoints; cs-control is enactment-only.
