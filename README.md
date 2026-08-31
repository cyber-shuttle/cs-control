# CyberShuttle Control

`csctl` is the per-user SSH/SLURM enactment control plane for CyberShuttle allocations. It stores non-secret scheduler, allocation, and tunnel metadata. Dev Tunnel connect credentials are kept separately in private local credential files and are never returned by the API; the per-generation Jupyter token stored beside them is returned only by the owner-authenticated access endpoint.

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

The only pre-authentication routes are `POST /api/v1/oauth/device/start` and `POST /api/v1/oauth/device/poll/{opaqueHandle}`. They broker pinned Microsoft device-code requests for exact allowed browser origins, retain the device code only in bounded process memory, enforce polling intervals, and discard refresh tokens and terminal state.

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
POST     /api/v1/runtimes/validate
GET      /api/v1/runtimes/{id}
DELETE   /api/v1/runtimes/{id}
POST     /api/v1/runtimes/{id}/start
POST     /api/v1/runtimes/{id}/stop
GET      /api/v1/runtimes/{id}/access
```

The one WebSocket is interactive SSH authentication, whose prompts are untyped
bytes. It never forwards runtime data.

## Runtime lifecycle

Before submission cs-control performs SSH discovery and `sbatch --test-only`,
provisions uv and Linkspan, installs the workflow the allocation runs, creates a
principal-owned Dev Tunnel, durably records the allocation generation and connect
credential, and submits.

`GET /api/v1/runtimes` is the read a browser polls: it answers from persisted
state, starts a reconciliation for the next poll to collect, and carries the
caller's runtimes and their startup tails. It carries a strong `ETag`, so a poll
whose `If-None-Match` still matches is answered `304 Not Modified` with no body.

Scheduler state remains SSH/SLURM authoritative. The owner-authenticated `/access` endpoint returns the allocation's Jupyter URI and its token. cs-control does not proxy Jupyter, VS Code, or other runtime data.

The runtime states are `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED`, and `FAILED`. There is one state field: a Slurm word this vocabulary does not cover is treated as no observation rather than a state of its own. Runtime list responses, and the log tails that travel with them, are filtered to the validated owner principal; item and access reads reject a different principal.

Invariants and trust boundaries: see CLAUDE.md.
