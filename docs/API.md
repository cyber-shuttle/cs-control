# API

`csctl serve` exposes one JSON HTTP API and one WebSocket route on an explicit loopback address, `127.0.0.1:8045`
by default. Every path below is relative to that address. There is no other interface: the CLI has no commands
for hosts or runtimes.

## Authentication

Every request except the two device-code routes carries two independent credentials:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer <Dev Tunnels access token>` |
| `X-CyberShuttle-Identity` | the signed Microsoft ID token |

The access token is validated remotely as a Dev Tunnels capability; the ID token is validated
cryptographically and is the only source of caller identity. Exactly one of each header is accepted.

The SSH authentication WebSocket cannot send headers from a browser, so it carries the same two credentials as
subprotocols. A client offers exactly three, in any order:

```
cybershuttle.v1
bearer.<base64url of the access token, unpadded>
identity.<base64url of the ID token, unpadded>
```

The server negotiates `cybershuttle.v1`. Any other set — a missing version, a fourth protocol, a padded or
non-canonical encoding — is refused. No other route accepts subprotocol authentication, and an Upgrade-shaped
request to any other route is not treated as a WebSocket.

## Origins

`serve` requires at least one exact `--allowed-origin`. HTTPS origins and loopback HTTP origins are accepted;
wildcards are not. A request whose `Origin` is not in the list is refused with `403`. A request with no
`Origin` at all — a native client — passes the origin check but still needs both credentials.

When an `Origin` is present the response carries `Access-Control-Allow-Origin`, `Vary: Origin` and
`Access-Control-Expose-Headers: ETag`. Preflight is answered for `GET`, `POST`, `PUT`, `DELETE` and `OPTIONS`
with the request headers `Authorization`, `Content-Type`, `If-None-Match` and `X-CyberShuttle-Identity`; a
preflight asking for anything else is refused with `403`.

## Errors

Every refusal produced by the API or the device broker is this envelope, with `Cache-Control: no-store`:

```json
{ "error": { "code": "runtime_not_found", "message": "runtime not found" } }
```

Refusals produced by the authentication boundary itself are plain text with the status and no envelope:
`401 unauthorized` (missing or invalid credentials), `403 origin is not allowed`, `403 preflight is not
allowed`. A `401` also carries `WWW-Authenticate: Bearer`.

An error the API did not classify becomes `500 internal_error`.

| Code | Status |
| --- | --- |
| `invalid_json`, `invalid_ssh_alias`, `invalid_ssh_command`, `invalid_root_folder`, `invalid_partition`, `invalid_account`, `invalid_gpu`, `invalid_resource`, `invalid_resources`, `invalid_idempotency_key`, `invalid_runtime_id`, `slurm_validation_failed` | 400 |
| `tunnel_authorization_required` | 401 |
| `runtime_owner_mismatch` | 403 |
| `not_found`, `runtime_not_found`, `ssh_host_not_found` | 404 |
| `method_not_allowed` | 405 |
| `runtime_exists`, `runtime_running`, `runtime_not_stopped`, `idempotency_conflict`, `runtime_provisioning_in_progress`, `runtime_access_unavailable`, `ssh_host_exists`, `ssh_host_not_managed`, `ssh_authentication_required`, `ssh_authentication_in_progress` | 409 |
| `upgrade_required` | 426 |
| `internal_error` | 500 |
| `runtime_provisioning_failed` | 502 or 504 |
| `service_stopping`, `ssh_authentication_unavailable` | 503 |

Request bodies are JSON, at most 64 KiB. Unknown fields and trailing data are refused with `invalid_json`.

## SSH hosts

### `GET /api/v1/ssh` → 200

Every host `~/.ssh/config` and `/etc/ssh/ssh_config` resolve to. `managed` marks the entries this API wrote,
which are the only ones it may remove.

```json
{
  "hosts": [
    {
      "name": "delta",
      "hostname": "login.delta.example.edu",
      "user": "alice",
      "port": 22,
      "identityFile": "~/.ssh/id_ed25519",
      "extraDirectives": ["ProxyJump bastion"],
      "managed": true
    }
  ]
}
```

`hostname`, `user`, `port` and `identityFile` are omitted when unset.

### `POST /api/v1/ssh` → 201

The body is the `ssh` command the user already knows works; the server parses it, so the client never composes
configuration text. `name` matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`.

```json
{ "name": "delta", "command": "ssh -i ~/.ssh/id_ed25519 -J bastion alice@login.delta.example.edu" }
```

`-p`, `-i`, `-l`, `-J`, `-o` and one `[user@]host` target are understood. `-o` is limited to an allowlist
covering how a connection authenticates or keeps itself alive; every other option, every other flag, and a
trailing remote command are refused with `invalid_ssh_command`. The response is the resulting host, and an
alias that already exists is `ssh_host_exists`.

### `DELETE /api/v1/ssh/{alias}` → 200

Removes a managed entry. An alias outside the managed block is `ssh_host_not_managed`.

```json
{ "name": "delta", "extraDirectives": null, "managed": false }
```

### `POST /api/v1/ssh/{alias}/test` → 200

Runs one bounded remote command. A host that answers but wants an interactive login is a reportable state, not
a failed call, so `ok` is `false` with a `200`.

```json
{ "host": "delta", "ok": true, "message": "Connected." }
```

### `GET /api/v1/ssh/{alias}/slurm` → 200

Slurm discovery: the accounts the remote user is associated with, the partitions `sinfo` reports, and the
remote home directory. Abandoning the request cancels the remote process group.

```json
{
  "host": "delta",
  "accounts": ["project-a"],
  "partitions": [
    { "name": "gpuA100", "cpuCount": 64, "memoryMb": 243200, "gres": [{ "name": "gpu:a100", "count": 4 }] }
  ],
  "homeDir": "/home/alice"
}
```

A partition appears once per node configuration, so the same name can repeat with different capacities; a
request has to fit at least one of them.

### `GET /api/v1/ssh/{alias}/auth` (WebSocket)

Interactive SSH authentication. It establishes the multiplexed control master every later operation reuses. A
request without an `Upgrade` header is refused with `426 upgrade_required`.

Server to client: binary frames are raw PTY output — untyped bytes, including password and second-factor
prompts. Text frames are JSON:

```json
{ "type": "ready" }
{ "type": "exit", "code": 1, "message": "SSH authentication failed" }
```

`ready` is followed by `exit` with code `0`. Diagnostics from the remote host are never forwarded; `exit`
carries a fixed message.

Client to server: binary frames are keystrokes, at most 32 KiB each. Text frames resize the PTY:

```json
{ "type": "resize", "cols": 100, "rows": 30 }
```

`cols` is honoured between 20 and 500, `rows` between 5 and 200; other values are ignored. Frames are capped at
64 KiB and the server pings every 20 seconds. A second authentication for the same host while one is in flight
is refused with `ssh_authentication_in_progress`.

## Runtimes

`{id}` matches `^rt-[a-f0-9]{12}$`; a path that does not is `404 not_found`.

### `POST /api/v1/runtimes/validate` → 200

Builds the candidate batch script and runs `sbatch --test-only` with it. This is the review step: the script it
returns is byte-identical to the one create submits.

Request:

```json
{
  "idempotencyKey": "5f2b0d0a-3f14-4a9c-9a1e-6c2b0f7d51ab",
  "sshHost": "delta",
  "account": "project-a",
  "partition": "cpu",
  "rootFolder": "$HOME/project",
  "resources": { "cores": 2, "memoryMb": 4096, "wallMinutes": 60, "gpuType": "a100", "gpuCount": 1 }
}
```

`account` is optional and `gpuType`/`gpuCount` are supplied together or not at all. `cores` is 2–4096,
`memoryMb` is 4096–100000000, `wallMinutes` is 1–525600, and the request must fit a discovered partition.
`rootFolder` is a safe absolute, home-relative (`~/x`, `$HOME/x`) or environment-relative (`$VAR/x`) POSIX
path, resolved on the host.

Response:

```json
{
  "runtimeId": "rt-012345abcdef",
  "script": "#!/bin/bash\n#SBATCH --nodes=1\n...",
  "status": "PASSED",
  "message": "Slurm accepted the job script."
}
```

`status` is `PASSED` or `FAILED`. A Slurm rejection is a `FAILED` result with a `200`, not an error; a failed
SSH call is an error. `stdout` and `stderr` are omitted when empty.

### `POST /api/v1/runtimes` → 201

Same request body as validate. Creates the tunnel and credential, persists the record, prepares the login node,
and submits. A repeated request with the same `idempotencyKey` and the same fields returns the existing
runtime; the same key with different fields is `idempotency_conflict`.

The response is one runtime record, which is also the item shape everywhere else:

```json
{
  "id": "rt-012345abcdef",
  "generation": "g-0123456789abcdef",
  "state": "READY",
  "sshHost": "delta",
  "account": "project-a",
  "partition": "cpu",
  "rootFolder": "$HOME/project",
  "resources": { "cores": 2, "memoryMb": 4096, "wallMinutes": 60 },
  "createdAt": "2030-01-01T00:00:00Z",
  "updatedAt": "2030-01-01T00:01:00Z"
}
```

`state` is one of `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED`, `FAILED`. `account` and
`error` are omitted when empty. Owner, tunnel, job ID, job name, node and remote paths are held but never
returned.

### `GET /api/v1/runtimes` → 200 or 304

The one read a client polls. It answers from persisted state and starts a reconciliation for the next poll to
collect, so it never waits on SSH. Runtimes and log tails are both filtered to the caller.

```json
{
  "runtimes": [],
  "logs": [
    {
      "runtimeId": "rt-012345abcdef",
      "lines": [
        { "stream": "status", "text": "Preparing the runtime environment", "at": "2030-01-01T00:00:05Z" },
        { "stream": "stdout", "text": "Installing collected packages", "at": "2030-01-01T00:00:07Z" }
      ]
    }
  ]
}
```

`runtimes` holds runtime records in the shape above.
`stream` is `status` (this daemon's own narration), `stdout` or `stderr` (the allocation's startup output,
replaced by whatever the last read returned). Lines are bounded and redacted. `at` is when the line was first
observed here; an unchanged remote line keeps the time it was first seen.

The response carries a strong `ETag` over the filtered body, so it cannot match across principals. A poll whose
`If-None-Match` matches is answered `304 Not Modified` with no body.

### `GET /api/v1/runtimes/{id}` → 200

One runtime record. A runtime owned by another principal is `runtime_owner_mismatch`.

### `POST /api/v1/runtimes/{id}/start` → 200

Runs a terminal runtime again under the same identity: a new generation, a new tunnel, a new job. A runtime
that is not terminal is `runtime_running`.

### `POST /api/v1/runtimes/{id}/stop` → 200

Marks the runtime `STOPPING`, releases the allocation's tunnel and credential, and asks the scheduler to cancel
the job. The response carries what the scheduler reported.

### `DELETE /api/v1/runtimes/{id}` → 200

Stops the runtime first, then removes the record and its stored credential. A runtime the scheduler has not
released yet is `runtime_not_stopped`; delete it again once it is.

### `GET /api/v1/runtimes/{id}/access` → 200

The only route that returns a secret, and only to the owner of a `READY` runtime. `uri` is the allocation's
direct Jupyter URI over the tunnel and `token` is Jupyter Server's own identity token; `expiresAt` is the live
tunnel expiration, not the value recorded at creation.

```json
{
  "runtimeId": "rt-012345abcdef",
  "generation": "g-0123456789abcdef",
  "expiresAt": "2030-01-01T01:00:00Z",
  "jupyter": { "uri": "https://31001.use.devtunnels.ms", "token": "<43-character token>" }
}
```

A runtime that is not `READY`, has no stored credential, or whose tunnel cannot be reached or has expired is
`runtime_access_unavailable` with the reason in the message.

## Device-code sign-in

The only two routes in front of the authentication boundary. They broker pinned Microsoft device-code requests
for exact allowed browser origins, keep the device code in bounded process memory, enforce polling intervals,
and discard refresh tokens. Both require an allowed `Origin` header and accept `POST` only, with no body and no
query string.

### `POST /api/v1/oauth/device/start` → 200

```json
{
  "handle": "<43-character opaque handle>",
  "userCode": "ABCD-EFGH",
  "verificationUri": "https://microsoft.com/devicelogin",
  "expiresInSeconds": 900,
  "intervalSeconds": 5
}
```

`handle` is this daemon's own reference to the authorization; the device code itself never reaches the client.
More than one start per second per origin is `429 rate_limited`.

### `POST /api/v1/oauth/device/poll/{handle}` → 200 or 202

Still waiting, `202`:

```json
{ "status": "pending", "intervalSeconds": 5 }
```

Complete, `200`:

```json
{ "status": "complete", "accessToken": "...", "idToken": "...", "expiresInSeconds": 3599 }
```

Polling faster than `intervalSeconds` is `429 rate_limited` with `Retry-After`. A denied authorization is
`403 authorization_denied`; an expired one is `410 authorization_expired`. The handle is discarded on any
terminal outcome, so a completed poll cannot be replayed. The two tokens are the pair every other route needs.
