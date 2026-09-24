# API

`cs serve` answers on its loopback address (default `127.0.0.1:8045`). Paths are relative to that address.

| Route | Methods |
| --- | --- |
| `/api/v1/hosts` | `GET`, `POST` |
| `/api/v1/hosts/{alias}` | `PUT`, `DELETE` |
| `/api/v1/hosts/{alias}/health` | `GET` |
| `/api/v1/hosts/{alias}/slurm` | `GET` |
| `/api/v1/hosts/{alias}/ssh` (WebSocket) | `GET` |
| `/api/v1/keys/ssh` | `GET`, `POST` |
| `/api/v1/keys/ssh/{id}` | `DELETE` |
| `/api/v1/oauth/config` | `GET` |
| `/api/v1/oauth/device` | `POST` |
| `/api/v1/oauth/device/poll` | `POST` |
| `/api/v1/oauth/exchange` | `POST` |
| `/api/v1/oauth/refresh` | `POST` |
| `/api/v1/sessions` | `GET`, `POST` |
| `/api/v1/sessions/validate` | `POST` |
| `/api/v1/sessions/{id}` | `GET`, `DELETE` |
| `/api/v1/sessions/{id}/access` | `GET` |
| `/api/v1/sessions/{id}/metrics` | `GET` |
| `/api/v1/sessions/{id}/runs` | `POST` |
| `/api/v1/sessions/{id}/start` | `POST` |
| `/api/v1/sessions/{id}/stop` | `POST` |
| `/api/v1/telemetry` | `GET` |
| `/api/v1/tunnel` | `GET`, `DELETE` |
| `/api/v1/tunnel/authorizations` | `POST` |
| `/api/v1/tunnel/authorizations/{handle}/poll` | `POST` |

| Convention | Answer |
| --- | --- |
| Created host, key or session | `201` with `Location` |
| Successful `DELETE` | `204`, no body |
| Unknown path | `404 not_found` |
| Method the path lacks | `405 method_not_allowed` with `Allow` |
| Request body | JSON, at most 64 KiB; unknown fields or trailing data are `400 invalid_json` |
| JSON response | `Cache-Control: no-store` |

## Authentication

Every route except the sign-in routes requires:

```
Authorization: Bearer <OIDC ID token>
```

The token is validated against the issuer's discovery document and JWKS, with exact issuer and the audience pinned to
the client ID. The principal is the user id Custos returns for `GET {custos-url}/me` with the same bearer, under
tenant `custos`, cached five minutes per token. A token Custos answers `401` for is `401 identity_not_linked`; any
other failure is `401 unauthorized` with `WWW-Authenticate: Bearer`.

The SSH authentication WebSocket carries the credential as exactly two subprotocols, in any order, and negotiates
`cybershuttle.v1`:

```
cybershuttle.v1
bearer.<unpadded base64url of the ID token>
```

Any other protocol set is `400 invalid_websocket_auth`; a missing, oversized or non-canonical token is `401`. No
other bearer route accepts subprotocol authentication.

## Origins

`--allowed-origin` lists exact HTTPS or loopback HTTP origins. On every route, including the SSH authentication WebSocket, a
present `Origin` outside the list is `403 origin_not_allowed`; a request without `Origin` is a native
client. `oauth/config` and `oauth/exchange` refuse a missing `Origin` with `403 origin_required`.

An allowed `Origin` gets `Access-Control-Allow-Origin`, `Vary: Origin` and `Access-Control-Expose-Headers: ETag,
Location`. A preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) is answered `204` with the path's
methods from the route table. It may request `Authorization`, `Content-Type` and
`If-None-Match`, or only `Content-Type` on sign-in routes; anything else is `403 preflight_not_allowed`.

## Errors

Every refusal is this envelope:

```json
{ "error": { "code": "session_not_found", "message": "session not found" } }
```

An unclassified failure is `500 internal_error`, its
detail logged, not returned.

| Code | Status |
| --- | --- |
| `invalid_json`, `invalid_websocket_auth`, `invalid_ssh_alias`, `invalid_ssh_command`, `invalid_ssh_key_id`, `invalid_ssh_key`, `invalid_root_folder`, `invalid_partition`, `invalid_account`, `invalid_gpu`, `invalid_resource`, `invalid_resources`, `invalid_idempotency_key`, `invalid_session_id`, `slurm_validation_failed`, `invalid_grant`, `unknown_provider`, `invalid_runs` | 400 |
| `unauthorized`, `identity_not_linked` | 401 |
| `session_owner_mismatch`, `origin_required`, `origin_not_allowed`, `preflight_not_allowed`, `authorization_denied` | 403 |
| `not_found`, `session_not_found`, `ssh_host_not_found`, `ssh_key_not_found` | 404 |
| `method_not_allowed` | 405 |
| `session_running`, `session_not_stopped`, `session_has_history`, `idempotency_conflict`, `session_provisioning_in_progress`, `session_access_unavailable`, `ssh_host_exists`, `ssh_key_exists`, `ssh_authentication_required`, `ssh_authentication_in_progress`, `tunnel_link_required` | 409 |
| `authorization_expired` | 410 |
| `upgrade_required` | 426 |
| `rate_limited` | 429 |
| `internal_error` | 500 |
| `session_provisioning_failed` | 502, or 504 on timeout |
| `slurm_discovery_failed`, `upstream_unavailable`, `upstream_invalid`, `upstream_failure` | 502 |
| `service_stopping`, `broker_capacity` | 503 |

## Hosts

Hosts are per caller: one caller's aliases are invisible to another, and two callers may reuse an alias.

### `GET /api/v1/hosts` → 200

```json
{
  "hosts": [
    {
      "name": "delta",
      "hostname": "login.delta.example.edu",
      "user": "alice",
      "port": 22,
      "keyId": "delta-key",
      "extraDirectives": ["ProxyJump bastion"],
      "managed": true
    }
  ]
}
```

`user` and `keyId` are omitted when unset. `managed` is always `true`. A host with `keyId` signs in with that key
only (`IdentitiesOnly yes`); the key's path is never returned.

### `POST /api/v1/hosts` → 201

```json
{ "name": "delta", "command": "ssh -J bastion alice@login.delta.example.edu", "keyId": "delta-key" }
```

`name` matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`. `command` is an `ssh` command line the server parses:
`-p`, `-l`, `-J`, allowlisted `-o` options and one `[user@]host`. Anything else, including `-i`, identity options and
a remote command, is `invalid_ssh_command`. `keyId` is optional and must name a stored key (`ssh_key_not_found`). An
existing alias is `ssh_host_exists`. The answer is the host.

### `PUT /api/v1/hosts/{alias}` → 200

```json
{ "command": "ssh -p 2222 -J bastion alice@login2.delta.example.edu", "keyId": "delta-key" }
```

Replaces the host under the same alias, parsed as `POST`; an absent `keyId` unassigns the key. The answer is the
host. An unknown alias is `ssh_host_not_found`.

### `DELETE /api/v1/hosts/{alias}` → 204

An unknown alias is `ssh_host_not_found`.

### `GET /api/v1/hosts/{alias}/health` → 200

```json
{ "host": "delta", "ok": true, "message": "Listening at login.delta.example.edu:22." }
```

Opens a TCP connection, without signing in, to the first hop: the alias's host and port, or its first `ProxyJump`
host, followed through further jumps. Only public addresses are dialed; a closed port or a loopback, private or
link-local address is `ok: false` with `200`. An unknown alias is `404 ssh_host_not_found`.

### `GET /api/v1/hosts/{alias}/slurm` → 200

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

The remote user's Slurm accounts, `sinfo` partitions and home directory. A partition appears once per node
configuration, so a name can repeat; a session must fit one entry. Abandoning the request cancels the remote process
group.

### `GET /api/v1/hosts/{alias}/ssh` (WebSocket)

Interactive SSH authentication that establishes the control master later operations reuse. A request without
`Upgrade` is `426 upgrade_required`; a second authentication in flight for the host is
`ssh_authentication_in_progress`.

| Direction | Binary frames | Text frames |
| --- | --- | --- |
| Server to client | raw PTY output, including password and second-factor prompts | `{ "type": "ready" }` then `exit` code 0 on success; `{ "type": "exit", "code": 1, "message": "..." }` on failure |
| Client to server | keystrokes, at most 32 KiB each | `{ "type": "resize", "cols": 100, "rows": 30 }` |

`exit` carries a fixed message, never remote diagnostics. Resize honours `cols` 20 to 500 and `rows` 5 to 200 and
ignores other values. Frames are capped at 64 KiB; the server pings every 20 seconds.

## SSH keys

Keys are per caller, stored at mode `0600` and never returned. Passphrase-protected keys are accepted; the
passphrase is asked for during SSH authentication.

### `GET /api/v1/keys/ssh` → 200

```json
{ "keys": [{ "id": "delta-key", "type": "ssh-ed25519", "fingerprint": "SHA256:..." }] }
```

### `POST /api/v1/keys/ssh` → 201

```json
{ "id": "delta-key", "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n..." }
```

Answers the key's metadata. `id` matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` and does not end in `.pub`
(`invalid_ssh_key_id`). Bytes that are not a private key are `invalid_ssh_key`; an existing id is `ssh_key_exists`.

### `DELETE /api/v1/keys/ssh/{id}` → 204

Removes the key and unassigns it from every host. An unknown id is `ssh_key_not_found`.

## Sign-in

These routes finish CILogon's authorization-code flow with PKCE for browsers and the device grant for other clients,
adding the client secret only cs-plane holds. They need no bearer. `config` and `exchange` require an allowed
`Origin`. Upstream failures are `502 upstream_unavailable` or `502 upstream_invalid`.

### `GET /api/v1/oauth/config` → 200

```json
{
  "issuer": "https://cilogon.org",
  "authorizationEndpoint": "https://cilogon.org/authorize",
  "clientId": "cilogon:/client_id/...",
  "scope": "openid email profile offline_access"
}
```

The browser sends the user to `authorizationEndpoint` with `response_type=code`, `clientId`, `scope`, a
`redirect_uri` on an allowed origin, a `state` and an S256 `code_challenge`.

### `POST /api/v1/oauth/exchange` → 200

```json
{ "code": "...", "codeVerifier": "...", "redirectUri": "https://jupyter.cybershuttle.org/lab/index.html" }
```

```json
{ "idToken": "...", "refreshToken": "...", "expiresInSeconds": 900 }
```

`refreshToken` is present when the issuer granted `offline_access`. A missing field, a `redirectUri` off the allowed
origins, or a rejected code is `400 invalid_grant`.

### `POST /api/v1/oauth/refresh` → 200

```json
{ "refreshToken": "..." }
```

Answers `exchange`'s shape, with a rotated `refreshToken` when the issuer rotates it. An empty token is
`invalid_json`; a refused one is `400 invalid_grant`.

### `POST /api/v1/oauth/device` → 200

No body. Answers `{ "deviceCode", "userCode", "verificationUriComplete", "intervalSeconds" }`; the client opens
`verificationUriComplete` and polls `device/poll` every `intervalSeconds`.

### `POST /api/v1/oauth/device/poll` → 200

```json
{ "deviceCode": "..." }
```

| Outcome | Answer |
| --- | --- |
| Not yet approved | `{ "status": "pending", "intervalSeconds": 5 }` |
| Approved | `{ "status": "complete", "idToken": "...", "refreshToken": "...", "expiresInSeconds": 900 }` |

A missing `deviceCode` is `invalid_json`; a denied or expired grant is `400 invalid_grant`.

## Sessions

An unknown `{id}` is `404 session_not_found`; another principal's is `403 session_owner_mismatch`.

| Step | Route |
| --- | --- |
| Check a request | `POST /api/v1/sessions/validate` |
| Record a session | `POST /api/v1/sessions` |
| Run it | `POST /api/v1/sessions/{id}/start` |
| Reach it | `GET /api/v1/sessions/{id}/access`, then Jupyter over the session's Dev Tunnel |
| End the run | `POST /api/v1/sessions/{id}/stop` |
| Drop the record | `DELETE /api/v1/sessions/{id}` |

### Session record

```json
{
  "id": "s-012345abcdef",
  "seq": 1,
  "state": "READY",
  "sshHost": "delta",
  "account": "project-a",
  "partition": "cpu",
  "rootFolder": "$HOME/project",
  "resources": { "cores": 2, "memoryMb": 4096, "wallMinutes": 60 },
  "createdAt": "2030-01-01T00:00:00Z",
  "startedAt": "2030-01-01T00:00:30Z",
  "updatedAt": "2030-01-01T00:01:00Z"
}
```

| Field | Meaning |
| --- | --- |
| `seq` | 0 until the first `start`, then the run currently serving the session; each `start` increments it |
| `state` | `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED` or `FAILED` |
| `startedAt` | when Slurm first reported the job running; absent before that. With `wallMinutes` it gives the deadline |
| `account`, `error` | omitted when empty |

`READY` means the job is running and its Linkspan has written to its log.

### `POST /api/v1/sessions/validate` → 200

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

| Field | Rule |
| --- | --- |
| `idempotencyKey` | required, at most 128 bytes, no NUL, CR or LF |
| `account` | optional; must be one discovery reports |
| `cores` | 2 to 4096 |
| `memoryMb` | 4096 to 100000000 |
| `wallMinutes` | 1 to 525600 |
| `gpuType`, `gpuCount` | together or not at all |
| `rootFolder` | absolute, home-relative (`x`, `.`, `~/x`, `$HOME/x`) or `$VAR/x`, resolved on the host |

The request must fit a discovered partition.

```json
{
  "sessionId": "s-012345abcdef",
  "script": "#!/bin/bash\n#SBATCH --nodes=1\n...",
  "status": "PASSED",
  "message": "Slurm accepted the job script."
}
```

Runs `sbatch --test-only` on the script `start` would submit, which differs only in its log path (seq `0` here).
A Slurm rejection is `status: "FAILED"` with `200`; a failed SSH call is an error. `stdout` and `stderr` are omitted
when empty.

### `POST /api/v1/sessions` → 201 or 200

Takes `validate`'s body, checked for shape only, and records a `STOPPED` session at seq 0 without launching it. The
ID derives from the caller and `idempotencyKey`: a new session is `201` with `Location`, a replay with the same
fields is `200`, and the same key with different fields is `idempotency_conflict`. Answers the session record.

### `GET /api/v1/sessions` → 200 or 304

```json
{
  "sessions": [],
  "logs": [
    {
      "sessionId": "s-012345abcdef",
      "lines": [
        { "stream": "status", "text": "Preparing the session environment", "at": "2030-01-01T00:00:05Z" },
        { "stream": "stdout", "text": "Installing collected packages", "at": "2030-01-01T00:00:07Z" }
      ]
    }
  ]
}
```

The caller's session records and log tails, from persisted state; it never waits on SSH. `stream` is `status`
(cs-plane's narration), `stdout` or `stderr` (the job's startup output). Lines are bounded and redacted; `at` is when
cs-plane first saw the line. A tail moves to telemetry when its run ends. The response carries a strong `ETag`;
`If-None-Match` accepts `*`, lists and weak validators, and a match is `304` with no body.

### `GET /api/v1/sessions/{id}` → 200

The session record.

### `POST /api/v1/sessions/{id}/start` → 200

Launches through Slurm. Validates the session against the host as `validate` does, then takes the next seq, a new
Dev Tunnel, a new capability and a new job. Answers the session record.

| Refusal | Code |
| --- | --- |
| Session not terminal, including one another `start` is launching | `409 session_running` |
| No Dev Tunnels account linked | `409 tunnel_link_required` |
| Slurm rejects the script | `400 slurm_validation_failed` |
| Another launch is preparing the same host for this caller | `409 session_provisioning_in_progress` |
| Login-node preparation fails | `502` or `504 session_provisioning_failed` |

A conclusive submission failure leaves the session `FAILED` at the new seq.

### `POST /api/v1/sessions/{id}/stop` → 200

Marks the session `STOPPING`, releases its tunnel and capability, and asks Slurm to cancel the job. Answers the
session record; stopping a terminal session answers it unchanged.

### `DELETE /api/v1/sessions/{id}` → 204

Removes a terminal session's record and capability; its runs stay in telemetry. A session that is not terminal is
`409 session_not_stopped`.

### `POST /api/v1/sessions/{id}/runs` → 200

```json
{
  "createdAt": "2026-09-10T04:22:00Z",
  "runs": [
    { "finalState": "STOPPED", "startedAt": "2026-09-10T04:23:00Z", "endedAt": "2026-09-10T04:26:06Z",
      "stats": { "cpuEfficiencyPct": 9.76, "memoryEfficiencyPct": 47.34 },
      "samples": [{ "at": "2026-09-10T04:24:24Z", "memBytes": 84418560, "cpuUsageUsec": 4669597 }] }
  ]
}
```

Adopts runs another client finished, oldest first, into a session at seq 0 with no runs. Each run joins telemetry
under seq 1, 2, and so on. Answers the session record with `seq` equal to the run count, the last run's state,
`error` and `startedAt`, and `createdAt` from the body when given.

| Refusal | Code |
| --- | --- |
| No runs, more than 50, a `finalState` other than `STOPPED` or `FAILED`, no `endedAt`, or more than 20 samples | `400 invalid_runs` |
| Session has run or already adopted a history | `409 session_has_history` |

### `GET /api/v1/sessions/{id}/access` → 200

```json
{
  "sessionId": "s-012345abcdef",
  "seq": 1,
  "expiresAt": "2030-01-01T01:00:00Z",
  "jupyter": {
    "uri": "https://31001.use.devtunnels.ms",
    "token": "<43-character token>"
  }
}
```

The only session route that returns a secret. `uri` is the session's Jupyter URI over its Dev Tunnel, `token` is
Jupyter Server's token, and `expiresAt` is the live tunnel expiration. A session that is not `READY`, has no stored
capability, or whose tunnel cannot be reached or has expired is `409 session_access_unavailable`, with the reason in
the message.

### `GET /api/v1/sessions/{id}/metrics` → 200

```json
{
  "sessionId": "s-012345abcdef",
  "samples": [
    {
      "at": "2030-01-01T00:05:00Z",
      "memBytes": 2147483648,
      "cpuUsageUsec": 295339339,
      "gpus": [{ "index": 0, "utilPct": 40, "memUsedMiB": 1024, "memTotalMiB": 40960 }]
    }
  ]
}
```

Up to the last 20 samples, taken from Linkspan over the session's Dev Tunnel every five seconds while the session is
`READY`; possibly empty.
Every figure is optional: an unreadable counter is absent, not zero. `at` is when cs-plane took the sample, so
consecutive `cpuUsageUsec` values give a rate.

## Telemetry

### `GET /api/v1/telemetry` → 200

```json
{
  "runs": [
    {
      "sessionId": "s-012345abcdef",
      "seq": 1,
      "sshHost": "delta",
      "partition": "cpu",
      "rootFolder": "$HOME/project",
      "resources": { "cores": 2, "memoryMb": 4096, "wallMinutes": 60 },
      "finalState": "STOPPED",
      "startedAt": "2030-01-01T00:00:30Z",
      "endedAt": "2030-01-01T01:00:30Z",
      "stats": {
        "cores": 2,
        "requestedMemory": "4.0 GB",
        "elapsedSeconds": 3600,
        "maxRss": "2.0 GB",
        "cpuEfficiencyPct": 50,
        "memoryEfficiencyPct": 50
      },
      "logs": [
        { "stream": "status", "text": "Session is running", "at": "2030-01-01T00:00:05Z" }
      ]
    }
  ]
}
```

The caller's finished runs, newest first, one per `(sessionId, seq)`; they survive relaunch and delete of the
session. cs-plane keeps the newest 200 runs across all callers. Each run is frozen when it ends with its log tail
(`logs`) and last metric samples (`samples`). `stats` is Slurm accounting, absent until it lands; cs-plane retries
for ten minutes after the run ends. `account`, `error`, `startedAt`, `stats`, `samples` and `logs` are omitted when
empty.

## Dev Tunnels link

A Microsoft or GitHub account, required before a session starts, that gives each run its own Dev Tunnel. The credential is stored sealed under the caller's principal and never returned. These routes need the
bearer.

### `GET /api/v1/tunnel` → 200

```json
{ "linked": true, "provider": "github", "account": "octocat", "linkedAt": "2026-09-17T10:00:00Z" }
```

`{ "linked": false }` when nothing is linked. `provider` is `microsoft` or `github`; `account` is the Microsoft
username or GitHub login when known.

### `DELETE /api/v1/tunnel` → 204

Forgets the linked credential; idempotent.

### `POST /api/v1/tunnel/authorizations` → 200

```json
{ "provider": "github" }
```

```json
{
  "handle": "<43-character opaque handle>",
  "userCode": "ABCD-EFGH",
  "verificationUri": "https://github.com/login/device",
  "expiresInSeconds": 900,
  "intervalSeconds": 5
}
```

Starts a device-code authorization with the provider's Dev Tunnels client (`microsoft` through the common Microsoft
authority, or `github`). `handle` is cs-plane's reference; the device code never reaches the client.

| Refusal | Code |
| --- | --- |
| Other provider | `400 unknown_provider` |
| More than one start per second per caller | `429 rate_limited` |
| Too many pending authorizations | `503 broker_capacity` |

### `POST /api/v1/tunnel/authorizations/{handle}/poll` → 200

| Outcome | Answer |
| --- | --- |
| Pending | `{ "status": "pending", "intervalSeconds": 5, "linked": false }` |
| Linked | `{ "status": "linked", "linked": true, "provider": "microsoft", "account": "someone@outlook.com", "linkedAt": "..." }` |

| Refusal | Code |
| --- | --- |
| Unknown handle, or another caller's | `404 not_found` |
| Poll sooner than `intervalSeconds` | `429 rate_limited` |
| Denied | `403 authorization_denied` |
| Expired | `410 authorization_expired` |

The handle is discarded on any terminal outcome; a failed credential refresh is `502 upstream_unavailable`.
