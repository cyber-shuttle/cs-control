# API

`csctl serve` exposes one JSON HTTP API and one WebSocket route on an explicit loopback address,
`127.0.0.1:8045` by default. Every path below is relative to that address. There is no other interface: the CLI
has no commands for keys, hosts, or sessions.

| Method | Route |
| --- | --- |
| `GET` | `/api/v1/oauth/config` |
| `POST` | `/api/v1/oauth/exchange`, `/api/v1/oauth/refresh`, `/api/v1/oauth/device` |
| `GET`, `POST` | `/api/v1/ssh/hosts`, `/api/v1/ssh/keys` |
| `PUT`, `DELETE` | `/api/v1/ssh/hosts/{alias}` |
| `DELETE` | `/api/v1/ssh/keys/{name}` |
| `POST` | `/api/v1/ssh/hosts/{alias}/test` |
| `GET` | `/api/v1/ssh/hosts/{alias}/auth` (WebSocket), `/api/v1/ssh/hosts/{alias}/slurm` |
| `GET`, `DELETE` | `/api/v1/tunnel` |
| `POST` | `/api/v1/tunnel/authorizations`, `/api/v1/tunnel/authorizations/{handle}/poll` |
| `GET`, `POST` | `/api/v1/sessions` |
| `POST` | `/api/v1/sessions/validate` |
| `GET` | `/api/v1/sessions/{id}`, `/api/v1/sessions/{id}/access`, `/api/v1/sessions/{id}/metrics` |
| `POST` | `/api/v1/sessions/{id}/start`, `/api/v1/sessions/{id}/stop` |
| `DELETE` | `/api/v1/sessions/{id}` |
| `GET` | `/api/v1/telemetry` |

Every `OPTIONS` preflight is answered from this table: an unknown path is `404`, a method the path lacks is
`405` with `Allow`, and a disallowed origin or request header is `403`. A successful `DELETE` is `204` with no
body. A created host, key or session is `201` with a `Location` header naming it.

## Authentication

Every request except the sign-in routes carries one credential:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer <CILogon ID token>` |

The token is validated cryptographically against the configured issuer's discovery document and JWKS. The
discovered issuer must match exactly, and the audience is pinned to the configured client id. The caller's
identity is then the Custos user the token resolves to: the daemon calls `GET <custos>/me` with the same bearer and takes the
returned user id as the principal, under the tenant `custos`. The result is held five minutes per token. A
token Custos does not recognise is refused with `401 identity_not_linked`; any other failure is `401`.

The SSH authentication WebSocket cannot send headers from a browser, so it carries the same credential as a
subprotocol. A client offers exactly two, in any order:

```
cybershuttle.v1
bearer.<base64url of the ID token, unpadded>
```

The server negotiates `cybershuttle.v1`. Any other set — a missing version, a third protocol, a padded or
non-canonical encoding — is refused. No other route accepts subprotocol authentication, and an Upgrade-shaped
request to any other route is not treated as a WebSocket.

## Origins

`serve` requires at least one exact `--allowed-origin`. HTTPS origins and loopback HTTP origins are accepted;
wildcards are not. A request whose `Origin` is not in the list is refused with `403`. A request with no
`Origin` at all — a native client — passes the origin check but still needs its bearer credential.

When an `Origin` is present the response carries `Access-Control-Allow-Origin`, `Vary: Origin` and
`Access-Control-Expose-Headers: ETag, Location`. Preflight is answered for `GET`, `POST`, `PUT`, `DELETE` and `OPTIONS`
with the request headers `Authorization`, `Content-Type` and `If-None-Match`; a
preflight asking for anything else is refused with `403`.

## Errors

Every refusal, including those of the authentication boundary, is this envelope with `Cache-Control: no-store`:

```json
{ "error": { "code": "session_not_found", "message": "session not found" } }
```

Missing or invalid credentials are `401 unauthorized` with `WWW-Authenticate: Bearer`; a malformed or
incomplete `Sec-WebSocket-Protocol` negotiation is `400 invalid_websocket_auth`.

An error the API did not classify becomes `500 internal_error`.

| Code | Status |
| --- | --- |
| `invalid_json`, `invalid_websocket_auth`, `invalid_ssh_alias`, `invalid_ssh_command`, `invalid_ssh_key_name`, `invalid_ssh_key`, `invalid_root_folder`, `invalid_partition`, `invalid_account`, `invalid_gpu`, `invalid_resource`, `invalid_resources`, `invalid_idempotency_key`, `invalid_session_id`, `slurm_validation_failed`, `invalid_grant`, `authorization_pending`, `unknown_provider` | 400 |
| `unauthorized`, `identity_not_linked` | 401 |
| `session_owner_mismatch`, `origin_required`, `origin_not_allowed`, `preflight_not_allowed`, `authorization_denied` | 403 |
| `not_found`, `session_not_found`, `ssh_host_not_found`, `ssh_key_not_found` | 404 |
| `method_not_allowed` | 405 |
| `session_exists`, `session_running`, `session_not_stopped`, `idempotency_conflict`, `session_provisioning_in_progress`, `session_access_unavailable`, `ssh_host_exists`, `ssh_key_exists`, `ssh_authentication_required`, `ssh_authentication_in_progress`, `tunnel_link_required` | 409 |
| `authorization_expired` | 410 |
| `upgrade_required` | 426 |
| `rate_limited` | 429 |
| `internal_error` | 500 |
| `session_provisioning_failed` | 502 or 504 |
| `slurm_discovery_failed`, `upstream_unavailable`, `upstream_invalid`, `upstream_failure` | 502 |
| `service_stopping`, `broker_capacity` | 503 |

Request bodies are JSON, at most 64 KiB. Unknown fields and trailing data are refused with `invalid_json`.

## SSH hosts

### `GET /api/v1/ssh/hosts` → 200

The caller's own hosts, and only those. Each principal has a private configuration this API writes; the
account the daemon runs as has none of its own standing here, and one caller's aliases are invisible to
another. `managed` marks the entries this API wrote, which are the only ones it may change.

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

`hostname`, `user`, `port`, `identityFile` and `key` are omitted when unset. `key` names a stored login key
(below) the host is assigned; its `identityFile` is then that key's path and `extraDirectives` carries
`IdentitiesOnly yes`.

### `POST /api/v1/ssh/hosts` → 201

The body is the `ssh` command the user already knows works; the server parses it, so the client never composes
configuration text. `name` matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`.

```json
{ "name": "delta", "command": "ssh -J bastion alice@login.delta.example.edu", "key": "delta-key" }
```

`key` is optional: the name of a stored login key to use for this host, which replaces any `-i` in the
command. A name that is not stored is `ssh_key_not_found`.

The alias is the caller's own, so a name another principal already uses is free. `-p`, `-i`, `-l`, `-J`, `-o`
and one `[user@]host` target are understood. `-o` is limited to an allowlist
covering how a connection authenticates or keeps itself alive; every other option, every other flag, and a
trailing remote command are refused with `invalid_ssh_command`. The response is the resulting host, and an
alias that already exists is `ssh_host_exists`.

### `PUT /api/v1/ssh/hosts/{alias}` → 200

Replaces a managed entry with what the command now says, so a login whose host, port, user or jump
changed is corrected without losing its alias. The body is the same pasted command `POST` takes, and it
is parsed by the same rules; the alias comes from the path, so an edit cannot rename what it edits.

```json
{ "command": "ssh -p 2222 -J bastion alice@login2.delta.example.edu", "key": "delta-key" }
```

`key` is as on `POST`; an empty or absent `key` unassigns the one the host had. The response is the resulting
host. An alias that is not configured is `ssh_host_not_found`.

### `DELETE /api/v1/ssh/hosts/{alias}` → 204

Removes an entry. An alias that is not configured is `ssh_host_not_found`.

### `POST /api/v1/ssh/hosts/{alias}/test` → 200

Runs one bounded remote command. A host that answers but wants an interactive login is a reportable state, not a
failed call, so `ok` is `false` with a `200`. Failure messages are fixed; SSH output is never returned.

```json
{ "host": "delta", "ok": true, "message": "Connected." }
```

### `GET /api/v1/ssh/hosts/{alias}/slurm` → 200

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

## SSH keys

A stored key is held under the caller's hosts directory at mode `0600` and assigned to hosts by name. Reads
return type and fingerprint but never private bytes. Passphrase-protected keys are accepted; the passphrase is
asked for during SSH authentication.

### `GET /api/v1/ssh/keys` → 200

```json
{ "keys": [{ "name": "delta-key", "type": "ssh-ed25519", "fingerprint": "SHA256:..." }] }
```

### `POST /api/v1/ssh/keys` → 201

```json
{ "name": "delta-key", "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n..." }
```

Creates a key and returns its metadata without `privateKey`. An existing name is `409 ssh_key_exists`. The
private file is staged before its metadata is committed; startup promotes only a stage matching that metadata.
Names match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, do not end in `.pub`, and invalid key bytes are
`invalid_ssh_key`.

### `DELETE /api/v1/ssh/keys/{name}` → 204

Removes the key and unassigns it from every host that referenced it. The
file deletion, metadata deletion, host-reference changes, and rendered config replacement are one compensated
flow. A name that is not stored is `ssh_key_not_found`.

### `GET /api/v1/ssh/hosts/{alias}/auth` (WebSocket)

Interactive SSH authentication establishes the multiplexed control master every later operation reuses. A request
without an `Upgrade` header is refused with `426 upgrade_required`.

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

## Sessions

`{id}` matches `^s-[a-f0-9]{12}$`; a path that does not is `404 not_found`.

### `POST /api/v1/sessions/validate` → 200

Builds the candidate batch script and runs `sbatch --test-only` with it. This is the review step: the script it
returns is identical to the one create submits, except for the log redirect. No seq exists yet at
validation time, so the returned script's log path carries a placeholder seq of `0`; create rebuilds the script
with the real seq once one is assigned, before submitting it.

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
`rootFolder` is a safe POSIX path: absolute, relative to the home (`x`, `.`, `~/x`, `$HOME/x`) or under
another variable (`$VAR/x`), resolved on the host.

Response:

```json
{
  "sessionId": "s-012345abcdef",
  "script": "#!/bin/bash\n#SBATCH --nodes=1\n...",
  "status": "PASSED",
  "message": "Slurm accepted the job script."
}
```

`status` is `PASSED` or `FAILED`. A Slurm rejection is a `FAILED` result with a `200`, not an error; a failed
SSH call is an error. `stdout` and `stderr` are omitted when empty.

### `POST /api/v1/sessions` → 201

Same request body as validate. Creates the tunnel and its capability, persists the record, prepares the login node,
and submits. A new session is `201` with `Location: /api/v1/sessions/{id}`. A repeated request with the same
`idempotencyKey` and the same fields returns the existing session as `200`; the same key with different fields
is `idempotency_conflict`.

The response is one session record, which is also the item shape everywhere else:

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

`id` names the session, the durable record; `seq` names the Slurm job currently serving it. A session
outlives its jobs -- `start` takes the next seq under the same `id` -- so `seq` is what ties this
record to one particular run.

`state` is one of `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED`, `FAILED`; `READY` means
the job is running and its Linkspan has started writing its log. `account` and
`error` are omitted when empty. `startedAt` is when Slurm was first seen running the session, taken from
the scheduler's own elapsed figure rather than from a poll, and is absent until it starts: with
`resources.wallMinutes` it is the deadline a client counts down to, so a queue wait is never mistaken for one. Owner, tunnel, job ID, job name, node and remote paths are held but never
returned.

### `GET /api/v1/sessions` → 200 or 304

The one read a client polls. It answers from persisted state, which a background reconciler keeps current, so it
never waits on SSH. Sessions and log tails are both filtered to the caller. `If-None-Match` accepts `*`, a list,
and weak validators; a match is `304` with no body.

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

`sessions` holds session records in the shape above.
`stream` is `status` (this daemon's own narration), `stdout` or `stderr` (the session's startup output,
replaced by whatever the last read returned). Lines are bounded and redacted. `at` is when the line was first
observed here; an unchanged remote line keeps the time it was first seen.

The response carries a strong `ETag` over the filtered body, so it cannot match across principals. A poll whose
`If-None-Match` matches is answered `304 Not Modified` with no body.

### `GET /api/v1/sessions/{id}` → 200

One session record. A session owned by another principal is `session_owner_mismatch`.

### `POST /api/v1/sessions/{id}/start` → 200

Runs a terminal session again under the same identity: the next seq, a new tunnel, a new job. A session
that is not terminal is `session_running`.

### `POST /api/v1/sessions/{id}/stop` → 200

Marks the session `STOPPING`, releases the session's tunnel and capability, and asks the scheduler to cancel
the job. The response is the session record.

### `DELETE /api/v1/sessions/{id}` → 204

Removes a terminal session's record and its stored capability. A session that is not terminal is
`409 session_not_stopped`: stop it, then delete it once the scheduler has released the job. Runs the session
accumulated stay in telemetry.

### `GET /api/v1/sessions/{id}/access` → 200

The only route that returns a secret, and only to the owner of a `READY` session. `uri` is the session's
direct Jupyter URI over the tunnel and `token` is Jupyter Server's own identity token; `expiresAt` is the live
tunnel expiration, not the value recorded at creation.

```json
{
  "sessionId": "s-012345abcdef",
  "seq": 1,
  "expiresAt": "2030-01-01T01:00:00Z",
  "jupyter": { "uri": "https://31001.use.devtunnels.ms", "token": "<43-character token>" }
}
```

A session that is not `READY`, has no stored capability, or whose tunnel cannot be reached or has expired is
`session_access_unavailable` with the reason in the message.

### `GET /api/v1/sessions/{id}/metrics` → 200

What the session is using now, as Linkspan on the compute node reports it over the control port of the
session's own tunnel. Samples are bounded, process-local and five seconds apart; the window holds the last
twenty. They are deliberately not part of the poll above: they change every tick, and folding them in would
defeat its `ETag` for exactly the sessions that have any.

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

Every figure is optional: a host with no GPUs reports none, and a cgroup file that cannot be read is absent
rather than zero, which for a cumulative counter is a different claim. `at` is when the sample was observed
here, so consecutive samples differentiate `cpuUsageUsec` into a rate. A session that is not running answers
with an empty window rather than an error.

## Telemetry

### `GET /api/v1/telemetry` → 200

What this caller's finished sessions did, newest first and bounded. A run is named by the seq that
ran it, so relaunching a session leaves the previous run behind rather than overwriting it, and deleting the
session record does not remove the runs it accumulated.

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

The record is frozen when the session ends, carrying its final sample window and its narration with it.
Both are process-local and dropped at that moment, so the run is the only place either survives: a session
carries no log tail in `GET /api/v1/sessions` once its run is frozen, because what it said belongs to the
run that said it. `logs` has the same shape as the tails on that route and is absent when it said nothing. `stats` comes from
Slurm's own accounting and is absent until it lands: `slurmdbd` flushes step usage a beat after a job ends, so
it is read again on the sampling tick for ten minutes and then left as it is. `samples` carries the run's last
resource samples the same way `logs` carries its narration, and `error` names why the run ended if it did not
end cleanly; both are absent rather than empty when there is nothing to report.

## Sign-in

The only routes in front of the authentication boundary. The browser runs CILogon's authorization-code flow
with PKCE itself; these routes finish it, because CILogon's token endpoint requires the client secret, which
only the daemon holds. All three require an allowed `Origin` header and accept no query string. `GET` answers
the client's configuration; the two `POST` routes take JSON and answer with `Cache-Control: no-store`.

### `GET /api/v1/oauth/config` → 200

```json
{
  "issuer": "https://cilogon.org",
  "authorizationEndpoint": "https://cilogon.org/authorize",
  "clientId": "cilogon:/client_id/...",
  "scope": "openid email profile offline_access"
}
```

The browser sends the user to `authorizationEndpoint` with `response_type=code`, this `clientId` and `scope`,
its own `redirect_uri` on an allowed origin, a `state`, and an S256 `code_challenge`.

### `POST /api/v1/oauth/exchange` → 200

```json
{ "code": "...", "codeVerifier": "...", "redirectUri": "https://jupyter.cybershuttle.org/lab/index.html" }
```

`redirectUri` must sit on an allowed origin; the daemon adds the client secret and redeems the code at the
issuer. The answer is the credential every other route needs:

```json
{ "idToken": "...", "refreshToken": "...", "expiresInSeconds": 900 }
```

`refreshToken` is present when the issuer granted `offline_access`. A rejected code is `400 invalid_grant`;
an unreachable issuer is `502 upstream_unavailable`.

### `POST /api/v1/oauth/refresh` → 200

```json
{ "refreshToken": "..." }
```

Answers the same shape as `exchange`, with a rotated `refreshToken` when the issuer rotates it. A refused
refresh is `400 invalid_grant`.

### `POST /api/v1/oauth/device` → 200

For a client that cannot receive a redirect, such as an editor extension. Takes no body and starts the
issuer's device grant:

```json
{
  "deviceCode": "...",
  "userCode": "QFP-7N3-VQF",
  "verificationUri": "https://cilogon.org/device/",
  "verificationUriComplete": "https://cilogon.org/device/?user_code=QFP-7N3-VQF",
  "expiresInSeconds": 900,
  "intervalSeconds": 5
}
```

The caller shows `userCode`, opens `verificationUriComplete`, and every `intervalSeconds` posts
`{ "deviceCode": "..." }` to `exchange`. Until the user approves, that answers `400 authorization_pending`, or
`429 rate_limited` when the issuer asks to slow down; then it answers the usual credential. A denied or
expired code is `400 invalid_grant`.

## Dev Tunnels link

Sessions run over the caller's own Dev Tunnels account, which is a Microsoft or GitHub identity linked once
and kept by the daemon under the caller's principal, sealed with a key the daemon holds. Nothing here returns
the linked token. These routes sit behind the authentication boundary.

### `GET /api/v1/tunnel` → 200

```json
{ "linked": true, "provider": "github", "account": "octocat", "linkedAt": "2026-09-17T10:00:00Z" }
```

`{ "linked": false }` when nothing is linked. `provider` is `microsoft` or `github`; `account` is the
Microsoft username or the GitHub login when known.

### `POST /api/v1/tunnel/authorizations` → 200

```json
{ "provider": "github" }
```

Starts a device-code authorization with that provider's Dev Tunnels client: `microsoft` through the common
Microsoft authority, or `github`. Any other name is `400 unknown_provider`. The answer is the device
authorization the browser shows:

```json
{
  "handle": "<43-character opaque handle>",
  "userCode": "ABCD-EFGH",
  "verificationUri": "https://github.com/login/device",
  "expiresInSeconds": 900,
  "intervalSeconds": 5
}
```

`handle` is this daemon's own reference to the authorization; the device code itself never reaches the client.
More than one start per second per caller is `429 rate_limited`.

### `POST /api/v1/tunnel/authorizations/{handle}/poll` → 200

Still waiting:

```json
{ "status": "pending", "intervalSeconds": 5 }
```

Complete: the daemon has stored the credential and answers what `GET /api/v1/tunnel` would.

```json
{ "linked": true, "provider": "microsoft", "account": "someone@outlook.com", "linkedAt": "..." }
```

A link keeps its refresh token and is renewed silently on use before it expires; GitHub tokens last eight
hours and Microsoft tokens one, so neither ever surfaces as an expired credential.
Polling faster than `intervalSeconds` is `429 rate_limited`. A denied authorization is
`403 authorization_denied`; an expired one is `410 authorization_expired`. The handle is bound to the caller
that started it and is discarded on any terminal outcome.

### `DELETE /api/v1/tunnel` → 204

Forgets the linked credential; deleting when nothing is linked is the same.

### Sessions without a link

`POST /api/v1/sessions` and `POST /api/v1/sessions/{id}/start` refuse with `409 tunnel_link_required` when
the caller has no linked credential, before anything is provisioned. `POST /api/v1/sessions/validate` does
not need one.
