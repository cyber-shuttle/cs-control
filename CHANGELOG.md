# Changelog

Notable changes to CyberShuttle Control. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `csctl serve`: a loopback-only JSON HTTP and WebSocket API, `127.0.0.1:8045` by default, requiring
  `--oidc-client-id`, `--custos-url`, `CSCTL_OIDC_CLIENT_SECRET` and at least one exact `--allowed-origin`.
  Every route lives under `/api/v1`, one subsystem per prefix: `oauth`, `ssh`, `tunnel`, `sessions` and
  `telemetry`.
- Device sign-in for clients with no redirect URI: `POST /oauth/device` starts the issuer's device grant, and
  `POST /oauth/exchange` redeems the device code once the user approves it.
- Sign-in relay: `GET /oauth/config`, `POST /oauth/exchange` and `POST /oauth/refresh` finish the browser's
  CILogon (or another configured OIDC issuer) authorization-code-with-PKCE flow. Every other request carries
  one `Authorization: Bearer <ID token>`, validated against the issuer and resolved to a principal through
  Custos (`GET {custos-url}/me`) under the fixed tenant `custos`. The SSH authentication WebSocket offers
  `cybershuttle.v1` and `bearer.<id token>`.
- SSH hosts per caller: `GET,POST /ssh/hosts`, `PUT,DELETE /ssh/hosts/{alias}`, `POST .../test`,
  `GET .../slurm` and the interactive `GET .../auth` WebSocket that establishes the multiplexed control master
  every later operation reuses. A host is added or replaced from an `ssh` command line that already works.
  Each principal has a private configuration under `<state>/hosts/<principal>/config` that `ssh -F` names, so
  one caller authenticating a host cannot hand another an authenticated login.
- SSH keys: `GET,POST /ssh/keys` and `DELETE /ssh/keys/{name}` provide metadata-only list, create and delete
  for private keys held at mode `0600`. A host references a key as its `IdentityFile` with
  `IdentitiesOnly yes`; deleting a key clears every reference and renders the affected configuration
  transactionally.
- Dev Tunnels linking: `POST /tunnel/authorizations` and `POST /tunnel/authorizations/{handle}/poll` link a
  Microsoft or GitHub account once through a device-code flow; `GET,DELETE /tunnel` read and remove the
  link, sealed to disk with `nacl/secretbox`. A Microsoft link refreshes silently within two minutes of
  expiry. Session creation and start answer `409 tunnel_link_required` while nothing is linked.
- Sessions: `POST /sessions/validate` checks a request with `sbatch --test-only`; `GET,POST /sessions`,
  `GET,DELETE /sessions/{id}`, `POST .../start`, `POST .../stop`, `GET .../access` and `GET .../metrics`
  create, list, relaunch, stop and read a session. `access` returns the owner's Jupyter URI and token over the
  allocation's tunnel; `metrics` returns the last twenty CPU, memory and GPU samples read from Linkspan every
  five seconds. A session's attempt counter `seq` starts at 1 and increments on every `start`; the Slurm job
  is named `cs-<id>-<seq>`. `startedAt` records when Slurm first ran the job.
- Login-node preparation before submission: uv and Linkspan 0.19.0 or newer installed under `$HOME`, and the
  `tasks` workflow document the job runs. A host whose Linkspan cannot host the allocation's tunnel is refused.
- Reconciliation in the background, never from a read: a session the scheduler stops answering for is
  retired, one that reaches its walltime ends as stopped, and a submission that completes against an
  already-terminal record cancels the job it created.
- `GET /telemetry`: this caller's finished runs, frozen when each job ends and named by the `seq` that ran it,
  with Slurm accounting (peak RSS, CPU and memory efficiency) filled in as it flushes. A run outlives both a
  relaunch and a delete of its session record.
- HTTP conventions: new hosts, keys and sessions answer `201` with `Location`, an idempotent session replay
  `200`, every successful `DELETE` `204` with no body, and `DELETE /sessions/{id}` of a live session
  `409 session_not_stopped`. `GET /sessions` carries a strong `ETag` and honours `If-None-Match` with `*`,
  lists and weak validators. Preflight is answered from the route registry (`404`, `405` with `Allow`, or
  `403`); every refusal, including a missing credential (`401 unauthorized` with `WWW-Authenticate: Bearer`),
  is the JSON error envelope, and an unclassified failure is `500 internal_error` with its detail logged, not
  returned.
- Local state under `~/.cybershuttle/control` at mode `0700`: one SQLite database whose schema each subsystem
  declares in its own `schema.sql` and reads through sqlc-generated queries. A database without the current
  format marker is refused before any credential file is created; nothing is migrated.
- An Apache-2.0 `LICENSE`, contribution and security policies, and reference documentation for the routes
  (`docs/API.md`) and for the package layout, session lifecycle and trust boundaries (`docs/ARCHITECTURE.md`).

[Unreleased]: https://github.com/cyber-shuttle/cs-control/commits/main
