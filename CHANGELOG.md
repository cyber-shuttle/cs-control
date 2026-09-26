# Changelog

Notable changes to CyberShuttle Plane. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- Job submission no longer puts the session environment, including the link and Dev Tunnel host tokens, on
  `sbatch`'s command line, where any user of the login node could list it; a stdin program exports it instead.

### Added

- `attach` answers the `port` the client's Linkspan must serve its API on, and a telemetry run names its
  `launcher`, `cs-plane` (JupyterLab) or `client` (CS Bridge); runs recorded before 0.3.0 have none.

### Changed

- The request and response types of the API and the SSH login frames are exported, so clients generate their
  TypeScript types from them with tygo. JSON shapes are unchanged.
- Stopping a session without a Dev Tunnel no longer reads the linked Dev Tunnels account.

### Removed

- `POST /api/v1/sessions/{id}/runs`, which only moved CS Bridge's local history into cs-plane.

### Fixed

- An expired SSH login while preparing a session answers `409 ssh_authentication_required` instead of
  `502 session_provisioning_failed`.

## [0.3.0] - 2026-09-24

### Changed

- Sessions carry `tunnelModes` (`websocket`, `devtunnel` or both; default `websocket`), chosen on create and on
  `attach`; `devtunnel` needs a linked Dev Tunnels account (`409 tunnel_link_required`) and is the only mode
  that creates a tunnel.
- Linkspan launches with `--tunnel-enable --tunnel-mode` and only the selected modes' `--tunnel-websocket-args` and
  `--tunnel-devtunnel-args`; the Dev Tunnel host token travels as `LINKSPAN_TUNNEL_HOST_TOKEN`. Requires Linkspan
  0.21.0 or newer.
- `attach` takes an optional `tunnelModes` body and answers `link` only with `websocket` and `devtunnel`
  (`id`, `cluster`, `hostToken`) only with `devtunnel`; a client-launched `devtunnel` run is `READY` once Linkspan
  answers through its tunnel.

### Added

- `cs serve`: loopback-only JSON HTTP and WebSocket API under `/api/v1`.
- Sign-in relay for CILogon or another OIDC issuer: browser PKCE (`oauth/config`, `oauth/exchange`), device grant
  (`oauth/device`, `oauth/device/poll`) and `oauth/refresh`.
- Bearer authentication by OIDC ID token, resolved to a principal through Custos `GET /me`.
- One exact-origin policy for the API, the Jupyter proxy and every WebSocket.
- Per-caller SSH hosts from a pasted `ssh` command, with health, Slurm discovery and interactive authentication.
- Per-caller SSH keys, referenced by hosts as `keyId`.
- Optional Dev Tunnels account linking by device code, sealed at rest, for a fallback Dev Tunnel per session seq.
- Sessions: validate, record, start, stop, delete, adopt runs, access, SSH, metrics.
- `POST /sessions/{id}/attach`: a client-launched run, admitted by its link, which cs-plane never schedules.
- Session link: Linkspan dials `GET /sessions/{id}/link`; forwards and the Jupyter proxy ride it as yamux streams.
- Login-node preparation: Linkspan 0.21.0 or newer and the session workflow document.
- Background reconciliation of session state against Slurm every 30 seconds.
- `GET /telemetry`: finished runs per seq with Slurm accounting.
- State in a Postgres schema named by `CS_DATABASE_URL`, with sqlc-generated queries.

[Unreleased]: https://github.com/cyber-shuttle/cs-plane/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cyber-shuttle/cs-plane/commits/v0.3.0
