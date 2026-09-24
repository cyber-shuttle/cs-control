# Changelog

Notable changes to CyberShuttle Plane. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
- Login-node preparation: Linkspan 0.20.0 or newer and the session workflow document.
- Background reconciliation of session state against Slurm every 30 seconds.
- `GET /telemetry`: finished runs per seq with Slurm accounting.
- State in a Postgres schema named by `CS_DATABASE_URL`, with sqlc-generated queries.

[Unreleased]: https://github.com/cyber-shuttle/cs-plane/commits/main
