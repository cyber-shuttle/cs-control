# CLAUDE.md

Working instructions for AI agents in this repository. Everything descriptive lives in the public docs:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the package layering, the allocation lifecycle and the trust
boundaries, [docs/API.md](docs/API.md) for the routes and their shapes, [CONTRIBUTING.md](CONTRIBUTING.md) for
the build, test and pull-request workflow. Read those first; do not restate them here.

## Working rules

- Run the build, vet and race-test commands in CONTRIBUTING.md before proposing a change. CI gates on exactly
  those three.
- A change to a route, a request or response field, an error code, a CLI flag or an environment variable is a
  change to a published contract: update docs/API.md or README.md in the same change.
- A change to the allocation lifecycle or a trust boundary updates docs/ARCHITECTURE.md in the same change.
- Comments explain why, not what. Match the surrounding terseness.

## Invariants to preserve

Read docs/ARCHITECTURE.md as constraint, not description: the package layering, the allocation lifecycle and
the trust boundaries are invariants — do not weaken one to make a change fit. Beyond what it states:

- Keep the CLI at `serve`, `help` and `version`. Runtime and SSH operations go through the OAuth-authenticated
  API; do not add delegated-token argv flags. Global flags precede commands.
