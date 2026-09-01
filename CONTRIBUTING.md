# Contributing to cs-control

Issues and pull requests go through GitHub. Branch off `main`, keep CI green, cover new behaviour with a test,
and say in the description what you ran.

## Prerequisites

- [Go](https://go.dev/dl/) 1.23.0 or newer — CI resolves the toolchain from `go.mod`.
- [Git](https://git-scm.com/).
- An OpenSSH client, for the tests that drive `ssh` directly.

There is no code generation step, no C dependency and no service to run locally. The only direct dependencies
are `github.com/creack/pty` and `github.com/gorilla/websocket`.

## Build and test

```bash
git clone https://github.com/cyber-shuttle/cs-control.git
cd cs-control

go build ./...
go vet ./...
go test -race ./...
```

`.github/workflows/ci.yml` runs exactly these three on `ubuntu-latest` for every pull request and every push to
`main`. There is no separate linter and no coverage gate. The race suite takes roughly a minute, most of it in
`internal/control` and `internal/gateway`; that is real work, not a hang.

`go build ./cmd/csctl` produces the `csctl` binary. See the [README](README.md) for running it.

Tests sit beside what they test as `*_test.go` and need no cluster, no network and no scheduler. Two of them do
drive a real host and are skipped unless you opt in:

```bash
LIVE_SSH_ALIAS=<an alias this machine can already reach> go test -race ./internal/gateway/
LIVE_SSH_ALIAS=<alias> LIVE_PROVISION_ROOT=<absolute remote directory> go test -race ./internal/control/
```

`LIVE_PROVISION_ROOT` names a directory the run may create and you may delete afterwards.

## Source layout

`cmd/csctl/` is the composition root; everything else is a package under `internal/`.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) lists those packages in the order they depend in, says what each
holds and gives the rule that none imports upward, and covers the allocation lifecycle and the trust
boundaries a change has to hold. [docs/API.md](docs/API.md) is the client-facing contract, so a route or
response change belongs there in the same pull request.

The codebase is deliberately terse: a comment earns its place by explaining why something is the way it is, not
by restating what the code does.

## Pull requests

State what changed and why, link the issue it closes, and give the commands you ran and their result. A change
that alters a route, a response body, an error code or a flag is a change to a published contract — update the
docs alongside it and say so.

## Releases

A user-visible change goes under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) in the same pull request.

## Code of Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
