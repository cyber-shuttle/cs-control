# Contributing to cs-control

Issues and pull requests go through GitHub. Branch off `main`, keep CI green, cover new behaviour with a test,
and say in the description what you ran.

## Prerequisites

- [Go](https://go.dev/dl/) 1.24.0 or newer — CI resolves the toolchain from `go.mod`.
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
golangci-lint run ./...
go test -race ./...
```

`.github/workflows/ci.yml` runs exactly these four on `ubuntu-latest` for every pull request and every push to
`main`, pinning `golangci-lint` to v2.13.2; `lefthook.yml` runs `gofmt`, `go vet`, the same lint and the race
suite before every commit, so a commit is formatted, linted and green; `lefthook install` wires it once per
clone. Suppressions for a finding that cannot be fixed at the root live only in `.golangci.yml`, each naming
the code and why, never as `//nolint` comments. There is no coverage gate. The race suite takes roughly a
minute, most of it in `internal/control` and `internal/gateway`; that is real work, not a hang.

`go build ./cmd/csctl` produces the `csctl` binary. See the [README](README.md) for running it.

Tests sit beside what they test as `*_test.go` and need no cluster, no network and no scheduler. Two of them do
drive a real host and are skipped unless you opt in:

```bash
LIVE_SSH_ALIAS=<an alias this machine can already reach> go test -race ./internal/gateway/
LIVE_SSH_ALIAS=<alias> LIVE_PROVISION_ROOT=<absolute remote directory> go test -race ./internal/control/
```

`LIVE_PROVISION_ROOT` names a directory the run may create and you may delete afterwards.

## File Layout

Go fixes no declaration order, so this repository picks one and enforces it in `TestLayout`
(`cmd/csctl/layout_test.go`):

1. The doc comment attached to the package clause names every top-level type, function and method, a method
   covered by its type's entry rather than named on its own. A const or var may be named.
   `Name*` covers a family.
2. A const, var or type used by two or more functions sits above the first function.
3. A method is declared after the type it is on.
4. Every unexported function precedes every exported one, a method taking its receiver's visibility.
5. A function is declared after every function, type, const and var of the file that it names.
6. The doc comment names them in the order the file declares them.
7. Every doc-comment entry names something the file declares.

A doc comment is a few sentences a person needs before reading the file, then the names in the order the
file declares them; an entry says nothing the name already says. Files read bottom-up, with primitives first
and the surface built on them last. Names on an entry line end at the first double space, and comment lines
run to 120 columns.

## Source layout

`cmd/csctl/` is the composition root; everything else is a package under `internal/`.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) lists those packages in the order they depend in, says what each
holds and gives the rule that none imports upward, and covers the session lifecycle and the trust
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
