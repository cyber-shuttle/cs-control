# Contributing to cs-control

Issues and pull requests go through GitHub. Branch off `main`, keep CI green, cover new behaviour with a test,
and say in the description what you ran.

## Prerequisites

- [Go](https://go.dev/dl/) 1.26.0 or newer — CI resolves the toolchain from `go.mod`.
- [Git](https://git-scm.com/).
- An OpenSSH client, for the tests that drive `ssh` directly.

The database tests need a Postgres server. Point `CSCTL_TEST_DATABASE_URL` at one and every test works in a
schema of its own that is dropped afterwards; without it those tests are skipped, and CI always provides one:

```bash
docker run -d -p 127.0.0.1:5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
export CSCTL_TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable'
```

There is no C dependency. SQL queries in each subsystem's `query.sql` are compiled
to Go by [sqlc](https://sqlc.dev) (`go generate ./internal/db`); the generated `query.sql.go`, `sql.go` and
`sql_models.go` are committed, so regenerate only when a `schema.sql` or `query.sql` changes.

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
minute, most of it in `subsystems/session`; that is real work, not a hang.

`go build .` produces the `csctl` binary. See the [README](README.md) for running it.

Tests sit beside what they test as `*_test.go` and need no cluster and no scheduler; only the database tests
need the Postgres server above.

## Source layout

The root package is the composition root: `main.go` builds `csctl`. Atomic packages with no HTTP surface of their own live under
`internal/`; `oauth`, `ssh`, `tunnel`, `session` and `telemetry`, each owning its wire shapes, logic and route
table, live under `subsystems/`. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) lists those packages in the order they depend in,
says what each holds and gives the rule that none imports upward and no subsystem imports another, and covers
the session lifecycle and the trust boundaries a change has to hold. [docs/API.md](docs/API.md) is the
client-facing contract, so a route or response change belongs there in the same pull request.

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
