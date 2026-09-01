# Security Policy

## Supported Versions

There are no tagged releases. Fixes land on `main`, and running the latest `main` is the expected state.

## Reporting a Vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.
Please do not use a public issue, pull request or discussion for a security problem.

Include the commit you tested (`git rev-parse HEAD` — there are no releases yet), your operating system, what
an attacker can reach, and the steps to reproduce it. Redact credentials from anything you paste: OAuth access
and ID tokens, Dev Tunnel connect and host tokens, and Jupyter tokens.

We will acknowledge the report and say whether we can reproduce it before any fix is published, and will credit
you in the advisory unless you would rather we did not.

## Scope

`csctl` runs on a researcher's own machine. It validates OAuth and OIDC tokens, brokers a device-code flow,
persists Dev Tunnel connect tokens and Jupyter tokens to disk, writes into `~/.ssh/config`, and executes
commands on remote HPC systems. These are the boundaries it is designed around; a report is most useful when it
shows one of them failing. How each one works is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- The API binds an explicit loopback address only, and a browser caller must present an exact allowed `Origin`.
- Every route but the two device-code routes needs both a Dev Tunnels access token and a signed Microsoft ID
  token; the ID token is the sole identity bearer.
- Runtime records, their log tails and the access response are filtered or refused by the owning principal.
- The device-code broker is the only unauthenticated surface.
- Dev Tunnel connect and Jupyter tokens are stored on disk; OAuth credentials and tunnel host tokens are not.
- `~/.ssh/config` is written only inside the `cybershuttle managed` markers, and only a managed alias may be
  removed.
- Remote execution is by fixed argument vector against constant scripts, with bounded output and timeouts.
- Nothing is proxied: the browser reaches the allocation directly over the tunnel.

Out of scope here: a finding that already assumes control of the user's local account or their Microsoft
credentials, and vulnerabilities in Jupyter Server, Microsoft Dev Tunnels, or
[Linkspan](https://github.com/cyber-shuttle/linkspan), which have their own reporting channels.
