# Security Policy

## Supported Versions

There are no tagged releases. Fixes land on `main`, and running the latest `main` is the expected state.

## Reporting a Vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.
Please do not use a public issue, pull request or discussion for a security problem.

Include the commit you tested (`git rev-parse HEAD` — there are no releases yet), your operating system, what
an attacker can reach, and the steps to reproduce it. Redact credentials from anything you paste: OIDC ID
tokens, Dev Tunnel connect and host tokens, and Jupyter tokens.

We will acknowledge the report and say whether we can reproduce it before any fix is published, and will credit
you in the advisory unless you would rather we did not.

## Scope

cs-plane runs on a researcher's own machine. It validates OIDC ID tokens and resolves them to a principal
through Custos, brokers a one-time Dev Tunnels device-code link, persists Dev Tunnel connect tokens and
Jupyter tokens to disk, writes each caller's own managed SSH configuration under
`<state>/hosts/<principal>/config`, and executes commands on remote HPC systems. These are the boundaries it
is designed around; a report is most useful when it shows one of them failing. How each one works is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- The API binds an explicit loopback address only, and a browser caller must present an exact allowed `Origin`.
- Every route but the four sign-in routes needs a signed OIDC ID token, validated against the configured
  issuer and resolved to a principal through Custos; the ID token is the sole identity bearer.
- Session records, their log tails and the access response are filtered or refused by the owning principal.
- The sign-in relay and the Dev Tunnels link broker are the only unauthenticated surfaces.
- Dev Tunnel connect and Jupyter tokens are stored on disk; the linked Dev Tunnels credential is stored sealed;
  the request's own bearer and tunnel host tokens are not persisted.
- Each principal's managed SSH configuration lives under `<state>/hosts/<principal>/config`; `~/.ssh/config`
  is neither read nor written, and only a managed alias may be removed.
- Remote execution is by fixed argument vector against constant scripts, with bounded output and timeouts.
- Nothing is proxied: the browser reaches the session directly over the tunnel.

Out of scope here: a finding that already assumes control of the user's local account or their CILogon,
Custos or Dev Tunnels credentials, and vulnerabilities in Jupyter Server, Microsoft Dev Tunnels, CILogon,
Custos, or [Linkspan](https://github.com/cyber-shuttle/linkspan), which have their own reporting channels.
