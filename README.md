# CyberShuttle Control

`csctl` is a CLI-first control tool for discovering SLURM resources and managing Linkspan allocations over SSH. It runs no server and stores only non-secret runtime metadata locally.

## Build

```bash
go build -o csctl ./cmd/csctl
```

## Discover a resource

SSH aliases are resolved by the installed `ssh` client and its normal configuration.

```bash
csctl resource discover --ssh delta
csctl resource discover --ssh delta --json
```

Discovery queries the current user's SLURM accounts, partitions, CPUs, memory, generic resources, and home directory.

## Runtime lifecycle

The Linkspan binary and workflow must already exist at absolute paths on the remote system.

```bash
csctl runtime create \
  --ssh delta \
  --partition cpu-interactive \
  --account project-a \
  --cpus 4 \
  --memory-mb 4096 \
  --walltime 01:00:00 \
  --linkspan /home/me/.cybershuttle/bin/linkspan \
  --workflow /home/me/.cybershuttle/runtime.yaml \
  --json

csctl runtime list --json
csctl runtime get --json rt-012345abcdef
csctl runtime stop --json rt-012345abcdef
```

`runtime create` persists a submission intent before invoking `sbatch`. Interrupted submissions are reconciled by their unique SLURM job name. `list` and `get` reconcile active jobs through `squeue` and terminal jobs through `sacct`; `stop` uses `scancel` and then reconciles. Each job starts Linkspan on `127.0.0.1` with an ephemeral HTTP port and a per-runtime Unix socket under `$SLURM_TMPDIR` (or `/tmp`). Passing `--workflow` makes Linkspan execute that workflow at startup.

Global flags must precede the command:

```bash
csctl --state-dir /tmp/cs-state --timeout 30s runtime list --json
```

## Boundaries

- State defaults to `~/.cybershuttle/control/state.json` and is atomically written with mode `0600` in a `0700` directory.
- State contains resource requests, SLURM job identifiers, and lifecycle status only. Bearer tokens, tunnel credentials, Custos credentials, SSH keys, and HPC credentials are never accepted or stored.
- SSH commands have fixed argument shapes, bounded output, and timeouts.
- Custos integration is deferred until its API is available. This project does not invent an authentication abstraction in the meantime.
- This first slice intentionally has no HTTP server, database, plugin framework, or third-party CLI dependency.
