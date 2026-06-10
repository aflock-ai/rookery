---
title: Configuration
sidebar_position: 6
---

# Configuration

CI/lock is **args-only**: CLI flags are the primary — and almost only — configuration interface. There is **no config file**. Every knob resolves through three layers, in most-specific-wins order:

| Layer | Source | Notes |
|---|---|---|
| 1 | **CLI flag** (per-invocation) | Highest precedence. An explicitly-passed flag wins over everything, including an empty value — `--platform-url=""` means "no platform", not "use the default". |
| 2 | **Env var** (`CILOCK_*`) | A small set of low-level feature toggles (see below). |
| 3 | **Built-in default** | Compiled-in fallback. |

> Source of truth: [`rookery/cilock/internal/options/resolve.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/internal/options/resolve.go) and [`internal/options/root.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/internal/options/root.go).

## No config file (removed)

Earlier releases inherited a `.witness.yaml` YAML config file (with a `--config, -c` override flag) from the witness lineage. That surface was **removed deliberately**:

- The default path was CWD-relative, so a malicious cloned repository could ship a `.witness.yaml` that **silently overrode security-critical flags** — `archivista-server`, `enable-archivista`, `signer-file-key-path`, `policy-ca-roots` — redirecting evidence or verification trust anchors without the operator noticing.
- Two sources of truth for "what flags drove this run" complicated audit: the [`configuration` attestor](../attestors/configuration) now captures exactly the CLI surface, with nothing hidden in a file.

If you previously used a config file, move the values onto the command line (or generate the command line in your CI templating). `--config` / `-c` no longer parse; invocations passing them fail fast with an unknown-flag error.

For repeated infrastructure config (Archivista URL, Fulcio, TSA), prefer `--platform-url`: everything auto-derives from the platform discovery document, which is one flag instead of five.

## Environment variables

CI/lock does not expose a general `CILOCK_*` env var prefix mirroring its CLI flags — flags are the primary interface. A few low-level feature toggles **are** read from the environment, though: `CILOCK_FANOTIFY` and `CILOCK_FSVERITY` force those capture features on/off (and win over `--hardening`), `CILOCK_TRACE_MODE` selects the tracing backend, `CILOCK_FANOTIFY_MAX_DIGESTS` caps the digest map, and `--diagnose` (or `CILOCK_DIAGNOSE`) enables verbose internals. Separately, the `cilock-action` GitHub Action uses `CILOCK_*` env vars internally to pass values *to* CI/lock — that's an action-layer convention, not a CLI-flag prefix.

## Example: standardized CI invocations

Per-step CI/lock calls carry their full configuration on the command line:

```bash
cilock run --step build --platform-url "$PLATFORM_URL" -- go build ./cmd/myapp
cilock run --step test  --platform-url "$PLATFORM_URL" -- go test ./...
```

Shared values live in your CI system's variables (`$PLATFORM_URL` above), not in a file cilock reads implicitly.

For the full set of flags supported under each subcommand, see the [CLI reference](./cli):

- All `run` flags → [`cilock run`](./cli#cilock-run-cmd)
- All `sign` flags → [`cilock sign`](./cli#cilock-sign-file)
- All `verify` flags → [`cilock verify`](./cli#cilock-verify)
