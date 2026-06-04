---
title: Configuration
sidebar_position: 6
---

# Configuration

CI/lock supports a YAML config file that persists CLI flag values, so you don't have to repeat them on every invocation. **CLI flags always override config file values.**

> Source of truth: [`rookery/cilock/internal/cmd/config.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/internal/cmd/config.go) and [`internal/options/root.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/internal/options/root.go).

## Discovery and override behavior

| Behavior | Detail |
|---|---|
| **Default path** | `.witness.yaml` (legacy from the witness lineage; not yet renamed to `.cilock.yaml`) |
| **Override path** | `--config, -c <path>` |
| **Missing file with explicit `--config`** | Hard error: `config file <path> does not exist` |
| **Missing file without `--config`** | Silently falls back to CLI args (debug log only) |
| **Precedence** | CLI flags > config file > flag defaults |

## Schema

The schema mirrors the CLI flag names. Each top-level key is a subcommand; each nested key is a flag name (without the leading `--`):

```yaml
run:
  attestations: [environment, git, github]
  step: build
  outfile: build.attestation.json
  workingdir: .
  hashes: [sha256]
  trace: false
  enable-archivista: true
  archivista-server: https://archivista.example.com
  archivista-headers:
    - "Authorization: Bearer ${ARCHIVISTA_TOKEN}"
  timestamp-servers:
    - https://freetsa.org/tsr
  signer-fulcio-url: https://fulcio.sigstore.dev
  signer-fulcio-oidc-client-id: sigstore
  signer-fulcio-oidc-issuer: https://token.actions.githubusercontent.com

sign:
  outfile: signed.json
  datatype: https://example.com/predicate/v1
  signer-file-key-path: ./signing.key

verify:
  policy: ./policy-signed.json
  publickey: ./policy-pubkey.pem
  attestations:
    - build.attestation.json
    - test.attestation.json
  subjects:
    - sha1:${RELEASE_COMMIT_SHA}
```

The `verify` example above uses `--subjects` rather than `--artifactfile` for the same reason the [verify-in-a-release-gate guide](../guides/verify-in-a-release-gate) recommends: in multi-stage pipelines the artifact path can land in materials rather than products, breaking the digest-to-subject match. `--artifactfile bin/myapp` still works for single-job builds.

For the full set of flags supported under each subcommand, see the [CLI reference](./cli):

- All `run` flags → [`cilock run`](./cli#cilock-run-cmd)
- All `sign` flags → [`cilock sign`](./cli#cilock-sign-file)
- All `verify` flags → [`cilock verify`](./cli#cilock-verify)

## Flag-name to YAML-key mapping

The mapping is mechanical: drop the `--` prefix and use the rest as the YAML key. Examples:

| CLI flag | YAML key under `run:` |
|---|---|
| `--step build` | `step: build` |
| `--attestations "git github"` | `attestations: [git, github]` |
| `--enable-archivista` | `enable-archivista: true` |
| `--archivista-server <url>` | `archivista-server: <url>` |
| `--signer-fulcio-url <url>` | `signer-fulcio-url: <url>` |
| `--attestor-product-include-glob "bin/*"` | `attestor-product-include-glob: "bin/*"` |

`stringSlice`-typed flags accept YAML arrays; everything else is a string.

## When to use a config file

Good fits:

- **Repeated infrastructure config:** Archivista URL, TSA URL, Fulcio URL, OIDC issuer
- **Standardized step defaults:** hash algorithms, default attestor sets per project
- **Local dev convenience:** signer-file-key-path so you don't retype it

Bad fits:

- **Per-step values** like `--step` itself (each invocation is a different step), these belong on the CLI
- **Secrets:** config files end up in repos; use env vars or env-templated headers instead

## Environment variables

CI/lock does not expose a general `CILOCK_*` env var prefix mirroring its CLI flags — flags are the primary interface. A few low-level feature toggles **are** read from the environment, though: `CILOCK_FANOTIFY` and `CILOCK_FSVERITY` force those capture features on/off (and win over `--hardening`), and the legacy `CILOCK_EBPF_DEBUG` / `CILOCK_BPF_DIAGNOSE` diagnostics are now folded into `--diagnose`. Separately, the `cilock-action` GitHub Action uses `CILOCK_*` env vars internally to pass values *to* CI/lock — that's an action-layer convention, not a CLI-flag prefix.

Within a config file, you can use shell-style env interpolation through your shell or a templating step before invocation; CI/lock itself does not interpolate.

## Example: standardized project config

A `.witness.yaml` checked into a repo so every CI/lock invocation uses the same Archivista and Fulcio:

```yaml
run:
  enable-archivista: true
  archivista-server: https://archivista.internal.example.com
  signer-fulcio-url: https://fulcio.internal.example.com
  signer-fulcio-use-http: true
  signer-fulcio-oidc-client-id: sigstore
  signer-fulcio-oidc-issuer: https://token.actions.githubusercontent.com
  timestamp-servers:
    - https://tsa.internal.example.com
  hashes: [sha256]
```

Then per-step CI/lock calls only need to specify what differs:

```bash
cilock run --step build --signer-fulcio-token "$OIDC" -- go build ./cmd/myapp
cilock run --step test  --signer-fulcio-token "$OIDC" -- go test ./...
```
