---
title: CLI reference
sidebar_position: 1
---

# `cilock` CLI reference

> Source of truth: [`rookery/cilock/cmd/cilock/main.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/cmd/cilock/main.go) and [`rookery/cilock/internal/cmd/`](https://github.com/aflock-ai/rookery/tree/main/cilock/internal/cmd). All defaults and flag names below match `cilock 1.1.0`.

```
cilock - Collect and verify attestations about your build environments
```

CI/lock attestation types use the `https://aflock.ai/attestations/<name>/v0.1` namespace. Witness-style URLs (`https://witness.dev/attestations/<name>/v0.1`) are accepted via legacy aliases for interop with witness-produced evidence.

## Top-level commands

| Command | Purpose |
|---|---|
| `cilock run [cmd]` | Run a command and record signed attestations about its execution. |
| `cilock attest` | Record attestations without wrapping a command (sugar for `run -- true`; for consultative/at-rest attestors). |
| `cilock sign [file]` | Sign an arbitrary file (typically a policy) with the configured signer. |
| `cilock verify` | Verify an artifact (subject) against a signed policy using attestations as evidence. |
| `cilock prove` | Emit signed inclusion proofs for files in a v0.3 product/material tree (selective disclosure / suppressed inline leaves). |
| `cilock prove-chain` | Build a chain-of-custody sidecar binding a step's consumed materials to an upstream step's signed Merkle root. |
| `cilock policy from-bundles` | Generate a starter Witness policy from one or more signed attestation bundles. |
| `cilock policy validate` | Validate a Witness/cilock policy document (schema only, no signature check). |
| `cilock keyid` | Print the canonical keyid (`hex(sha256(PEM(pub)))`) derived from a public or private key. |
| `cilock bundle create` / `inspect` | Build or inspect a portable attestation bundle (tar.gz of DSSE envelopes). |
| `cilock plan [cmd]` | Show which attestors detection would fire for a command, without executing it. |
| `cilock attestors list` | List every attestor compiled into the binary. |
| `cilock attestors schema <name>` | Print the JSON schema of a specific attestor's predicate. |
| `cilock tools` | List supported detectors and emit per-tool test plans. |
| `cilock completion <shell>` | Emit shell completion script (bash, zsh, fish, powershell). |
| `cilock version` | Print the `cilock` version. |

## Global flags

These persistent flags are accepted on every subcommand:

| Flag | Default | Notes |
|---|---|---|
| `--config, -c <path>` | `.witness.yaml` | Path to a YAML config file with persisted flag values. The `.witness.yaml` name is a legacy from the witness lineage; not yet renamed to `.cilock.yaml`. |
| `--log-level, -l <level>` | `info` | One of `debug`, `info`, `warn`, `error`. |
| `--debug-cpu-profile-file <path>` | (none) | Write a CPU pprof profile to this path. Profiling enabled when non-empty. |
| `--debug-mem-profile-file <path>` | (none) | Write a heap pprof profile to this path. Profiling enabled when non-empty. |

## `cilock run [cmd]`

> Runs the provided command and records attestations about the execution.

Always-run attestors (cannot be omitted): `material`, `product`, and (when args are provided) `command-run`. Trying to pass `command-run` via `--attestations` is rejected.

Only **one signer** is supported per `run` invocation (enforced at `cilock/internal/cmd/run.go:71-73`).

### Common flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--step <name>` | `-s` | inferred | Step category. Optional — when omitted, [inferred from the wrapped command](../concepts/step-categories). Must be a value from the step lexicon. |
| `--attestations <list>` | `-a` | `environment,git` | **Comma-separated** attestors. Passing `-a` disables [auto-detection](../concepts/auto-detection-and-defaults) (set becomes exact) unless `--workload auto`. |
| `--workingdir <dir>` | `-d` | current dir | Working directory for material/product capture. |
| `--outfile <path>` | `-o` | stdout | Path for the signed DSSE envelope. |
| `--trace` | `-r` | `false` | Enable syscall tracing (Linux). Backend is ptrace+seccomp or eBPF — see [capture modes](../concepts/capture-modes). No-op on non-Linux. |
| `--ignore-command-exit-code` | (none) | `false` | Still record (and sign) the attestation when the wrapped command exits non-zero, instead of aborting. Useful for tools that signal findings via exit code (e.g. `oscap` exits 2, scanners exit 1). |
| `--hashes <list>` | (none) | `sha256` | Hash algorithms used in digests (comma-separated). |
| `--dirhash-glob <list>` | (none) | (none) | Globs for which directories should be hashed as a single unit. |
| `--timestamp-servers <list>` | `-t` | (none) | RFC 3161 TSA URLs (comma-separated; repeatable). |
| `--enable-archivista` | (none) | `false` | Push the signed envelope to Archivista. |
| `--archivista-server <url>` | (none) | `https://platform.testifysec.com/archivista` | Archivista server URL (derived from `--platform-url` if not explicitly set). |
| `--archivista-headers <h>` | (none) | (none) | Repeatable `Authorization: ...` headers for Archivista. |
| `--archivista-oidc` | (none) | `false` | Use GitHub Actions OIDC for Archivista auth (auto-enabled in GitHub Actions). |
| `--archivista-audience <aud>` | (none) | Archivista server URL | OIDC audience claim. |
| `--platform-url <url>` | (none) | `https://platform.testifysec.com` | TestifySec platform URL; archivista, fulcio, and TSA URLs are derived from it if unset. |
| `--env-filter-sensitive-vars` | (none) | `false` | Remove sensitive env vars from output rather than obfuscating. |
| `--env-add-sensitive-key <key>` | (none) | (none) | Add a name or glob (e.g. `*TOKEN*`) to the sensitive env list (repeatable). |
| `--env-allow-sensitive-key <key>` | (none) | (none) | Whitelist a specific key from the sensitive list. |
| `--env-disable-default-sensitive-vars` | (none) | `false` | Disable CI/lock's default sensitive-var list entirely. |

### Capture, detection & hardening flags

| Flag | Default | Description |
|---|---|---|
| `--capture-mode <mode>` | `auto` | Where material/product digests come from: `auto` (trace if `--trace`, else walk), `walk`, `trace` (requires `--trace`), `ima`. See [capture modes](../concepts/capture-modes). |
| `--hardening <profile>` | `standard` | Integrity profile: `off`, `standard` (fanotify on, fs-verity opportunistic), `strict` (fanotify + fs-verity required, drops fail). |
| `--require-zero-drops` | from `--hardening` | Fail the run if the trace dropped any event. `strict` ⇒ `true`. |
| `--workload <mode>` | `auto` | Attestor selection. `auto` detects (only when `-a` absent, unless forced); `manual` uses `-a`/defaults exactly. See [auto-detection](../concepts/auto-detection-and-defaults). |
| `--validate-only` | `false` | Run pre-flight workload + tool checks, print the planned attestor set, exit without running the command. |
| `--no-default-attestor <name>` | (none) | Drop an always-on attestor (`product`, `material`). Repeatable. |
| `--diagnose` | `false` | Verbose internal logging (eBPF load, fanotify, ringbuf drops, fs-verity). Sets `CILOCK_DIAGNOSE=1`. |
| `--cache-add-pattern <glob>` | (none) | Add a glob to the build-cache classification set (cache files aren't products). Repeatable. |
| `--cache-allow-pattern <glob>` | (none) | Remove a glob from the cache set (treat as a product). Repeatable. |
| `--prewalk-skip-dir <name>` | (none) | Add a basename to the pre-trace walk skip list (defaults: `.git`, `node_modules`, `vendor`, `.cache`). Repeatable. |
| `--prewalk-include-dir <name>` | (none) | Force the pre-trace walk into a basename even if skipped. Most-specific wins. Repeatable. |

Capture backend selection within `--trace` is controlled by the `--capture-mode` suffix — `trace:auto` (eBPF, else ptrace), `trace:ebpf` (require eBPF), or `trace:ptrace` (skip the eBPF probe) — plus the `CILOCK_FANOTIFY` / `CILOCK_FSVERITY` feature toggles.

Plus the **signer flags** (see below) and **attestor-specific flags** prefixed `--attestor-<name>-*` (e.g. `--attestor-secretscan-fail-on-detection`, `--attestor-product-include-glob`).

### Signer selection

CI/lock loads signers based on which `--signer-*-*` flags are set. The **default binary** registers two signer providers plus a KMS provider:

- **`file`:** `--signer-file-key-path`, `--signer-file-cert-path`, `--signer-file-intermediate-paths`, `--signer-file-key-passphrase`, `--signer-file-key-passphrase-path`
- **`fulcio`:** `--signer-fulcio-url`, `--signer-fulcio-oidc-issuer`, `--signer-fulcio-oidc-client-id`, `--signer-fulcio-oidc-redirect-url`, `--signer-fulcio-token`, `--signer-fulcio-token-path`, `--signer-fulcio-use-http` (default `true`)
- **`kms`:** `--signer-kms-ref` (key reference URI, e.g. `awskms://`, `gcpkms://`, `azurekms://`, `hashivault://`), `--signer-kms-hashType` (default `sha256`), `--signer-kms-keyVersion`

Additional providers (`spiffe`, `vault`, and per-cloud KMS broker clients with their extra sub-flags) are **not** compiled into the default release binary; add them via a custom build — see [build a custom CI/lock](../guides/build-a-custom-cilock). Run `cilock run --help-advanced` to see the exact signer flags your binary exposes.

For the full URI conventions, see [signing & identity](../concepts/signing-and-identity).

## `cilock sign [file]`

> Signs a file with the provided key source and outputs the signed file to the specified destination.

Wraps an arbitrary file in a DSSE envelope. Used most commonly to sign a policy document before distribution. Same signer-selection model as `run`. Only one signer per invocation.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--infile <path>` | `-f` | (required) | File to sign (typically the policy JSON). |
| `--outfile <path>` | `-o` | stdout | Destination for the signed DSSE envelope. |
| `--datatype <uri>` | `-t` | `https://witness.testifysec.com/policy/v0.1` | DSSE `payloadType`. Default is the witness policy type for backward compatibility; CI/lock also accepts `https://aflock.ai/policy/v0.1`. |

## `cilock verify`

> Verifies an **artifact (subject)** against a signed policy. You name the subject — an artifact file (`-f`) or a digest such as `sha1:$COMMIT` (`-s`) — and CI/lock uses the supplied **attestations as the evidence** that validates it. You verify the thing, not the attestation.

Because v0.3 product/material attestations [inline their Merkle leaves](../attestors/product) by default, `cilock verify <artifact> -p policy -a <attestations>` resolves the artifact's digest to its signed tree with **no inclusion-proof envelope** — the inclusion-proof bridge maps the artifact's sha256 to the `tree:products` root. `artifactsFrom` chains verify from the inline leaves with no chain sidecar; strict-chain mode (`--require-sidecar`, default) is satisfied by verified inline leaves or a sidecar.

**Policy-signer trust.** A build can embed its policy trust anchors (policy CA root, TSA root, signer functionary) at compile time, so `cilock verify <artifact> -p policy -a <attestations>` needs no `--policy-*` flags; verify prints the trust anchors it uses. The canonical binary ships **empty** embedded trust (`{}`), so you supply trust per dimension via `-k`/`--publickey` (key) or `--policy-ca-roots` + the Fulcio constraint flags below. Flags override embedded trust; verify **fails closed** when neither a flag nor embedded trust is present for a required dimension.

| Flag | Short | Description |
|---|---|---|
| `--policy <path>` | `-p` | Path to the signed DSSE policy envelope. |
| `--publickey <path>` | `-k` | Path to the policy signer's public key (PEM). |
| `--attestations <list>` | `-a` | Attestation envelope files (comma-separated; repeatable). |
| `--artifactfile <path>` | `-f` | Path to the artifact subject to verify. |
| `--subjects <list>` | `-s` | Additional subjects to use when looking up attestations (e.g. `sha1:$COMMIT`). More reliable than `--artifactfile` in multi-stage pipelines. |
| `--directory-path <path>` | (none) | Path to a directory subject (for material/product matching). |
| `--enable-archivista` + `--archivista-server` | (none) | Pull collections from Archivista by subject digest instead of (or in addition to) file paths. |
| `--policy-ca-roots <list>` | (none) | X.509 roots for verifying a policy signed via x.509 cert (replaces the deprecated `--policy-ca`). |
| `--policy-ca-intermediates <list>` | (none) | Intermediate CAs for the policy cert chain. |
| `--policy-commonname`, `--policy-dns-names`, `--policy-emails`, `--policy-organizations`, `--policy-uris` | (none) | Cert-constraint fields when the policy is signed with x.509. |
| `--policy-fulcio-oidc-issuer`, `--policy-fulcio-build-trigger`, `--policy-fulcio-build-config-uri`, `--policy-fulcio-runner-environment`, `--policy-fulcio-run-invocation-uri`, `--policy-fulcio-source-repository-{ref,identifier,digest}` | (none) | Fulcio cert-constraint fields pinning a **keyless** policy signer — e.g. `--policy-fulcio-build-config-uri https://github.com/org/repo/.github/workflows/release.yml@*` pins which workflow may sign a trusted policy without pinning the ref; `--policy-fulcio-runner-environment github-hosted`. |
| `--require-sidecar` | (none) | Strict-chain mode (default on): an `artifactsFrom` chain must be satisfied by verified inline leaves **or** a chain sidecar. |
| `--policy-timestamp-servers <list>` | (none) | Trusted TSA CA cert paths for verifying timestamped policies. |
| `--verifier-kms-*` | (none) | Same shape as `--signer-kms-*`, used when the policy's public key is referenced by a KMS URI. |

Full verifier flag list is in [`cilock/internal/options/verify.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/internal/options/verify.go).

Exit code **0** on policy pass, non-zero on any verification failure or error.

## `cilock attest`

> Records attestations against the current context **without wrapping a command** — sugar for `cilock run -- true`. Every `run` flag works here. Use it for consultative / at-rest attestors that snapshot state (e.g. `github-review`, `aws-iid`) rather than observe a command.

```bash
cilock attest -a github-review -k key.pem -o review.bundle.json -s review-head
```

## `cilock prove`

> Emits a signed inclusion-proof attestation binding one file's digest to a v0.3 product/material Merkle root. Needed only for **selective disclosure** or when a build **suppressed inline leaves** — by default the product attestation's inline leaves already make every file verifiable. See [prove files in a build](../guides/prove-files-in-a-build).

| Flag | Description |
|---|---|
| `--tree-sidecar <path>` | The `<outfile>.product.tree.json` / `.material.tree.json` written by `cilock run` (required). |
| `--file <path>` | Leaf path to prove. Repeatable; each envelope lands at `<outfile>-<sanitised-path>.json`. |
| `--outfile <path>` | Output path for the signed inclusion-proof envelope. |
| `--signer-file-key-path` etc. | Standard signer flags (same as `run`). |

## `cilock prove-chain`

> Builds an unsigned `rookery.chain-proof.sidecar/v0.1` binding a step's **consumed** materials to an **upstream** step's signed Merkle root, so a policy verifier can confirm provenance across steps. With v0.3 inline leaves, `artifactsFrom` chains usually verify with no chain sidecar; `prove-chain` is for the cases that still need an explicit sidecar.

| Flag | Description |
|---|---|
| `--source-envelope <path>` | Signed DSSE envelope of the upstream step (its payload sha256 becomes the chain binding). |
| `--source-sidecar <path>` | The upstream step's v0.3 leaf sidecar. |
| `--source-step <name>` | Upstream step name as declared in the policy (default `source`). |
| `--consumed <path=sha256hex>` | A consumed material; must appear in the upstream tree. Repeatable. |
| `--outfile <path>` | Output path for the chain sidecar JSON (required). |

## `cilock policy from-bundles`

> Reads one or more signed attestation bundles and emits a **starter Witness policy** — one step per bundle (step name = the bundle basename without the `.bundle.json` suffix), functionaries populated from each signing keyid, and `attestations[]` populated from the predicate types found. Edit, then sign with `cilock sign`. Use `--step-prefix` to prepend a prefix to every generated step name.

```bash
cilock policy from-bundles -k signer.pub build.bundle.json scan.bundle.json -o policy.json
```

## `cilock keyid`

> Prints the canonical keyid — `hex(sha256(PEM(pubkey)))` — derived from a public or private key. The same value that appears in policy `functionaries[].publickeyid` and in attestation signatures.

```bash
cilock keyid show -k key.pub
```

## `cilock attestors list`

Prints a box-drawn table of every attestor compiled into the binary:

```
┌──────────────────────────┬─────────────────────────────────────────────────────┬─────────────┐
│           NAME           │                        TYPE                         │  RUN TYPE   │
├──────────────────────────┼─────────────────────────────────────────────────────┼─────────────┤
│ git (default)            │ https://aflock.ai/attestations/git/v0.1             │ prematerial │
│ environment (default)    │ https://aflock.ai/attestations/environment/v0.1     │ prematerial │
│ material (always run)    │ https://aflock.ai/attestations/material/v0.3        │ material    │
│ command-run (always run) │ https://aflock.ai/attestations/command-run/v0.1     │ execute     │
│ product (always run)     │ https://aflock.ai/attestations/product/v0.3         │ product     │
│ inclusion-proof          │ https://aflock.ai/attestations/inclusion-proof/v0.1 │ postproduct │
│ material-v0.1            │ https://aflock.ai/attestations/material/v0.1        │ material    │
│ product-v0.1             │ https://aflock.ai/attestations/product/v0.1         │ product     │
│ product-v0.2             │ https://aflock.ai/attestations/product/v0.2         │ product     │
│ ...                      │ ...                                                 │ ...         │
└──────────────────────────┴─────────────────────────────────────────────────────┴─────────────┘
```

Run types are lowercase strings: `prematerial`, `material`, `execute`, `product`, `postproduct`, `verify`.

Markers: `(always run)` means the attestor runs on every `cilock run`; `(default)` means it's enabled by default and you don't need to pass it via `--attestations`. The full catalog is in the [attestor catalog](./attestor-catalog).

## `cilock attestors schema <name>`

Prints the JSON Schema document for the named attestor's predicate. Useful for writing Rego policies against a specific schema.

## `cilock policy validate <path>`

Validates a Witness/cilock policy document for schema correctness. Does not perform signature verification.

## `cilock completion <shell>`

Standard cobra completion. Supported shells: `bash`, `zsh`, `fish`, `powershell`.

## `cilock version`

Prints `cilock <version>`. The version string is injected at build time via `-ldflags="-X 'github.com/aflock-ai/rookery/cilock/cli.Version=<version>'"`.

## `cilock license`

Prints the license under which this binary is distributed, plus any branded-distribution metadata baked in at build time. The **stock `cilock` CLI** is **Apache 2.0**, so a stock binary shows the Apache 2.0 statement. Binaries produced by the [`rookery-builder`](../guides/build-a-custom-cilock) are licensed under the **Business Source License 1.1** and report BUSL instead (see [licensing](../ecosystem/rookery#licensing)). Custom binaries built with `--customer X --tenant Y` additionally show:

```
Built for: X
Tenant:    Y
```

The CustomerID and TenantID are injected via `-ldflags="-X 'github.com/aflock-ai/rookery/cilock/cli.CustomerID=...' -X 'github.com/aflock-ai/rookery/cilock/cli.TenantID=...'"`.

## Configuration file

CI/lock supports a YAML config file at `.witness.yaml` (legacy name from the witness lineage). The schema mirrors the CLI flag names. See [Configuration](./configuration) for the full schema and override behavior.
