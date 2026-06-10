# Configuration Hierarchy

cilock follows the principle **everything user-overridable**. cilock is
**args-only** — there is no config file. Every built-in default exposed to
operators is reachable through at least one of three layers, applied in
**most-specific-wins** order.

## Override hierarchy

| Layer | Source | Notes |
|-------|--------|-------|
| 1 | **CLI flag** (per-invocation) | Highest precedence. An explicitly-passed flag wins over everything, including an empty value — `--platform-url=""` means "no platform", not "use the default". |
| 2 | **Env var** (`CILOCK_*`) | Set in the parent shell or CI job. Useful for cluster-wide tuning that you do not want to repeat on every `cilock run` invocation. |
| 3 | **Built-in default** (lowest) | Compiled-in fallback if no other layer resolves. Every default is regression-tested by `attestation/everything_overridable_test.go`. |

The precedence resolver helpers live in `cilock/internal/options/resolve.go`
(`ResolveString`, `ResolveInt`, `ResolveDuration`). New flags should route
through them; existing flags follow the same hierarchy via cobra defaults.

> Historical note: cilock inherited a `.witness.yaml` config-file layer from
> its witness lineage. It was removed deliberately — a config file in a cloned
> repo could silently override security-critical flags (archivista server,
> signing key paths, trust anchors). Flags and env vars are the whole surface.

## CLI flag reference (run / verify)

The list below covers the flags added or audited as part of the override audit.
For the full set, run `cilock run --help` and `cilock verify --help`.

| Flag | Command | Default | Env var | Notes |
|------|---------|---------|---------|-------|
| `--platform-url` | run | `https://platform.testifysec.com` | — | Pass `""` to disable platform-derived defaults. |
| `--archivista-server` | run, verify | derived from `--platform-url` | — | |
| `--no-default-attestor=<name>` (repeatable) | run | none | — | Drops the named always-on attestor (`product`, `material`). Disabling BOTH is a hard error. |
| `--prewalk-skip-dir=<name>` (repeatable) | run | (none, additive) | — | Adds a basename to the pre-trace walk skip list. Built-in defaults: `.git`, `node_modules`, `vendor`, `.cache`. |
| `--prewalk-include-dir=<name>` (repeatable) | run | (none) | — | Forces the walker to descend into the basename even if a default or `--prewalk-skip-dir` would skip it. Most-specific wins. |

## Env var reference

| Env var | CLI equivalent | Default | Notes |
|---------|----------------|---------|-------|
| `CILOCK_FANOTIFY_MAX_DIGESTS` | — (no CLI flag, advanced knob) | `200000` | Caps the fanotify digests map size. Zero/negative/unparseable falls back to the default with a stderr warning. |
| `CILOCK_FANOTIFY` | — | `1` (on) | Enables the fanotify zero-drop capture layer when supported. |
| `CILOCK_TRACE_MODE` | — | `auto` | Selects `ebpf` (default) vs `ptrace` tracing. |
| `CILOCK_HASH_WORKERS` | — | auto | Number of hashing goroutines in the eBPF consumer. |
| `CILOCK_FSVERITY` | — | off | Opt-in fs-verity sealing of trace outputs. |
| `CILOCK_DIAGNOSE` | `--diagnose` | off | Verbose internal logging across cilock subsystems (eBPF program loading, BPF CO-RE probe results, ringbuf drop reports). Replaces the per-feature `CILOCK_EBPF_DEBUG` / `CILOCK_BPF_DIAGNOSE` env vars. |
| `CILOCK_DEV_BPF_OBJECT_PATH` | — | — | **Dev-only**. Path to a prebuilt BPF object file; skips the embedded-object load. Not part of the supported operator surface. (Was: `CILOCK_BPF_OBJECT_PATH`.) |
| `CILOCK_DEV_BPF_REBUILD` | — | `on` | **Dev-only**. Set to `off` to disable the rebuild-on-CO-RE-failure path. (Was: `CILOCK_BPF_REBUILD`.) |
| `CILOCK_DEV_BPF_SKIP_PROGRAMS` | — | — | **Dev-only**. Comma-separated BPF program names to skip during load. Used to isolate CO-RE failures. (Was: `CILOCK_BPF_SKIP_PROGRAMS`.) |
| `ACTIONS_ID_TOKEN_REQUEST_URL` | `--archivista-oidc` (auto-enables when set) | — | Triggers GitHub Actions OIDC token fetch for Archivista auth. |

## Worked example: changing the product include-glob

Goal: include only `*.tar.gz` in the product attestor.

```bash
# Layer 3 (default): * (everything)

# Layer 2 (env var) — registry-routed attestor flags do not have
# corresponding env vars; use the CLI flag.

# Layer 1 (CLI flag): wins over everything
cilock run \
  --step build \
  --signer-file-key-path key.pem \
  --attestor-product-include-glob='*.tar.gz' \
  -- make release
```

Precedence: the CLI flag (layer 1) overrides the compiled-in default `*`
(layer 3). Remove the flag and the default applies.

## What's NOT overridable on purpose

These are deliberate exclusions, not gaps. Every entry is mirrored in
`deliberateExclusionsWhitelist` in `attestation/everything_overridable_test.go`
with a per-entry justification comment.

- **eBPF kprobe / fentry syscall set.** Kernel-side ABI. Adding or
  removing a hooked syscall changes which events the userspace consumer
  can observe; it is a code change, not a config change.
- **Schema versions** (`ChainSidecarSchemaVersion`, attestor predicate
  type strings, in-toto statement types). These pin the wire format
  between producer and verifier; bumping them is a coordinated
  multi-party change.
- **Crypto algorithm choices for the current version.** Hash algorithm
  selection (`--hashes`) IS overridable, but signing-curve / KDF
  decisions inside the signer providers are pinned to the version of
  the spec the signer implements. New algorithms ship as new signer
  providers, not as flags.
- **OCI / spec constants** (`DefaultRegistry`, `defaultRegistryAliases`).
  These mirror external specifications (Docker image-reference syntax).
  Changing them would break interoperability with every other tool
  in the ecosystem.
- **Process-wide singletons** (`defaultRegistry` in
  `attestation/detection`, `defaultResolver` in `k8smanifest`). These
  back internal package-level state where mutation would create a
  data race. They are not user-tunable.
- **Internal dispatch tables** (`defaultEncodingScanners` in
  secretscan). Adding a new encoding decoder is a code change with
  matching test coverage; it is not appropriate to wire it to a
  runtime knob.

## Adding a new default

If you are adding a new package-level `const default*` or `var default*`:

1. Add a CLI flag or env var that exposes it.
2. If the value is genuinely fixed (kernel boundary, schema version,
   internal singleton, etc.), add it to
   `attestation/everything_overridable_test.go`'s
   `deliberateExclusionsWhitelist` with a one-line justification
   comment.
3. Run `go test ./attestation -run TestEverythingOverridable`. If
   the test fails with `default constant "X" has no override path`,
   pick one of the two paths above before merging.
