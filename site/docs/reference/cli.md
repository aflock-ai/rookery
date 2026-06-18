---
title: CLI reference
sidebar_position: 1
---

# `cilock` CLI reference

> Source of truth: [`rookery/cilock/cmd/cilock/main.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/cmd/cilock/main.go) and [`rookery/cilock/internal/cmd/`](https://github.com/aflock-ai/rookery/tree/main/cilock/internal/cmd). Defaults and flag names below track the released `cilock` and are completeness-gated against the binary in CI (`scripts/check-cli-coverage.mjs`) — every command has a section here.

```
cilock - Collect and verify attestations about your build environments
```

CI/lock attestation types use the `https://aflock.ai/attestations/<name>/v0.1` namespace. Witness-style URLs (`https://witness.dev/attestations/<name>/v0.1`) are accepted via legacy aliases for interop with witness-produced evidence.

## Top-level commands

| Command | Purpose |
|---|---|
| `cilock login` | Sign in to the platform and store a session bound to a working tenant + product. |
| `cilock use` | Switch the working tenant/product the stored session binds attestations to. |
| `cilock whoami` | Show the current platform session (tenant, product, expiry). |
| `cilock logout` | Remove the stored platform session credential. |
| `cilock trust [provider] [owner/repo]` | Register an OIDC identity the platform trusts for keyless upload (CI). |
| `cilock doctor` | Read-only preflight: is the environment sane to attest + upload against the platform? |
| `cilock run [cmd]` | Run a command and record signed attestations about its execution. |
| `cilock attest` | Record attestations without wrapping a command (sugar for `run -- true`; for consultative/at-rest attestors). |
| `cilock sign [file]` | Sign an arbitrary file (typically a policy) with the configured signer. |
| `cilock verify` | Verify an artifact (subject) against a signed policy using attestations as evidence. |
| `cilock policy from-bundles` | Generate a starter Witness policy from one or more signed attestation bundles. |
| `cilock policy from-commit` | Author a Witness policy from a commit's CI attestations already in the platform's Archivista. |
| `cilock policy push` | Upload a signed policy DSSE to the platform and create a release. |
| `cilock policy bind` | Bind a published policy definition/release to a product on the platform. |
| `cilock policy validate` | Validate a Witness/cilock policy document (schema only, no signature check). |
| `cilock keyid` | Print the canonical keyid (`hex(sha256(PEM(pub)))`) derived from a public or private key. |
| `cilock bundle create` / `inspect` | Build or inspect a portable attestation bundle (tar.gz of DSSE envelopes). |
| `cilock plan -- <cmd>` | Show which attestors detection would fire for a command, without executing it. |
| `cilock attestors list` | List every attestor compiled into the binary. |
| `cilock attestors schema <name>` | Print the JSON schema of a specific attestor's predicate. |
| `cilock tools list` / `show` / `test-plan` | List supported detectors, show one, or emit per-tool test plans. |
| `cilock completion <shell>` | Emit shell completion script (bash, zsh, fish, powershell). |
| `cilock version` | Print the `cilock` version. |

## Global flags

These persistent flags are accepted on every subcommand:

| Flag | Default | Notes |
|---|---|---|
| `--log-level, -l <level>` | `info` | One of `debug`, `info`, `warn`, `error`. |
| `--debug-cpu-profile-file <path>` | (none) | Write a CPU pprof profile to this path. Profiling enabled when non-empty. |
| `--debug-mem-profile-file <path>` | (none) | Write a heap pprof profile to this path. Profiling enabled when non-empty. |

## Platform session & CI trust

These commands establish and inspect the platform session that attestation **upload** (and keyless signing-token exchange) need. Signing itself is keyless and needs no login; uploading to Archivista binds the evidence to your tenant/product, which is what the session carries. The onboarding path is `login` → (`use` to switch scope) → `trust` to let CI upload → `doctor` to preflight.

The platform is derived from a single `--platform-url` (default `https://platform.testifysec.com`); it auto-resolves Fulcio, TSA, and Archivista from that host's discovery document. After login, bare commands default to the platform you logged into.

### `cilock login`

Sign in and store a session credential. The browser approve page binds a working **tenant AND product** — creating a default tenant/product if you have none — so every subsequent attestation is scoped to one. Identity resolves by precedence: `--token` (explicit JWT, CI/headless; `-` reads stdin) → ambient CI workflow OIDC (GitHub Actions, auto-detected) → interactive browser (default for local use).

| Flag | Default | Description |
|---|---|---|
| `--platform-url <url>` | `https://platform.testifysec.com` | Platform to sign in to. |
| `--token <jwt>` | (none) | JWT for CI/headless login (skips the browser); `-` reads it from stdin. |
| `--workflow-identity` | `false` | Use the ambient CI workflow OIDC identity (auto-detected on the default platform; **required** to send a workflow token to a non-default `--platform-url`). |
| `--interactive` | `false` | Force the interactive browser login (skip ambient CI identity). |
| `--tenant <id\|name>` / `--product <id\|name>` | (none) | Pre-select tenant/product on the approve page. |
| `--tenant-id <uuid>` / `--product-id <uuid>` | (none) | Bind tenant/product directly for a headless `--token` login. |
| `--tenant-name` / `--product-name <str>` | (none) | Label to record alongside `--tenant-id` / `--product-id`. |
| `--allow-trust` | `false` | Also grant the narrow `oidc:write` scope so this session can run [`cilock trust`](#cilock-trust). Off by default. |

```bash
# Interactive browser login (binds tenant+product on the approve page)
cilock login

# CI on GitHub Actions: ambient workflow identity (needs permissions: id-token: write)
cilock login --workflow-identity --platform-url "$PLATFORM_URL"

# CI/headless with an explicit JWT + the tenant+product to bind
cilock login --platform-url https://platform.example.com --token "$TESTIFYSEC_TOKEN" \
  --tenant-id <uuid> --product-id <uuid>
```

### `cilock use`

Switch the working tenant + product the stored session binds attestations to, so `cilock run` scopes evidence without re-prompting. Requires an existing session (`cilock login` first). The analog of `kubectl config use-context` for cilock.

| Flag | Default | Description |
|---|---|---|
| `--product-id <uuid>` / `--tenant-id <uuid>` | (none) | Bind directly (no browser). |
| `--product-name` / `--tenant-name <str>` | (none) | Label recorded alongside the id. |
| `--product <id\|name>` / `--tenant <id\|name>` | (none) | Select by name on the approve page (re-opens the browser to resolve names → ids, auto-creating a default tenant/product if you have none). |
| `--platform-url <url>` | active session's platform | Platform whose session to rebind. |

```bash
# Switch the working product by id (no browser)
cilock use --product-id 5664d4f5-9003-41e8-90e4-035c51d09b45 --product-name acme-web

# Pick or create tenant+product interactively
cilock use

# Pre-select by name on the approve page
cilock use --tenant acme --product acme-web
```

### `cilock whoami`

Show the current platform session — the logged-in tenant, bound product, and expiry — for the given (or active) platform.

| Flag | Default | Description |
|---|---|---|
| `--platform-url <url>` | active session's platform | Platform whose session to show. |

```bash
cilock whoami
```

### `cilock logout`

Remove the stored platform session credential.

| Flag | Default | Description |
|---|---|---|
| `--platform-url <url>` | `https://platform.testifysec.com` | Platform whose session to remove. |

```bash
cilock logout
```

### `cilock trust`

Register an OIDC **federated** identity the platform will trust for keyless attestation upload — the CI complement to [`cilock run`](#cilock-run-cmd). It creates an OIDC credential only; cilock never mints a long-lived API-token secret. Run it as a tenant admin after `cilock login --allow-trust` (the `oidc:write` scope is opt-in). The audience defaults to the same `${platform}/archivista` that `cilock run` uploads to, and the subject is templated from the provider's claim convention, so trust and run can't drift. Providers: `github`, `gitlab` (or `--issuer` + `--subject` for any other); on-prem GHES / self-hosted GitLab add `--host`.

| Flag | Default | Description |
|---|---|---|
| `[provider] [owner/repo]` | auto-detect repo | Positional: e.g. `github testifysec/judge`. With no args (interactive), detects the current repo. |
| `--host <host>` | (none) | On-prem instance host for the provider (e.g. `github.acme.com`). |
| `--issuer <url>` / `--subject <glob>` | (none) | Generic provider escape hatch (use together). |
| `--audience <aud>` | `${platform-url}/archivista` | OIDC audience (matches `cilock run`). |
| `--scope <s>` | `attestation:upload` | Repeatable. Only `attestation:{upload,read,verify}` allowed. |
| `--verify` | `false` | Also grant `attestation:read` (for `cilock verify --enable-archivista`). |
| `--allowed-ip <cidr>` | any | Source IP/CIDR allowlist (repeatable; e.g. the runner egress). |
| `--name` / `--description <str>` | `<provider>:<slug>` | Credential name / description. |
| `--tag <t>` | (none) | Categorization tag (repeatable). |
| `--tenant <id>` | logged-in working tenant | Tenant to register the trust under. |
| `--dry-run` | `false` | Print what would be created without calling the platform. |
| `--yes, -y` | `false` | Skip the interactive confirmation. |

```bash
# Trust a GitHub repo's Actions to upload (most common)
cilock trust github testifysec/judge

# Interactive: auto-detect the current repo and confirm
cilock trust

# On-prem GitHub Enterprise Server
cilock trust github acme/app --host github.acme.com

# Any OIDC provider (generic escape hatch)
cilock trust --issuer https://oidc.corp/foo --subject sub:acme:prod
```

### `cilock doctor`

Read-only preflight (no build, no upload) of a cilock attestation environment. Prints a green/red checklist: logged in? platform reachable (`.well-known/judge-configuration` discovery)? Fulcio / TSA / Archivista destinations (derived + discovered); upload authorization (login session origin matches Archivista origin). Run it before a multi-minute `cilock run` to confirm signing + upload will work. `--json` emits a machine-readable report an agent can gate on (`report.ok`).

| Flag | Default | Description |
|---|---|---|
| `--platform-url <url>` | `https://platform.testifysec.com` | Platform to probe. |
| `--json` | `false` | Emit the preflight report as a single JSON object (`report.ok` is the rollup to gate on). |

```bash
# Check the default hosted platform
cilock doctor

# Check a self-hosted / standalone platform, machine-readable
cilock doctor --platform-url https://judge.example.com --json
```

## `cilock run [cmd]`

> Runs the provided command and records attestations about the execution.

Always-run attestors (cannot be omitted): `material`, `product`, and (when args are provided) `command-run`. Trying to pass `command-run` via `--attestations` is rejected.

Only **one signer** is supported per `run` invocation (enforced at `cilock/internal/cmd/run.go:71-73`).

### Common flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--step <name>` | `-s` | inferred | Step category. Optional — when omitted, [inferred from the wrapped command](../concepts/step-categories). Must be a value from the step lexicon. |
| `--attestations <list>` | `-a` | `environment,git,platform` | **Comma-separated** attestors (`product` + `material` are always recorded). Passing `-a` disables [auto-detection](../concepts/auto-detection-and-defaults) (set becomes exact) unless `--workload auto`. |
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

## `cilock plan`

> Dry-run of [`cilock run`](#cilock-run-cmd)'s pre-gate detection: prints which attestors **would fire** for a hypothetical command, which would be skipped (with reasons), and any warnings — **without executing** the command. Take the names from the `fire` list and pass them to `cilock run -a <attestor>,...` to run the planned set.

| Flag | Default | Description |
|---|---|---|
| `-- <command> [args...]` | (required) | The command to plan for (after the `--` separator). |
| `--format <fmt>` | `text` | `text` or `json` (machine-readable, for an agent to consume). |
| `--verbose, -v` | `false` | Include the full skip list (every detector considered) in text output. |

```bash
# Show which attestors would fire for a build, without running it
cilock plan -- go build ./...

# Machine-readable plan for an agent to consume
cilock plan --format json -- docker build -t app .
```

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

Because v0.3 product/material attestations [inline their Merkle leaves](../attestors/product) by default, `cilock verify <artifact> -p policy -a <attestations>` resolves the artifact's digest to its signed tree with **no separate inclusion-proof envelope** — the inclusion-proof bridge maps the artifact's sha256 to the `tree:products` root directly from the signed attestation's inline leaves.

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
| `--policy-timestamp-servers <list>` | (none) | Trusted TSA CA cert paths for verifying timestamped policies. |
| `--verifier-kms-*` | (none) | Same shape as `--signer-kms-*`, used when the policy's public key is referenced by a KMS URI. |

Full verifier flag list is in [`cilock/internal/options/verify.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/internal/options/verify.go).

Exit code **0** on policy pass, non-zero on any verification failure or error.

## `cilock bundle`

> Build or inspect a portable attestation **bundle** (a tar.gz of DSSE envelopes) — the offline-evidence companion to [`cilock verify --bundle`](#cilock-verify). `create` walks Archivista's subject graph from a digest and packs everything reachable; `inspect` prints a bundle's manifest so you can see what's inside before verifying.

### `cilock bundle create`

Pulls every DSSE envelope reachable from the given subject digest(s) via Archivista's subject graph and packs them into a tar.gz.

| Flag | Default | Description |
|---|---|---|
| `--subject, -s <digest>` | (required) | Subject digest(s) to seed the graph walk (e.g. `sha256:abc...`). Repeatable. |
| `--output, -o <path>` | stdout | Path to write the bundle (tar.gz). |
| `--max-depth <n>` | `5` | Maximum subject-graph traversal depth. |
| `--max-envelopes <n>` | `10000` | Maximum envelopes to fetch before aborting. |

```bash
cilock bundle create -s sha256:<digest> -o evidence.tar.gz
```

### `cilock bundle inspect`

Print a bundle's manifest and a per-envelope summary.

| Flag | Default | Description |
|---|---|---|
| `<bundle.tar.gz>` | (required) | Bundle to inspect. |
| `--json` | `false` | Emit the manifest as JSON (suppresses the per-envelope summary). |

```bash
cilock bundle inspect evidence.tar.gz
# then verify offline against it:
cilock verify ./app -p policy.signed.json -k pub.pem --bundle evidence.tar.gz --platform-url ""
```

## `cilock attest`

> Records attestations against the current context **without wrapping a command** — sugar for `cilock run -- true`. Every `run` flag works here. Use it for consultative / at-rest attestors that snapshot state (e.g. `github-review`, `aws-iid`) rather than observe a command.

```bash
cilock attest -a github-review -k key.pem -o review.bundle.json -s review-head
```

## `cilock policy from-bundles`

> Reads one or more signed attestation bundles and emits a **starter Witness policy** — one step per bundle (step name = the bundle basename without the `.bundle.json` suffix), functionaries populated from each signing keyid, and `attestations[]` populated from the predicate types found. Edit, then sign with `cilock sign`. Use `--step-prefix` to prepend a prefix to every generated step name.

```bash
cilock policy from-bundles -k signer.pub build.bundle.json scan.bundle.json -o policy.json
```

## `cilock policy from-commit <commit-sha>`

> Authors a starter Witness policy from the CI attestations the platform already holds for a commit — no local bundle files needed. It resolves the commit, finds every DSSE whose subjects include it, groups them by witness collection name (one step per collection), populates functionaries from each collection's signers (raw keyid or Fulcio keyless cert with the leaf SAN email pinned), recovers TSA trust anchors so short-lived keyless leaves verify, and wires cross-step provenance edges. Author-only by default (write the policy, then `cilock sign` → [`policy push`](#cilock-policy-push---file--definition---tag) → [`policy bind`](#cilock-policy-bind---definition--product)); pass both `--product` and `--tag` for the one-shot derive → sign → push → bind flow. The Archivista query needs a logged-in session; the one-shot mutations need `policy:write`.

| Flag | Default | Description |
|---|---|---|
| `--definition, -d <name>` | the product name | PolicyDefinition name for the one-shot flow. |
| `--description <str>` | (none) | Description used only when the one-shot flow creates a new PolicyDefinition. |
| `--expires <dur>` | `8760h` (1 year) | How far in the future the policy's `expires` field is set. Set short and re-issue after review. |
| `--output, -o <path>` | `-` (stdout) | Write the authored policy here. Ignored in one-shot mode. |
| `--platform-url <url>` | the logged-in platform | TestifySec platform URL. |
| `--product, -p <id\|name>` | (none) | Product id or exact name. With `--tag`, runs the one-shot sign→push→bind flow against this product. |
| `--step-prefix <str>` | (none) | Optional prefix prepended to every generated step name (e.g. `release-`). |
| `--tag, -t <t>` | (none) | Release tag for the one-shot flow (requires `--product`). |

```bash
# Author a policy from a commit's CI evidence, write it for review
cilock policy from-commit 1a2b3c4d... -o policy.json

# One-shot: derive, sign keyless, publish a release tagged v1, bind to a product
cilock policy from-commit 1a2b3c4d... --product my-service --tag v1
```

## `cilock policy push --file --definition --tag`

> Publishes an author-signed Witness policy to the platform. It uploads the signed policy DSSE to the platform's Archivista (the same upload path as `cilock run --enable-archivista`), ensures the named PolicyDefinition exists (creating it if absent), then creates a PolicyRelease that pins the definition to the uploaded policy under `--tag`. The policy file must already be DSSE-signed — produce it with `cilock sign` against the platform's keyless Fulcio. The DSSE upload needs `attestation:upload`; creating the release needs `policy:write`.

| Flag | Default | Description |
|---|---|---|
| `--file, -f <path>` | (required) | Path to the DSSE-signed policy (from `cilock sign`). |
| `--definition, -d <name>` | (required) | PolicyDefinition name; created if it doesn't exist. |
| `--tag, -t <t>` | (required) | Release tag (e.g. a semver or string). |
| `--description <str>` | (none) | Description used only when creating a new PolicyDefinition. |
| `--platform-url <url>` | the logged-in platform | TestifySec platform URL. |

```bash
# Sign first, then publish a release tagged v1.0.0
cilock sign -f policy.json -o policy.signed.json
cilock policy push --file policy.signed.json --definition supply-chain --tag v1.0.0
```

## `cilock policy bind --definition --product`

> Binds a published policy to a product on the platform. It resolves the named PolicyDefinition and the target product, then creates a PolicyBinding linking them. Pass `--release` (a release id) or `--tag` (resolved to a release under the definition) to pin a specific release; omit both to bind the definition itself. Creating the binding needs `policy:write`.

| Flag | Default | Description |
|---|---|---|
| `--definition, -d <name>` | (required) | PolicyDefinition name. |
| `--product, -p <id\|name>` | (required) | Product id or exact name to bind to. |
| `--release <id>` | (none) | PolicyRelease id to bind (overrides `--tag`). |
| `--tag, -t <t>` | (none) | Release tag to resolve under the definition. |
| `--platform-url <url>` | the logged-in platform | TestifySec platform URL. |

```bash
# Bind a definition's v1.0.0 release to a product (by exact name)
cilock policy bind --definition supply-chain --tag v1.0.0 --product my-service
```

## `cilock keyid show`

> Prints the canonical keyid — `hex(sha256(PEM(pubkey)))` — derived from a public or private key. The same value that appears in policy `functionaries[].publickeyid` and in attestation signatures. Reads PEM public keys (PKIX) or private keys (PKCS#8/PKCS#1/SEC1; the public half is extracted). One line per input (`<keyid>  <path>`, matching `sha256sum`'s shape). Keys come from positional args or `-k/--key`.

| Flag | Default | Description |
|---|---|---|
| `<key-file>...` / `--key, -k <path>` | (required) | Public or private key(s). `-k` takes a single file; mixing `-k` with positional args is an error. |
| `--format <fmt>` | `text` | `text` = sha256sum-style lines; `json` = JSON array (for `jq`). |

```bash
cilock keyid show signer.pub
cilock keyid show signer.key signer.pub other.pem
cilock keyid show --format=json signer.key | jq .
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

## `cilock tools`

> The catalog of detectors cilock knows how to auto-fire (the same source [cilock.dev's tool pages](../tools/) render from). `list` enumerates them, `show` prints one tool's full record, `test-plan` emits a validation plan.

### `cilock tools list`

List every detector cilock knows how to auto-fire.

| Flag | Default | Description |
|---|---|---|
| `--category <cat>` | (all) | Filter by lexicon category (e.g. `build`, `vulnerability-scan`, `ci-context`, `sbom-generate`). |
| `--source <src>` | (all) | Filter: `attestor-backed` \| `catalog-only`. |
| `--format <fmt>` | `table` | `table` or `json`. |

```bash
cilock tools list
cilock tools list --category vulnerability-scan --format json
```

### `cilock tools show <name>`

Show full catalog detail for one tool/attestor — the same record the website generates from.

| Flag | Default | Description |
|---|---|---|
| `<name>` | (required) | Tool/attestor to show (e.g. `sarif`). |
| `--section <slug>` | (all) | Print only one documentation section, by slug (see the summary). |
| `--format <fmt>` | `text` | `text` or `json` (the full machine-readable record). |

```bash
cilock tools show sarif
cilock tools show sarif --section policy-gotcha
cilock tools show sarif --format json
```

### `cilock tools test-plan`

Emit a structured test plan describing how to validate each detector (what triggers it, the expected fire decision, and a negative case). Pipe `--format=json` into a runner that exercises each scenario against `cilock plan`.

| Flag | Default | Description |
|---|---|---|
| `--only <name>` | (all) | Limit the plan to a single detector. |
| `--format <fmt>` | `markdown` | `markdown` or `json`. |

```bash
cilock tools test-plan
cilock tools test-plan --only sarif --format json
```

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

## Configuration

CI/lock is **args-only**: there is no config file. CLI flags (highest precedence), a small set of `CILOCK_*` env vars, and built-in defaults are the entire configuration surface. See [Configuration](./configuration) for the override hierarchy. (The legacy `.witness.yaml` config file inherited from the witness lineage was removed deliberately — a config file in a cloned repo could silently override security-critical flags.)
