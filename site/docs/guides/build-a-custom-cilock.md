---
title: Build a custom CI/lock
sidebar_position: 5
---

# Build a custom `cilock` binary

CI/lock is open source and standards-based. Its evidence is a signed [DSSE](https://github.com/secure-systems-lab/dsse) envelope containing an [in-toto Statement](https://github.com/in-toto/attestation), so you can fork CI/lock, audit it, and build a distribution for your environment.

Pushgate verifies the evidence, **not the `cilock` executable that produced it**. A custom binary is compatible only when the evidence satisfies the same producer/consumer contract as the released binary; sharing the command name or compiling the CLI package is not enough.

## The Pushgate evidence contract

Evidence intended for Pushgate must:

- be a valid DSSE envelope over an in-toto Statement;
- be signed through the platform Fulcio flow and, when required by the active policy and deployment, carry the platform RFC 3161 timestamp;
- bind the exact pushed commit in its signed subjects;
- use the collection and inner predicate schemas the active policy expects; and
- be stored as the exact signed bytes in the authenticated tenant's Archivista.

The predicate library is a producer/consumer boundary. Judge authoring accepts exact predicate URIs from its compiled registry or from evidence already observed in that tenant. Adding a custom attestor to your CI/lock fork does not register its type with Judge by itself: upload conforming evidence first, or coordinate compiled support when the policy needs typed server behavior rather than raw-JSON evaluation. Confirm that the exact URI is visible in the tenant's Judge attestation library before activating the policy; an unknown client-side plugin is not automatically available to a policy.

File, KMS, Vault, and SPIFFE signatures can be valid for other CI/lock workflows, but they do not replace the platform Fulcio trust chain Pushgate verifies today.

## Recommended Judge-compatible path: fork the stock main

For a custom distribution that must work with Judge and Pushgate, fork Rookery and customize the stock [`cilock/cmd/cilock/main.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/cmd/cilock/main.go). Keep these imports:

```go
// Resolves the stored platform session or ambient workflow identity into the
// signed platform binding.
_ "github.com/aflock-ai/rookery/cilock/internal/attestors/platform"

// Produces the certificate-backed signatures Pushgate trusts.
_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
```

Remove attestor imports you do not need and add reviewed attestor modules as blank imports. Then build from the `cilock` module in your fork:

```bash
git clone https://github.com/your-org/rookery.git
cd rookery/cilock
go build -trimpath -o ../bin/cilock ./cmd/cilock
../bin/cilock version
../bin/cilock attestors list --format json
```

Keeping the custom main inside the `github.com/aflock-ai/rookery/cilock` module is important: Go's `internal` package rule prevents a generated main in an unrelated module from importing the platform session adapter.

If your fork adds a new predicate type, confirm that Judge recognizes the exact URI through the compiled registry or tenant-observed evidence, then test the Fulcio-signed, timestamped evidence path before activating a policy that requires it.

## Compiled evidence defaults

Choose evidence defaults once for your distribution. Users and agents then need no per-run profile arguments. The stock main uses these string variables from `github.com/aflock-ai/rookery/cilock/internal/config`:

| Variable | Source default | Meaning |
|---|---|---|
| `DefaultEvidenceProfile` | `"compact"` | Compact material/product representation. `"compact-chain"` also enables material retention and inventory upload consent. `"legacy"` preserves the previous representation. |
| `DefaultProductInlineBytes` | `"131072"` | Maximum serialized product predicate size for inline encoding in compact builds, in bytes. |

These are build-time operator choices, not runtime profile flags. The CLI validates them before a run. The valid profiles are `compact`, `compact-chain`, and `legacy`. The budget must be a base-10 integer from `0` through `2147483647`, including in a legacy build. Invalid compiled values cause an error rather than a silent fallback. A successful `go build` alone does not validate those values.

For artifact-chain producers, compile `compact-chain` once rather than give users or agents a per-run inventory flag list. This profile retains materials and uploads retained inventories before the collection when Archivista is enabled. It does not enable a store or grant credentials.

From your fork's `cilock` module:

```bash
go build -trimpath \
  -ldflags "-X github.com/aflock-ai/rookery/cilock/internal/config.DefaultEvidenceProfile=compact-chain" \
  -o ../bin/cilock-chain ./cmd/cilock
../bin/cilock-chain version
../bin/cilock-chain run --help-advanced
```

Check that the help reports `--material-manifest` and `--upload-inventories` with `(default true)`. Then distribute that binary under your chosen command name. These are source-build instructions, not a claim that an installed release has compact support. Before requiring compact inventories remotely, verify support in the deployed consumer too.

From your fork's `cilock` module, build the stock main with the legacy representation:

```bash
go build -trimpath \
  -ldflags "-X github.com/aflock-ai/rookery/cilock/internal/config.DefaultEvidenceProfile=legacy" \
  -o ../bin/cilock-legacy ./cmd/cilock
```

For a compact build with a 64 KiB inline product budget:

```bash
go build -trimpath \
  -ldflags "-X github.com/aflock-ai/rookery/cilock/internal/config.DefaultProductInlineBytes=65536" \
  -o ../bin/cilock-compact ./cmd/cilock
```

The 64 KiB example keeps the source default `compact` profile. A budget of `0` detaches every nonempty product inventory. Changing only the budget does not change attestor selection, capture, signing identity, or upload consent. These instructions describe source builds, not the behavior of a deployed release.

### Compact representation

- With `compact`, a nonempty material set keeps its v0.3 root commitment and an `inventory` reference with `state: "omitted"`. With `compact-chain`, the CLI retains the details in a signed local companion and the reference has `state: "detached"`.
- Products remain inline when the complete serialized product predicate fits the budget and the inline encoding preserves every captured path. Duplicate-content paths require detachment even below the budget. Otherwise, the CLI retains the complete product inventory in a signed local companion.
- Confirmed empty sets retain the existing empty commitment encoding. Omitted or missing details are not empty sets.

The default 131072-byte (128 KiB) budget applies to the inline product predicate, not the whole signed envelope. Capture and the before-command baseline remain unchanged. Compact encoding does not establish reduced scan CPU cost, isolation, or hermeticity.

The `material` and `product` names and their `https://aflock.ai/attestations/material/v0.3` and `https://aflock.ai/attestations/product/v0.3` URIs do not change. Existing material/product v0.3 evidence remains readable, with legacy manifest fields retaining their original meaning. Direct library `material.New()` and `product.New()` calls keep their legacy inline defaults. The CLI applies the compiled profile separately.

The root commits to distinct file contents, not every path or duplicate-content occurrence. The signed `inventory.digest` binds the exact inventory manifest bytes, including all retained paths and metadata.

### Local retention and upload

In a `compact` build, `--material-manifest` retains full material details as a signed local companion. The `compact-chain` profile enables this retention by default. Product inventories that cannot stay inline are retained automatically. Companions are private files beside an explicit `--outfile`.

Without `--outfile`, a run that needs companions creates a private persistent `evidence/run-*` directory under the Cilock auth-state directory. The CLI prints its location and stores the collection and companions there. On Unix, automatic directories use mode `0700`, and evidence files use `0600`. On Windows, Cilock creates and verifies protected current-user-only ACLs and rejects reparse points. Compact builds refuse existing evidence files instead of overwriting them. Headless inventory retention and upload never prompt.

The `compact` profile keeps inventory upload off unless `--upload-inventories` explicitly permits it. The `compact-chain` profile supplies that consent at build time. Upload still requires an enabled Archivista store. Retention does not enable upload, and upload consent does not enable retention or Archivista itself. Inline product details travel with the collection. Local retention does not imply remote availability. Legacy builds retain their previous material-manifest behavior, including upload when Archivista is enabled.

Explicit `--material-manifest=false` disables material retention. Explicit `--upload-inventories=false` keeps detached inventories local even when the collection uploads. These overrides are independent. Offline runs without an enabled store keep retained inventories local instead of applying the compiled upload default. An explicit upload request without an enabled store fails.

A command-only policy can pass without optional inventory details. Artifact-chain checks require complete input data and the relevant product evidence. Omitted, missing, or invalid required inventories fail explicitly. Policy generation also refuses to infer artifact links from unavailable details. Use a `compact-chain` distribution for those workflows. Keep required companions with local evidence, and verify upload before relying on a remote verifier.

The signed schema, retention boundary, and consumer requirements follow the CI/lock compact-inventories contract.

### Platform and trust defaults are separate

The existing `config.DefaultPlatformURL` build override and your distribution's trust configuration remain separate from these evidence defaults. Selecting a platform, logging in, or changing trust roots does not select an evidence profile. No evidence profile authorizes signing or changes trusted identities. Only `compact-chain` supplies default inventory-upload consent, and it still requires an enabled store. Keep the stock platform adapter and Fulcio signer required by the Pushgate contract.

Agents produce evidence as enrolled agent principals. They can start `cilock enroll agent`, but the human must approve enrollment. A stored human login is not a substitute. Humans sign authoritative policies and approve exact repository assignments separately. A custom binary does not authorize an agent to sign as a human. Product `policy bind` is not Pushgate activation.

## `rookery-builder`: generic and offline distributions

The released `cilock` uses a curated attestor set plus the `file`, `fulcio`, and `piv` signers. If you need an opt-in signer (`debug-signer`, `kms/aws`, `kms/gcp`, `kms/azure`, `spiffe`, `vault`, `vault-transit`), a smaller offline binary, or a custom plugin for a verifier you control, **rookery-builder** can generate the generic `run` / `verify` / `sign` CLI with the selected plugins.

The current builder is not a safe shortcut for a Judge-compatible fork. Its generated main cannot import CI/lock's internal platform adapter, and its presets do not register that adapter. A logged-in default `cilock run` therefore retains the default `platform` attestor but has no session-aware implementation to resolve it. The `minimal` and `cicd` presets also omit the Fulcio signer. Importing the public `plugins/attestors/platform` package by itself does not fix this: that package requires its caller to supply an already-authorized binding.

Use rookery-builder for offline or bring-your-own-verifier workflows until it has a platform-aware generated-main contract and an end-to-end Judge compatibility test.

> Source: [`rookery/builder`](https://github.com/aflock-ai/rookery/tree/main/builder).

## Install the builder

```bash
go install github.com/aflock-ai/rookery/builder/cmd/builder@latest
# The binary installs as `builder` (into GOBIN, or GOPATH/bin when GOBIN is unset);
# give it the name these docs use:
BIN="$(go env GOBIN)"; BIN="${BIN:-$(go env GOPATH)/bin}"
mv "$BIN/builder" "$BIN/rookery-builder"
rookery-builder --help
```

Or invoke it from a rookery checkout:

```bash
git clone https://github.com/aflock-ai/rookery
cd rookery
go run ./builder/cmd/builder/ --help
```

## Add KMS to an offline or bring-your-own-verifier build

```bash
rookery-builder \
  --preset cicd \
  --with github.com/aflock-ai/rookery/plugins/signers/kms/aws \
  --output ./cilock
./cilock --help          # shows the full cilock cobra tree
./cilock attestors list  # confirms the manifest's attestor set
```

This verifies that the selected CLI and plugins compiled. It does not establish Pushgate compatibility; Pushgate still requires the evidence contract above.

## Presets

| Preset | What it includes |
|---|---|
| `minimal` | `commandrun`, `environment`, `git`, `material`, `product` + `file` signer |
| `cicd` | `minimal` + `github`, `gitlab`, `slsa` |
| `all` | The builder's broad curated attestor set + all signer modules listed by the builder |

```bash
rookery-builder --preset minimal --output ./cilock-min
rookery-builder --preset cicd    --output ./cilock-cicd
rookery-builder --preset all     --output ./cilock-everything
```

## Adding plugins with `--with`

Layer additional plugins onto any preset. Each `--with` accepts a Go module path, optionally with a version:

```bash
# rookery plugin, latest
--with github.com/aflock-ai/rookery/plugins/signers/spiffe

# rookery plugin, pinned
--with github.com/aflock-ai/rookery/plugins/attestors/maven@v0.1.3

# third-party plugin (build-time inclusion only; consumer support is separate)
--with github.com/your-org/custom-attestor@v1.2.0

# local plugin (replace directive)
--with github.com/your-org/custom-attestor=../local-plugin

# local path
--with ./path/to/local-plugin
```

## Manifest-driven builds

For reproducible, checked-in build definitions, use a YAML manifest:

```yaml
# build.yaml
name: my-cilock
output: ./bin/my-cilock
preset: cicd
plugins:
  - module: github.com/aflock-ai/rookery/plugins/signers/kms/aws
  - module: github.com/aflock-ai/rookery/plugins/attestors/maven
    version: v0.1.3
  - git: git@github.com:your-org/private-attestor
    ref: v2.0.0
    subdir: plugins/foo
  - path: ../local-plugin
```

```bash
rookery-builder --manifest build.yaml
```

The manifest path supports Git SSH for private repos and a checked-in build definition. The bare `--with` form also supports `@version` pins.

## FIPS mode

```bash
--fips on    # default; Go's FIPS 140-3 provider compiled in, runtime-selectable
--fips only  # boring crypto only; non-compliant algorithms fail at runtime
--fips off   # standard Go crypto
```

## Branded distribution: `--customer` / `--tenant`

For organizations distributing CI/lock variants to their teams or customers:

```bash
rookery-builder --preset cicd \
  --customer acme-corp \
  --tenant acme-prod \
  --output ./acme-cilock
./acme-cilock license
# ...
# Built for: acme-corp
# Tenant:    acme-prod
```

The `CustomerID` and `TenantID` get baked into the binary via `-ldflags` and surface through `cilock license`. Useful for support workflows where users include the output of `cilock license` in bug reports.

## Verifying your build

```bash
./cilock --help          # full cobra tree (run, verify, sign, attestors, policy, license, version)
./cilock attestors list  # every attestor compiled in
./cilock version         # build metadata
./cilock license         # license + branded metadata if set
```

These checks verify the binary's local surface only. For a Judge-compatible fork, also test that:

1. an enrolled-agent or registered workflow-OIDC run emits the `platform` predicate without `attestor not found` or a no-binding soft skip;
2. the DSSE signature chains to the Fulcio roots configured by Pushgate and includes the required platform timestamp;
3. the signed collection contains the exact commit subject; and
4. every policy-required predicate URI is present in Judge's compiled-or-tenant-observed attestation library.

## What the builder actually does

1. Resolves every plugin spec — preset entries, `--with` flags, manifest plugins — to a concrete Go module + version (or local path with a `replace` directive).
2. Generates a temporary `main.go` that blank-imports each selected plugin and calls `attestation.RegisterLegacyAliases()` + `cli.Execute()`. It provides the generic CLI shape, but it does not include the stock main's internal platform adapter.
3. Generates a `go.mod` listing only the resolved plugins as direct dependencies.
4. Runs `go build -trimpath` (with FIPS build tags as configured) to produce the output binary.

The `attestation`, `cilock/cli`, and other shared rookery modules are picked up transitively. Adding a plugin that doesn't exist fails at the `go build` step with a clear error.

## Local development

```bash
rookery-builder --local --preset minimal --output ./cilock-dev
```

`--local` autodetects the rookery root and adds `replace` directives for every workspace module, so the build uses your in-tree code. Required when testing changes to attestors or signers before publishing.

## Air-gapped builds

The builder needs network access during `go build` to fetch modules. For air-gapped environments:

1. Run with `GOPROXY=https://your-mirror.internal`.
2. Or use a manifest with `path:` entries pointing at a vendored rookery tree.

Once built, the generated binary is fully static (CGO disabled) and has no runtime network dependencies for the signers themselves — only those that talk to network APIs (`fulcio`, `kms/*`, `vault*`, `archivista`).

## See also

- [Installation](../getting-started/installation) — the prebuilt-binary path
- [Choose a signer](./choose-a-signer) — which signers ship by default vs require a custom build
- [Rookery ecosystem](../ecosystem/rookery) — the monorepo layout
- [rookery-builder source](https://github.com/aflock-ai/rookery/tree/main/builder)
