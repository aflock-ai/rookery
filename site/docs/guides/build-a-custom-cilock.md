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

1. a logged-in or workflow-OIDC run emits the `platform` predicate without `attestor not found` or a no-binding soft skip;
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
