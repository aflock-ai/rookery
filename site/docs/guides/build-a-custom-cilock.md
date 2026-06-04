---
title: Build a custom CI/lock
sidebar_position: 5
---

# Build a custom `cilock` binary

The prebuilt `cilock` ships every attestor plus two signers (`file`, `fulcio`). If you need one of the seven opt-in signers (`debug-signer`, `kms/aws`, `kms/gcp`, `kms/azure`, `spiffe`, `vault`, `vault-transit`), or want a slimmer binary that only includes the plugins you actually use, or want to add a third-party plugin, use the **rookery-builder**.

The builder is a real CI/lock generator — same `run` / `verify` / `sign` CLI surface, same wire format, same config-file schema. The only difference is the plugin set you choose.

> Source: [`rookery/builder`](https://github.com/aflock-ai/rookery/tree/main/builder).

## Install the builder

```bash
go install github.com/aflock-ai/rookery/builder/cmd/builder@latest
# Installed as `rookery-builder`
rookery-builder --help
```

Or invoke it from a rookery checkout:

```bash
git clone https://github.com/aflock-ai/rookery
cd rookery
go run ./builder/cmd/builder/ --help
```

## The 80% case: add KMS to the default set

```bash
rookery-builder \
  --preset cicd \
  --with github.com/aflock-ai/rookery/plugins/signers/kms/aws \
  --output ./cilock
./cilock --help          # shows the full cilock cobra tree
./cilock attestors list  # confirms the manifest's attestor set
```

The output binary is a drop-in replacement for the prebuilt `cilock`.

## Presets

| Preset | What it includes |
|---|---|
| `minimal` | `commandrun`, `environment`, `git`, `material`, `product` + `file` signer |
| `cicd` | `minimal` + `github`, `gitlab`, `slsa` |
| `all` | Every attestor + every signer in rookery |

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

# third-party plugin
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

The manifest path supports Git SSH for private repos and version pinning for reproducibility, neither of which the bare `--with` form does.

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

## What the builder actually does

1. Resolves every plugin spec — preset entries, `--with` flags, manifest plugins — to a concrete Go module + version (or local path with a `replace` directive).
2. Generates a temporary `main.go` that blank-imports each plugin and calls `attestation.RegisterLegacyAliases()` + `cli.Execute()`, exactly mirroring the cilock-default `main.go` shape.
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
