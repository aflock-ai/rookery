---
title: Add a custom attestor
sidebar_position: 4
---

# Add a custom attestor

When the [30+ attestors in the default `cilock` binary](../reference/attestor-catalog) don't capture what you need, write your own. This guide walks through the rookery `attestation.Attestor` interface, the lifecycle hooks, and how to ship a custom attestor as a Go module that downstream binaries can blank-import.

## The interface

Every attestor implements **five** methods (verified from `rookery/attestation/factory.go:31`):

```go
type Attestor interface {
    Name() string                                // unique short name, e.g. "git"
    Type() string                                // versioned type URL
    RunType() RunType                            // when to run in the lifecycle
    Attest(ctx *AttestationContext) error
    Schema() *jsonschema.Schema                  // JSON schema of the attestor's output struct
}
```

`Schema()` is what `cilock attestors schema <name>` returns. The conventional implementation is a one-liner: `return jsonschema.Reflect(&a)` (used by every attestor in `rookery/plugins/attestors/*/`).

That's the minimum. Several optional interfaces give your attestor more capability:

```go
type Subjecter interface {
    Subjects() map[string]cryptoutil.DigestSet     // contributes subjects to the in-toto statement
}

type BackReffer interface {
    BackRefs() map[string]cryptoutil.DigestSet     // links this attestation to other related digests
}

type Materialer interface {
    Materials() map[string]cryptoutil.DigestSet    // declares pre-execute material digests
}

type Producer interface {
    Products() map[string]Product                  // declares post-execute product digests
}

type Exporter interface {
    Export() bool                                  // request separate export of this attestation
    Subjects() map[string]cryptoutil.DigestSet
}
```

Most custom attestors only need `Subjecter`. The others are for attestors that participate in the material/product diff machinery (`Materialer`, `Producer`) or that should be emitted as standalone attestations alongside the collection (`Exporter`, `MultiExporter`).

A real attestor declares all four interfaces with compile-time checks (from `rookery/plugins/attestors/git/git.go`):

```go
var (
    _ attestation.Attestor   = &Attestor{}
    _ attestation.Subjecter  = &Attestor{}
    _ attestation.BackReffer = &Attestor{}
)
```

If your custom attestor doesn't satisfy a contract, you'll find out at compile time, not at runtime.

## Picking a type URL

Cilock-native attestors use the `https://aflock.ai/attestations/<name>/v0.1` namespace. For your own attestor, pick a URL **you control:** typically your organization's domain:

```go
const (
    Name    = "internal-license-check"
    Type    = "https://example.com/attestations/internal-license-check/v0.1"
    RunType = attestation.PostProductRunType
)
```

The version suffix matters. When the predicate schema changes incompatibly, bump to `v0.2` rather than mutating `v0.1`, old policies that target the old version should still verify against old evidence.

## Picking a lifecycle phase

Attestors run in five phases (verified from `witness/docs/concepts/attestor.md`):

| Phase | Constant | Use it for |
|---|---|---|
| Pre-material | `PreMaterialRunType` | Environment, identity, CI metadata, anything that exists before the wrapped command runs |
| Material | `MaterialRunType` | Input file digests, lockfiles, dependency state |
| Execute | `ExecuteRunType` | Information about the command itself |
| Product | `ProductRunType` | Output file digests |
| Post-product | `PostProductRunType` | Anything that *inspects* the products, SBOMs, SARIF, OCI metadata |

If your attestor reads a file produced by the wrapped command, it has to be Post-product. If it captures runtime state independent of the command, Pre-material is usually right.

## Implementing it

A minimal attestor that records the contents of an environment-specified license file:

```go
// example.com/cilock-attestor-license/license/license.go
package license

import (
    "os"

    "github.com/aflock-ai/rookery/attestation"
    "github.com/aflock-ai/rookery/attestation/cryptoutil"
    "github.com/invopop/jsonschema"
)

const (
    Name    = "internal-license-check"
    Type    = "https://example.com/attestations/internal-license-check/v0.1"
    RunType = attestation.PostProductRunType
)

type Attestor struct {
    LicenseFile string               `json:"licensefile"`
    Digest      cryptoutil.DigestSet `json:"digest"`
}

// Compile-time interface check
var _ attestation.Attestor = &Attestor{}

func New() *Attestor { return &Attestor{} }

func (a *Attestor) Name() string                  { return Name }
func (a *Attestor) Type() string                  { return Type }
func (a *Attestor) RunType() attestation.RunType  { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema    { return jsonschema.Reflect(&a) }

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
    a.LicenseFile = os.Getenv("LICENSE_FILE")
    if a.LicenseFile == "" {
        return nil
    }
    digest, err := cryptoutil.CalculateDigestSetFromFile(a.LicenseFile, ctx.Hashes())
    if err != nil {
        return err
    }
    a.Digest = digest
    return nil
}
```

## Registering it

Attestors register themselves in `init()` so blank-importing the package is enough to make them available (verified from every attestor in `rookery/plugins/attestors/`):

```go
func init() {
    attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
        return New()
    })
}
```

For an attestor that should also accept old type URLs (e.g. when you rename it), use `RegisterAttestationWithTypes` to pass multiple aliases.

## Using it in CI/lock

Two ways to consume your custom attestor:

### Option A: A custom `cilock` binary

Build your own variant of the `cilock` binary that blank-imports your attestor:

```go
// cmd/cilock-custom/main.go
package main

import (
    "github.com/aflock-ai/rookery/attestation"
    "github.com/aflock-ai/rookery/cilock/internal/cmd"

    // ...all the standard cilock attestors and signers...
    _ "example.com/cilock-attestor-license/license"
)

func main() {
    attestation.RegisterLegacyAliases()
    cmd.Execute()
}
```

The simplest path is to fork `cilock/cmd/cilock/main.go`, add your import, and build with `GOWORK=off CGO_ENABLED=0 go build`.

### Option B: The rookery builder

The [rookery builder](../ecosystem/rookery) generates custom binaries from a manifest that lists which attestors and signers to include. The cilock-action exposes this via the `builder-manifest` and `builder-preset` inputs.

## Schema generation

Your attestor's struct fields are serialized to JSON in the attestation. CI/lock generates a JSON Schema from the struct via `cilock attestors schema <name>` (verified from `rookery/cilock/internal/cmd/attestors.go`). Use struct tags to control field names and required/optional status:

```go
type Attestor struct {
    LicenseFile string               `json:"licensefile"`
    Digest      cryptoutil.DigestSet `json:"digest,omitempty"`
}
```

Fields tagged `omitempty` are optional in the schema; others are required.

## Subjects and backrefs

If your attestor produces something that's a meaningful **subject** for verification (e.g. a license document hash that other attestations should be linked to), implement `Subjects()`:

```go
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
    return map[string]cryptoutil.DigestSet{
        a.LicenseFile: a.Digest,
    }
}
```

Subjects appear in the in-toto statement and are queryable via Archivista by digest.

`BackRefs()` is rarer, use it when your attestor needs to assert that *other* digests should be considered related (e.g. cross-referencing an upstream tag to a commit).

## Testing

The rookery `attestation` package ships test helpers for attestor lifecycle testing. The `presets/cicd` test patterns are a good reference (verified location). Use the rookery-core testers (per the project's CONTRIBUTING guidance) so your attestor behaves consistently with the built-in set.

## See also

- [Attestor concept](../concepts/attestors), lifecycle and what attestors do
- [Attestor catalog](../reference/attestor-catalog), the attestors already in the default binary; check whether your need is already covered
- [Witness attestor concept docs](https://github.com/in-toto/witness/blob/main/docs/concepts/attestor.md), the upstream reference CI/lock's interface descends from
