---
title: slsa
description: The cilock slsa attestor assembles a SLSA Provenance v1.0 predicate from sibling attestors in the same collection and signs it into in-toto evidence under the slsa.dev predicate type.
sidebar_position: 24
examples_repo: 38-slsa
---

Emits a SLSA Provenance v1.0 predicate assembled from sibling attestors that ran in the same collection.

## What it captures

The predicate is the `prov.Provenance` struct from `attestation/intoto/provenance`, which mirrors the SLSA v1.0 spec:

- `buildDefinition.buildType` — set to the constant `https://aflock.ai/slsa-build@v0.1`.
- `buildDefinition.externalParameters` — `{ "command": "<joined command-run argv>" }` (populated from the `command-run` sibling).
- `buildDefinition.internalParameters` — `{ "env": { ... } }` (populated from the `environment` sibling).
- `buildDefinition.resolvedDependencies` — array of `ResourceDescriptor{name,digest}` entries built from `git` remotes + commit digest, the GitHub/GitLab JWT `sha` claim, and every `material` attestor entry.
- `runDetails.builder.id` — see "Builder identity" below.
- `runDetails.builder.version`, `runDetails.builder.builderDependencies` — present in the schema but not populated.
- `runDetails.metadata.invocationId` — pipeline URL (GitHub/GitLab/Jenkins) or AWS CodeBuild build ARN.
- `runDetails.metadata.startedOn` / `finishedOn` — timestamps copied from the `command-run` attestor's span.
- `runDetails.byproducts` — present in the schema but not populated.

Subjects come from the `product` attestor (as `file:<name>`) and from any `oci` attestor subjects (image references), merged together.

## When to use

Use whenever your verification chain expects upstream SLSA Provenance v1 consumers — `cosign verify-attestation --type slsaprovenance1`, `slsa-verifier`, OpenSSF Scorecard, or any policy engine that keys off the `https://slsa.dev/provenance/v1.0` predicate URI. The `slsa` attestor is the canonical bridge between cilock's collection-style attestations and the SLSA ecosystem.

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--attestor-slsa-export` | bool | `false` | Emit the SLSA predicate as its own standalone DSSE envelope (in addition to being embedded in the collection). |

## Output shape

```json
{
  "buildDefinition": {
    "buildType": "https://aflock.ai/slsa-build@v0.1",
    "externalParameters": { "command": "go build ./..." },
    "internalParameters": { "env": { "PATH": "...", "HOME": "..." } },
    "resolvedDependencies": [
      { "name": "origin", "digest": { "sha1": "abc123..." } },
      { "digest": { "sha1": "def456..." } }
    ]
  },
  "runDetails": {
    "builder": { "id": "https://aflock.ai/attestation-github-action-builder@v0.1" },
    "metadata": {
      "invocationId": "https://github.com/owner/repo/actions/runs/123",
      "startedOn": "2026-05-21T12:00:00Z",
      "finishedOn": "2026-05-21T12:00:05Z"
    }
  }
}
```

## Gotchas

- **Builder identity is auto-selected** from sibling attestors. Defaults to `https://aflock.ai/attestation-default-builder@v0.1`; promoted to `attestation-github-action-builder@v0.1`, `attestation-gitlab-component-builder@v0.1`, `attestation-jenkins-component-builder@v0.1`, or `attestation-aws-codebuild-builder@v0.1` if the matching sibling ran. If the builder stays at the default, the attestor logs a warning suggesting you add a build-system attestor.
- **Sibling-attestor dependencies**: with no `git`, `material`, `command-run`, `environment`, `product`, or `oci` in the same step, the predicate is essentially empty — the `slsa` attestor only assembles, it does not collect.
- **Wrapped vs exported**: without `--attestor-slsa-export`, the predicate ships inside the cilock collection envelope. Upstream SLSA tooling expects a top-level DSSE with the `https://slsa.dev/provenance/v1.0` predicate type — turn the flag on for those consumers.
- **Two registrations exist**: the active `slsa` attestor (postproduct, type `.../v1.0`) and a `slsa-provenance-v1` verify-only factory (type `.../v1`) used by the external-attestation flow. Only the former runs during a build.
- The `slsa` attestor implements `Subjecter` and merges product subjects with OCI subjects, so container image digests are not silently dropped.

## CLI example

Real SLSA Provenance v1.0 emitted from command-run + material + product.

```bash
cilock run --step slsa-provenance \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations slsa \
  -- make build 
```

Validated against a real build emitting SLSA v1.0 provenance. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/38-slsa](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/38-slsa).

## See also
- [Catalog row](../reference/attestor-catalog)
- [SLSA spec](https://slsa.dev/spec/v1.0/)
- Upstream: [witness/slsa.md](https://github.com/in-toto/witness/blob/main/docs/attestors/slsa.md)
