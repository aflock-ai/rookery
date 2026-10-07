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
- `buildDefinition.resolvedDependencies`: the source as `{uri, digest.gitCommit}`, where `uri` is `git+https://<host>/<owner>/<repo>` plus `@<ref>` when the GitHub/GitLab token names the ref. There is one source entry per repository and commit. It comes only from the CI platform's signed token: GitHub's `repository`/`ref`/`sha` when GitHub's own key set verified it, or GitLab's `project_path`/`ref_path`/`sha` on the token's `iss` host when that issuer's key set verified it. The token names what triggered the job, so the entry is recorded only when the `git` attestor observed that same commit checked out, by a hash it re-computed (`commithashverified`). Otherwise the claim goes to `internalParameters.ciTrigger` as context and there is no source entry. `git` remotes are local, mutable config and never become a source entry; the `git` attestation still records them. The uri keeps a non-default port and IPv6 brackets. Every `material` attestor entry follows as `{name, digest}`.
- `runDetails.builder.id` — see "Builder identity" below.
- `runDetails.builder.version`, `runDetails.builder.builderDependencies` — present in the schema but not populated.
- `runDetails.metadata.invocationId` — pipeline URL (GitHub/GitLab/Jenkins) or AWS CodeBuild build ARN.
- `runDetails.metadata.startedOn` / `finishedOn` — timestamps copied from the `command-run` attestor's span.
- `runDetails.byproducts` — present in the schema but not populated.

Subjects come from the `product` attestor (as `file:<name>`) and from any `oci` attestor subjects (image references), merged together.

## When to use

Use whenever your verification chain expects upstream SLSA Provenance v1 consumers — `cosign verify-attestation --type slsaprovenance1`, `slsa-verifier`, OpenSSF Scorecard, or any policy engine that keys off the `https://slsa.dev/provenance/v1` predicate URI (the SLSA v1.0 spec string). cilock emitted the non-spec `.../v1.0` in earlier releases; that spelling is no longer accepted anywhere, so re-attest old provenance as SLSA v1. The `slsa` attestor is the canonical bridge between cilock's collection-style attestations and the SLSA ecosystem.

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
      { "uri": "git+https://github.com/owner/repo@refs/heads/main", "digest": { "gitCommit": "abc123..." } },
      { "name": "go.mod", "digest": { "sha256": "def456..." } }
    ]
  },
  "runDetails": {
    "builder": { "id": "https://aflock.ai/cilock/inline/github-actions@v1" },
    "metadata": {
      "invocationId": "https://github.com/owner/repo/actions/runs/123",
      "startedOn": "2026-05-21T12:00:00Z",
      "finishedOn": "2026-05-21T12:00:05Z"
    }
  }
}
```

## Gotchas

- **Builder identity names the trust boundary, and only where the platform can back it.** When cilock runs inline in the build job, `builder.id` names the inline mode: `https://aflock.ai/cilock/inline/github-actions@v1` only when the `github` attestor verified a token from `https://token.actions.githubusercontent.com`, `.../gitlab-ci@v1` only when the `gitlab` attestor verified a token from `https://gitlab.com` (the CI issuers a Fulcio CA maps to a build identity), and otherwise `https://aflock.ai/attestation-default-builder@v0.1`, which claims nothing and which the SLSA gate refuses. GitHub Enterprise Server, self-managed GitLab, Jenkins and AWS CodeBuild keep that default; their invocation ID is still recorded. Only the isolated provenance workflow (`aflock-ai/cilock-action/.github/workflows/provenance.yml`, compiled in) gets its reusable-workflow identity, `https://github.com/<job_workflow_ref>`, and only when GitHub's own JWKS verified the job's OIDC token. At verify time, a `builder.id` naming a `.github/workflows/` identity must equal an authorized signer's Fulcio Build Signer URI, or the collection is rejected. The earlier per-vendor ids (`https://aflock.ai/attestation-{github-action,gitlab-component,jenkins-component,aws-codebuild}-builder@v0.1`) are no longer emitted and stay valid on read. Do not grant a level on `builder.id` alone: pin the signer certificate's issuer and Build Signer URI in the policy.
- **Sibling-attestor dependencies**: with no `git`, `material`, `command-run`, `environment`, `product`, or `oci` in the same step, the predicate is essentially empty — the `slsa` attestor only assembles, it does not collect.
- **Wrapped vs exported**: without `--attestor-slsa-export`, the predicate ships inside the cilock collection envelope. Upstream SLSA tooling expects a top-level DSSE with the `https://slsa.dev/provenance/v1` predicate type — turn the flag on for those consumers.
- **Two registrations exist**: the active `slsa` attestor (postproduct) and a `slsa-provenance-v1` verify-only factory, both for `https://slsa.dev/provenance/v1`. A lookup by `https://slsa.dev/provenance/v1` resolves to `slsa`, which decodes the same predicate; the earlier `https://slsa.dev/provenance/v1.0` has no factory and is refused by name. Only `slsa` runs during a build.
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
