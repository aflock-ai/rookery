---
title: Verify in a release gate
sidebar_position: 3
---

# Verify in a release gate

This guide is the operational counterpart to the [release promotion gate tutorial](../tutorials/release-promotion-gate). The tutorial shows you a worked example. This guide covers the design decisions you'll hit when wiring it into a real production environment.

## Where to put the gate

Four common locations, with tradeoffs:

| Location | When to pick it | Tradeoffs |
|---|---|---|
| **Separate "promote" workflow** | Most teams. Easiest to reason about and audit. | Adds a manual step (`workflow_dispatch`) or a scheduled trigger. |
| **End of the build workflow itself** | Small teams, simple pipelines. | Couples build and verification, the build job needs the policy public key, which expands its blast radius. |
| **Kubernetes admission controller** | Cluster-side enforcement; you want to reject unverified images at deploy time regardless of how they got there. | Requires running a verifier inside the cluster; doesn't catch non-cluster deploys. |
| **External orchestrator (ArgoCD, Spinnaker, custom)** | When deploys are driven by something other than CI. | Requires the orchestrator to have access to Archivista and the policy. |

Most pipelines start with a separate promote workflow. Move to admission control only when you have multiple deploy paths to defend.

## Inputs the gate needs

Whatever the location, the gate needs three things to verify:

1. **The subject:** a commit SHA, an artifact digest, or an image reference. This is what the verifier matches collections against.
2. **The evidence:** one or more attestation envelopes. Either passed in as files, fetched from Archivista by subject digest, or pulled from the OCI registry as referrers.
3. **The signed policy:** `policy-signed.json` plus the `policy-pubkey.pem` that signed it.

```bash
cilock verify \
  --policy ./policy-signed.json \
  --publickey ./policy-pubkey.pem \
  --attestations build.attestation.json,sbom.attestation.json \
  --subjects "sha1:$RELEASE_COMMIT_SHA"
```

Exit code 0 = pass, anything else = fail.

Two flag traps worth knowing:

- `--attestations` is comma-separated (cobra `StringSlice`), not space-separated. Multiple files on one flag must be joined with commas, or you pass `-a` repeatedly.
- Prefer `--subjects "sha1:$COMMIT"` over `--artifactfile bin/myapp` when the gate runs in a different job than the build. In multi-job pipelines, the build artifact often arrives in the gate job's working directory via `needs:`/`dependencies:` *before* its build-side attestation was produced, which can leave the artifact in the build's *materials* (not products) and break the digest-to-subject match. The git commit hash is recorded by the `git` attestor on every collection, so it's a reliable subject. (This trap is covered end-to-end in the [GitLab CI tutorial](../tutorials/gitlab-ci-pipeline).)

## Soft-fail vs fail-closed

The single biggest design choice. Roll out in phases:

| Phase | Behavior | What it gives you |
|---|---|---|
| **Observe** | Run `cilock verify` but don't block deploy on its result. Log failures. | Visibility into what *would* be blocked, without disrupting releases. Run for at least 2 weeks. |
| **Soft-fail with override** | Verify gates the deploy, but operators can override via a workflow input. | Catches real violations, but lets you ship past false positives while you tune. |
| **Fail-closed** | Verification failure blocks the deploy with no override path. | Production state. Mistakes here are stop-the-line events. |

The temptation to skip from "Observe" to "Fail-closed" is strong. Don't. The intermediate phase exists because real policies are written by humans who get details wrong.

## Handling failure modes

### When the policy is too strict

Symptoms: legitimate builds fail policy. Operators ask for the override knob.

Fix: tighten or relax specific Rego rules with concrete exit criteria. **Don't** add blanket `if true` exemptions; they ossify and become permanent.

### When the policy is too loose

Symptoms: the gate passes everything, including builds that obviously shouldn't ship.

Fix: this usually means a missing required attestation type or a missing `regopolicy` rule. The [SBOM and SARIF tutorial](../tutorials/sbom-and-sarif-evidence) covers requiring evidence presence; the [policy schema](../reference/policy-schema) covers Rego enforcement.

### When evidence isn't available

Symptoms: the verifier reports "no collections found for subject X."

Fix: either the build didn't produce the evidence (check the build workflow), or it didn't make it into Archivista (check the upload step). The [store-attestations-in-archivista guide](./store-attestations-in-archivista) has the troubleshooting table.

### When verification is slow

Symptoms: the verify step takes minutes; deploys feel laggy.

Fix: most slowness is fetching evidence from Archivista. Pre-fetch in parallel before the verify step, or use a closer Archivista replica for production gates.

## Recording the verification itself

The verification result *is itself useful evidence*. CI/lock has two patterns for capturing it, used together in production:

**1. The built-in `policyverify` attestor.** `cilock verify` already runs an attestor named `policyverify` (predicate type `https://slsa.dev/verification_summary/v1`, the SLSA Verification Summary Attestation). When `--enable-archivista` is set, the resulting VSA is pushed to Archivista alongside the other collections, with the same key/identity that signed the inputs. No extra wrapping is needed.

```bash
cilock verify \
  --policy ./policy-signed.json --publickey ./policy-pubkey.pem \
  --attestations "$ATTESTATIONS" \
  --subjects "sha1:$RELEASE_COMMIT_SHA" \
  --enable-archivista \
  --archivista-server "$ARCHIVISTA_URL"
```

The `policyverify` attestor is a *verify-type* attestor; it does not run in `cilock run` (attempting `cilock run -a policyverify` returns `attestors of type verify cannot be run in conjunction with other attestor types`).

**2. Wrap the verify *invocation* itself.** If you want to record who/where/when of the gate run too (cert identity, environment, repo state), wrap the verify command with `cilock run`:

```bash
cilock run --step promote-verify \
  --attestations "environment git github" \
  --signer-fulcio-token "$OIDC" \
  -o promote-verify.attestation.json \
  -- cilock verify \
       --policy policy-signed.json --publickey policy-pubkey.pem \
       --attestations "$ATTESTATIONS" \
       --subjects "sha1:$RELEASE_COMMIT_SHA"
```

The outer `cilock run` records the gate runner's identity and environment + the command-run output of the verify call. The inner `cilock verify` produces the SLSA VSA via `policyverify` as described above. Stored together, you have a signed record of *who verified what*, with what policy, at what time. Useful for audit ("show me every release that was promoted to prod last quarter, with the verification evidence").

## Identity constraints worth requiring

Almost every production policy should constrain `functionaries` by identity. Common shapes:

| Constraint | Where it goes | Why |
|---|---|---|
| Fulcio cert SAN URI = `https://github.com/<org>/<repo>/.github/workflows/<build>.yml@refs/heads/main` | `certConstraint.uris` in the policy step's `functionaries` | Build came from the canonical workflow file on `main`, not a fork or a copy of `build.yml`. This is the exact value the Fulcio cert encodes after a GitHub Actions OIDC exchange (verified by inspecting a real `aflock-ai/cilock-action` attestation). |
| OIDC issuer = `https://token.actions.githubusercontent.com` | `certConstraint.extensions.issuer` | Cert was issued in response to a GitHub Actions OIDC token, not some other issuer that happens to share a Fulcio CA. |
| `source_repository_uri` extension matches your repo | `certConstraint.extensions.source_repository_uri` | Belt-and-braces with the SAN URI; some teams pin both. |
| SPIFFE URI = `spiffe://prod/builder` | `certConstraint.uris` (SPIFFE SVID) | Build ran in the production builder workload, not a dev one. |
| KMS key id matches your release-signing key | `functionaries[].publickeyid` (KMS URI form) | Signed by a key only the release-engineering team controls. |

(Note: the raw GitHub Actions OIDC token's `sub` claim `repo:<org>/<repo>:ref:refs/heads/main` is a different format from the Fulcio cert URI. The token claim is what AWS/GCP/Azure trust policies for federated identity match against; the cert URI is what CI/lock's `certConstraint.uris` matches. They reference the same build, in two different shapes.)

The [signing & identity](../concepts/signing-and-identity#what-the-verifier-checks) page has the full list of certificate-constraint fields.

## Operational checklist

Before turning fail-closed on:

- [ ] Policy is signed and the public key is committed to the repo
- [ ] At least 2 weeks of soft-fail logs reviewed
- [ ] Every team that ships through this gate has been told the rollout date
- [ ] An override path exists for genuine emergencies (a tagged "break-glass" branch with a documented audit trail, *not* the ability to skip the gate)
- [ ] On-call has been told what failures look like and where to find the evidence
- [ ] The verification result is itself logged or attested (`policyverify`)
- [ ] You've decided what to do when Archivista is down, fail-closed (safer) or fail-open with alert (less disruptive)

## See also

- [Release promotion gate tutorial](../tutorials/release-promotion-gate), the worked example
- [Policy schema reference](../reference/policy-schema), the full policy document format
- [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks), what the gate is defending against
