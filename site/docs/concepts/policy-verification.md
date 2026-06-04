---
title: Policy verification
sidebar_position: 13
---

# Policy verification

A **CI/lock policy** is a signed document that encodes the requirements for an artifact to be validated. It includes trusted public keys (or X.509 roots), the steps that must appear in the supply chain, the functionaries trusted to sign each step, and embedded OPA Rego rules to evaluate against attestation contents.

`cilock verify` evaluates a set of attestation collections against a policy document. If the collections satisfy the policy, the command exits 0; any other exit code indicates an error or policy failure.

## The policy document

The policy is itself a signed DSSE document. The DSSE `payloadType` is `https://aflock.ai/policy/v0.1` (the legacy witness type `https://witness.testifysec.com/policy/v0.1` is also accepted, so existing witness policies verify unchanged). Top-level fields of the inner JSON document:

| Field | Purpose |
|---|---|
| `expires` | ISO-8601 expiration. Evaluation of expired policies always fails. |
| `roots` | Trusted X.509 root certificates. Attestations signed by certs chained to these roots are trusted. |
| `publickeys` | Trusted public keys (incl. KMS reference URIs). Attestations signed by these keys are trusted. |
| `steps` | Map of step name → step definition (functionaries, expected attestations, `artifactsFrom`). |
| `timestampauthorities` | Trusted X.509 roots for [RFC 3161](./timestamping) timestamp authorities. |

### Inside a step

Each step declares:

- **`functionaries`:** who is allowed to sign this step's attestation collection. A functionary is either type `publickey` (referencing a `publickeyid`) or type `root` (referencing a trust root with a `certConstraint` on commonname, dnsnames, emails, organizations, SPIFFE URIs, etc.).
- **`attestations`:** which attestation types must appear, and optional `regopolicies` to evaluate against each.
- **`artifactsFrom`:** names of upstream steps whose products must match this step's materials, so the verifier can prove the binary you're shipping was built from the same files that came out of `clone`/`fetch`.

### Embedded Rego

Each `attestation` entry can carry one or more **base64-encoded OPA Rego modules** in `regopolicies[].module`. The module must export a `deny` rule that returns a string (or array of strings) when the policy fails. Anything else the module outputs is ignored.

Example:

```
package commandrun.exitcode

deny[msg] {
    input.exitcode != 0
    msg := "exitcode not 0"
}
```

This is what turns "the build command must have exited 0" or "the SBOM must contain at least one component" into automated checks.

## The verification process

`cilock verify` runs five checks, in order:

1. **Verify signatures on collections** against the public keys and trust roots declared in the policy. Anything that fails signature verification is dropped before further evaluation.
2. **Map each signer to a trusted functionary** for the corresponding step name in the policy.
3. **Verify timestamps:** if a signature was timestamped, the timestamp must come from a TSA root declared in `timestampauthorities`, and the signing certificate must have been valid at the timestamped time.
4. **Verify materials/products consistency** across steps. A step's materials must match the products of any step listed in `artifactsFrom`.
5. **Evaluate every embedded Rego policy** against its target attestation. All must pass.

## Where verification runs

| Location | When to use it |
|---|---|
| **Release gate** | A separate workflow that runs before deploy. Most common. |
| **Kubernetes admission controller** | Cluster-side gate that rejects unverified images. |
| **Image promotion gate** | Run before tagging or promoting an image to a production registry. |
| **Local CLI** | Engineers running `cilock verify` against an artifact during investigation. |

## Soft fail vs. fail closed

Policy verification is most useful when teams **fail closed:** a missing SBOM blocks the deploy. But for the first weeks of adoption, you may want to fail soft (warn, alert, but don't block) while you learn what the pipelines actually produce. The [trust model](./trust-model) page covers this transition.

For schema details and a full example policy, see the [policy schema reference](../reference/policy-schema). For a worked end-to-end example, see [Verify in a release gate](../guides/verify-in-a-release-gate).
