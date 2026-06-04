---
title: vsa
sidebar_position: 40
---

# `vsa` attestor

Typed decoder for pre-signed SLSA VSA predicates so downstream policies can consume external VSAs as first-class attestations — distinct from [`policyverify`](./policyverify.mdx), which *produces* a VSA at verify time.

| | |
|---|---|
| Name | `vsa` |
| Predicate type | `https://slsa.dev/verification_summary/v1` |
| Lifecycle | `verify` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The attestor wraps a `VerificationSummary` predicate that mirrors the SLSA VSA v1 shape. Its `MarshalJSON` emits the embedded predicate directly so Rego sees `input.verifier.id`, `input.verificationResult`, etc.

Fields on `VerificationSummary`:

- `verifier` — `{ id string }` identifying the party that ran verification.
- `timeVerified` — wall-clock timestamp the source VSA was produced.
- `policy` — `ResourceDescriptor` (`uri`, `digest`) referencing the policy that was evaluated.
- `inputAttestations[]` — `ResourceDescriptor` entries (`uri`, `digest`) for each attestation considered.
- `verificationResult` — `"PASSED"` or `"FAILED"` (the only two values defined in the package).

`ResourceDescriptor` shape: `{ uri string, digest cryptoutil.DigestSet }`.

## When to use

Build this attestor in when a downstream policy needs to read a VSA that was produced *outside* the current pipeline — for example, a deploy gate that ingests a release pipeline's signed VSA as an external attestation, then re-asserts policy on top of it. The factory is looked up via `FactoryByType` on the predicate URI and decodes the bare DSSE payload into the typed shape.

Contrast with [`policyverify`](./policyverify.mdx): `policyverify` runs inside `cilock verify` and *emits* a fresh VSA recording the outcome of that verify run. `vsa` does the inverse — it has a no-op `Attest()` and exists purely so a pre-signed VSA predicate can be unmarshalled and exposed to Rego under canonical SLSA field names.

## Flags

None. The attestor has no flag surface; it is selected by predicate-type lookup, not by name on the CLI.

## Output shape

```json
{
  "verifier": { "id": "..." },
  "timeVerified": "2026-05-21T12:34:56Z",
  "policy": {
    "uri": "...",
    "digest": { "sha256": "..." }
  },
  "inputAttestations": [
    { "uri": "...", "digest": { "sha256": "..." } }
  ],
  "verificationResult": "PASSED"
}
```

## Gotchas

- **Verify-only.** `RunType` is `attestation.VerifyRunType`. The factory is not selectable inside `cilock run` and `Attest()` is a no-op — it never produces an attestation by itself.
- **Decoder, not emitter.** To emit a VSA from a verify run, use [`policyverify`](./policyverify.mdx). The `vsa` package exists so external VSAs can flow into downstream policies as typed input.
- **PredicateType is the only routing key.** Registration uses the SLSA VSA v1 URI; bare-predicate DSSEs with any other type will not be routed to this factory.
- **Field names match the SLSA spec, not the wrapper.** Custom `MarshalJSON`/`UnmarshalJSON` flatten the embedded `Predicate` field out of the JSON, so policies should reference `verifier`, `verificationResult`, etc. directly — not `predicate.verifier`.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/42-vsa](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/42-vsa). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`policyverify`](./policyverify.mdx) — the verify-time VSA emitter
- [SLSA VSA spec](https://slsa.dev/spec/v1.0/verification_summary)
