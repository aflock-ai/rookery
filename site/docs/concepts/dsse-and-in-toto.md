---
title: DSSE & in-toto
sidebar_position: 3
---

# DSSE & in-toto

[DSSE](https://github.com/secure-systems-lab/dsse) (Dead Simple Signing Envelope) and [in-toto](https://in-toto.io/) are the standardized envelope and provenance formats that make CI/lock evidence interoperable with the wider supply-chain tooling ecosystem.

For everyday adoption, the takeaway is **interoperability**: evidence is structured so other tools can consume and verify it, regardless of who produced it.

## DSSE in 60 seconds

DSSE is a signing envelope. It defines:

- A `payload` (your structured statement, base64-encoded)
- A `payloadType` (a content type that tells verifiers how to interpret the payload)
- One or more `signatures` over the envelope

That's it. DSSE doesn't care what's *inside* the payload, it just provides a clean way to sign structured data so multiple parties can sign the same statement, and so verifiers don't accidentally validate a signature against the wrong shape of data.

## in-toto attestations

[in-toto](https://in-toto.io/) defines what goes *inside* the DSSE envelope. Specifically, the [in-toto attestation framework](https://github.com/in-toto/attestation) defines a typed **Statement** with four fields:

| Field | Description |
|---|---|
| `_type` | Always `"https://in-toto.io/Statement/v0.1"`. Identifies the framework version. |
| `subject` | An array of `ResourceDescriptor` objects (artifacts the statement applies to, with their digests). |
| `predicateType` | A URI identifying the type of the predicate, for example `https://aflock.ai/attestations/git/v0.1`. |
| `predicate` | The actual typed claim. Its structure is determined by `predicateType`. |

The Statement is JSON-serialized, base64-encoded, and placed in the DSSE `payload` field. The DSSE `payloadType` is set to the Statement type (`application/vnd.in-toto+json` for Statement v1).

CI/lock follows the relevant in-toto enhancements: [ITE-5](https://github.com/in-toto/ITE/blob/master/ITE/5/README.md) (which disassociates the signature envelope from the in-toto specification and recommends DSSE) and [ITE-6](https://github.com/in-toto/ITE/blob/master/ITE/6/README.md) (which is the contextual-attestation framework that defines `subject` / `predicateType` / `predicate`). [ITE-7](https://github.com/in-toto/ITE/tree/master/ITE/7) (X.509 signing & verification) is currently a draft enhancement; CI/lock's Fulcio and Vault PKI signers anticipate that direction.

CI/lock attestation types use the `https://aflock.ai/attestations/<name>/v0.1` namespace, for example `https://aflock.ai/attestations/git/v0.1` or `https://aflock.ai/attestations/product/v0.3`. The legacy witness namespace (`https://witness.dev/attestations/<name>/v0.1`) is also accepted via aliases registered in `attestation/legacy.go`, so policies targeting witness-produced evidence continue to work in CI/lock.

## Why standardization matters

Because CI/lock outputs DSSE-wrapped in-toto attestations, the evidence works with:

- **Witness:** CI/lock verifies witness-produced evidence directly (legacy witness.dev type aliases are registered on startup). The reverse is partial — witness can read CI/lock's shared base attestors but **not** its Merkle-tree `product`/`material`, inclusion-proof, or trace evidence. See [the interop comparison](../ecosystem/witness#interop-direction-precisely).
- **Sigstore** verification stacks
- **Kubernetes** admission controllers (e.g. Sigstore policy-controller)
- **Tekton Chains** and other CI provenance tooling
- Anything else that speaks DSSE + in-toto

The base envelope is portable: a consumer that implements the same predicate type can verify CI/lock evidence regardless of who produced it. CI/lock's advanced evidence types (Merkle trees, inclusion proofs) need a verifier that understands them — that portability has limits, and they're worth knowing.

## Next

- [Signing & identity](./signing-and-identity) — how the envelope gets signed and who the functionary is.
- [The spine of the graph](./the-spine-of-the-graph) — how these envelopes link into a verifiable evidence graph.
- [Policy verification](./policy-verification) — how a signed policy checks the collected attestations at a release gate.

## Upstream specs

- [DSSE protocol](https://github.com/secure-systems-lab/dsse)
- [in-toto attestation framework](https://github.com/in-toto/attestation)
- [in-toto enhancements (ITE)](https://github.com/in-toto/ITE)
