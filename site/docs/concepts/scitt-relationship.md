---
title: SCITT relationship
sidebar_position: 15
---

# SCITT relationship

[SCITT](https://datatracker.ietf.org/wg/scitt/about/) — Supply Chain Integrity, Transparency, and Trust — is an IETF working group standardizing how supply-chain attestations get registered in transparency services. CI/lock is not a SCITT implementation today. This page explains what SCITT is, where CI/lock's v0.3 design overlaps with the underlying primitives, and what would need to happen to bridge the two.

## What SCITT is

SCITT's architecture, specified in [draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture), defines three roles:

- An **Issuer** signs a statement about a supply-chain artifact (a build, a vulnerability claim, an audit result, a license attestation, etc.).
- A **Transparency Service** appends the signed statement to an append-only log and returns a *Receipt* — a signed inclusion proof against the log's current root.
- A **Verifier** later reads the receipt + statement and confirms both that the statement was registered (via the inclusion proof) and that the log has not been forked or rewound (via consistency proofs).

The wire format for those receipts is specified in [draft-ietf-cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/html/draft-ietf-cose-merkle-tree-proofs-18). Receipts are encoded as CBOR with a registered algorithm identifier — `alg = 1` is reserved for `RFC9162_SHA256`, which is the same hash construction CI/lock uses for its product/material trees and its inclusion-proof attestor.

## Where CI/lock overlaps

CI/lock's v0.3 design uses the same underlying primitive — RFC 6962/9162 inclusion proofs with `0x00`/`0x01` domain prefixes — that SCITT's COSE-Merkle wire format wraps. The Merkle hash chain bytes (leaf hash, interior nodes, root) are bytewise identical; the on-disk envelope formats differ (JSON-in-DSSE vs. CBOR-in-COSE). That gives CI/lock three forward-compatibility properties:

1. **No re-hash needed.** A CI/lock inclusion-proof attestation's `auditPath` and `treeRoot` fields, plus the leaf pre-hash reconstructed at verify time from `leafPath` + `fileDigest` via the canonical `inclusionproof.LeafHash` encoder, are computed with the same hash inputs as a SCITT receipt's COSE-Merkle envelope would carry. A converter that produces SCITT receipts from CI/lock attestations does not have to re-hash; it reconstructs the leaf hash from the CI/lock predicate and rewraps the proof in CBOR COSE-Merkle. (the standalone inclusion-proof predicate does not carry a precomputed `leafHash` field — it binds `leafPath` + `fileDigest` and reconstructs the leaf at verify time — see [inclusion-proof attestor](../attestors/inclusion-proof) for why that is a security property, not an oversight. The product/material attestations are different: their inline `leaves` do carry a `leafHash` field alongside `path` + `fileDigest`.)

2. **No algorithm choice to debate later.** CI/lock pins SHA-256 with `construction: "RFC6962"` in every inclusion-proof predicate. That maps directly to `alg = 1` in the COSE-Merkle registry. Future algorithm additions (e.g. SHA-3 variants) extend the registry without invalidating existing artifacts.

3. **The audit-path encoding aligns.** RFC 9162's audit path is an ordered list of sibling hashes; the COSE-Merkle CBOR encoding is the same ordered list with a CBOR header. CI/lock stores the list as a JSON array of digest strings, which is the equivalent JSON form.

## Where CI/lock differs

We are explicit about scope. CI/lock does not ship the following parts of the SCITT picture today:

- **No transparency service.** CI/lock's product/material trees are per-build snapshots. They are signed by the builder and embedded in the build's DSSE envelopes; they do not live in an append-only log operated by a separate party. The architectural role analog is "Issuer + statement" without "Transparency Service + receipt."
- **No consistency proofs.** Because there is no append-only log on CI/lock's side, there is nothing to prove consistency against. A future CI/lock integration with Sigstore Rekor or a SCITT-conformant transparency service would gain consistency proofs from that service's log.
- **No COSE wire format.** CI/lock encodes inclusion-proof attestations as JSON inside a DSSE envelope, not CBOR inside a COSE envelope. The two are isomorphic at the data-model level, but the bytes on disk are different.
- **No SCITT receipt issuance.** A SCITT receipt is a signed inclusion proof issued by a transparency service. CI/lock's inclusion-proof attestation is a signed inclusion proof issued by the *producer* itself. The trust model is different — a SCITT receipt's value comes from the transparency service being a neutral third party; a CI/lock inclusion-proof attestation's value comes from the producer being a trusted functionary under a verifier's policy.

## What a future bridge would look like

A cilock-to-SCITT bridge — call it `cilock-scitt-publish` — would do the following per CI/lock product attestation:

1. Read the CI/lock product attestation and its inclusion-proof attestations.
2. Submit the underlying signed statement(s) to a SCITT-conformant transparency service.
3. Receive a SCITT receipt back.
4. Optionally, emit a new attestation (or extend a bundle) carrying the receipt.

The submission step would re-encode the proof bytes from JSON into CBOR COSE-Merkle. The hash inputs do not change. A consumer who only trusts SCITT receipts would consume the receipt; a consumer who trusts the producer's signature directly would consume the original CI/lock attestation.

Neither code path exists today. CI/lock v0.3 establishes the primitives; the bridge is future work.

## Why the spec choice matters

The honest reason CI/lock builds against RFC 6962/9162 — rather than inventing a fresh proof format — is that it is the format SCITT, Sigstore Rekor, Google Certificate Transparency, and the broader transparency ecosystem already use. If CI/lock had picked something idiosyncratic, every future integration would require a re-hash and re-sign. The current choice means future integrations are wire-format translations.

The vendor implementation is `github.com/transparency-dev/merkle@v0.0.2`, the same library Sigstore Rekor depends on. CI/lock does not introduce a novel cryptographic dependency; it reuses the one the rest of the supply-chain ecosystem already trusts.

## References

- [draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture) — SCITT architecture
- [draft-ietf-cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/html/draft-ietf-cose-merkle-tree-proofs-18) — COSE wire format for Merkle proofs
- [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) — Certificate Transparency v2 (the underlying construction)
- [SCITT working group](https://datatracker.ietf.org/wg/scitt/about/) — current status and drafts
