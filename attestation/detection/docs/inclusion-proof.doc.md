---
title: inclusion-proof
description: The cilock inclusion-proof attestor binds a single file's digest to a Merkle tree root via an RFC 6962 audit path and signs it into in-toto evidence for downstream per-file verification.
sidebar_position: 5
examples_repo: multi-step-attestationsFrom
---

Emits a signed inclusion proof binding a single file's digest to a Merkle tree's root. Generated on demand by [`cilock prove`](../guides/prove-files-in-a-build) against a producer-side tree sidecar; consumed by `cilock verify` when a downstream verifier needs to confirm a per-file claim against a v0.3 [product](./product-v0.3) or material attestation.

## What it captures

The predicate carries the data a verifier needs to recompute the Merkle root from a single leaf via [RFC 6962 §2.1.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1.1):

| JSON field | Type | Source |
|---|---|---|
| `treeRoot` | string (hex) | The Merkle root the proof terminates at. Must equal the product/material attestation's `tree:products` (or `tree:materials`) subject digest. |
| `leafIndex` | integer | Zero-based index of the file in the sorted leaf list. |
| `leafPath` | string | The file's portable (forward-slash) path within the working directory. The leaf hash is reconstructed from this plus `fileDigest` at verify time. |
| `fileDigest` | string (hex) | Lowercase hex SHA-256 of the file content. |
| `auditPath` | array of hex strings | Ordered list of sibling hashes from the leaf up to the root. Length is `⌈log₂(treeSize)⌉`. |
| `hashAlgorithm` | string | Hash algorithm used to build the tree (always `sha256` for v0.1). |
| `construction` | string | Always `RFC6962` for v0.1. |

The verifier reconstructs the leaf hash by calling the canonical encoder `inclusionproof.LeafHash(leafPath, fileDigest)` (which produces `sha256(leafPath-bytes || 0x00 || fileDigest-bytes-raw32)`); the RFC 6962 audit-path verifier applies the `0x00` leaf-domain prefix on top of that pre-hash. Carrying the path and digest in the predicate (instead of a pre-computed leaf hash) lets the verifier refuse a proof whose `fileDigest` does not match the subject the user asked to verify — closing off the CVE-2026-22703 class.

The DSSE statement's subject is the file digest itself (the file content's hash, not the leaf hash):

```json
"subject": [
  {
    "name":   "file:dist/binary",
    "digest": { "sha256": "<file-digest>" }
  }
]
```

The subject being the file digest is what makes the inclusion-proof attestation discoverable via the existing subject-digest BFS. See [the spine of the graph](../concepts/the-spine-of-the-graph) for the structural reasoning.

## When to use

After `cilock run` has produced a v0.3 product (or material) attestation and the matching `` `<outfile>.product.tree.json` `` (or `.material.tree.json`) sidecar, run `cilock prove` against the sidecar for any file a downstream consumer might need to verify. Typically that means release binaries, container images, public-API entry points, and SBOMs — anything someone might verify by digest. Skip intermediate build files (`node_modules` contents, object files, build temp). See [prove files in a build](../guides/prove-files-in-a-build).

## Flags

The `cilock prove` subcommand carries the flags that drive this attestor. (The attestor itself does not register CLI flags via the standard attestor registry; it is producer-driven only.)

| Flag | Effect |
|---|---|
| `--tree-sidecar <path>` | Path to the product or material tree sidecar from `cilock run` (required). |
| `--file <path>` | Leaf path within the sidecar tree to emit a proof for. Repeat to emit multiple proofs in one invocation. |
| `--outfile <path>` | Where to write the signed inclusion-proof envelope. With multiple `--file` values each envelope lands at `<outfile>-<sanitised-path>.json`. |
| `--signer-file-key-path` / `--signer-fulcio-*` / `--signer-kms-*` | Standard cilock signer flags. Same flow as `cilock run`. |
| `--timestamp-servers` | Optional TSA servers to use when signing the envelope. |

## Verification semantics

A verifier consuming an inclusion-proof attestation must, in order:

1. **Verify the DSSE signature.** Reject if the signer is not a trusted functionary per the active policy.
2. **Reconstruct the leaf and recompute the root.** Compute `leafPreHash = sha256(leafPath || 0x00 || fileDigest-raw32)` via the canonical `inclusionproof.LeafHash` encoder, then fold the pre-hash through `auditPath` using RFC 6962's audit-path verifier (which applies the `0x00` leaf-domain prefix on top). The reconstructed value must equal the claimed `treeRoot`.
3. **Cross-check against the seed.** The predicate's `fileDigest` must equal the subject digest the verifier was asked to verify. Skipping this is the [CVE-2026-22703](https://nvd.nist.gov/vuln/detail/CVE-2026-22703) class of bug — a valid proof for the wrong artifact silently passes.
4. **Find the product/material attestation.** The `treeRoot` digest is a BackRef of the inclusion-proof attestation's Collection. The verifier's BFS expands to it; the matching product/material attestation's subject must equal it.
5. **Verify the product/material attestation's signature.** Same trust check as step 1.

All five checks are mandatory. See [verify a specific file](../guides/verify-a-specific-file) for the consumer-side flow with worked failure modes.

## Output shape

A full DSSE statement for an inclusion-proof attestation:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name":   "file:dist/binary",
      "digest": { "sha256": "9c6fb35e4d3a1c7b8e2f0a91d5c8b4f6e3a2b1c9d7e8f6a3b2c1d4e5f6a7b8c9d" }
    }
  ],
  "predicateType": "https://aflock.ai/attestations/inclusion-proof/v0.1",
  "predicate": {
    "treeRoot":      "abc1234567890def1234567890abcdef1234567890abcdef1234567890abcdef",
    "leafIndex":     1247,
    "leafPath":      "dist/binary",
    "fileDigest":    "9c6fb35e4d3a1c7b8e2f0a91d5c8b4f6e3a2b1c9d7e8f6a3b2c1d4e5f6a7b8c9d",
    "auditPath": [
      "1111111111111111111111111111111111111111111111111111111111111111",
      "2222222222222222222222222222222222222222222222222222222222222222",
      "3333333333333333333333333333333333333333333333333333333333333333"
    ],
    "hashAlgorithm": "sha256",
    "construction":  "RFC6962"
  }
}
```

(Digests above are synthetic placeholders. A real proof's `auditPath` length is `⌈log₂(treeSize)⌉` — three hashes here would correspond to a tree of size 5–8. All hex values are unprefixed lowercase — the `treeRoot` and `auditPath` entries are raw hex, not `sha256:`-prefixed.)

## Gotchas

- **One attestation per file.** v0.1 does not cluster proofs. Five files needing per-file claims = five inclusion-proof attestations. Storage cost is bounded by `O(log(treeSize))` per proof — small enough that one-per-file is fine for typical release sets.
- **Algorithm pinning.** The verifier must reject any proof whose `hashAlgorithm` does not match the product attestation's `hashAlgorithm`. A proof tagged `sha-1` against a tree built with `sha256` is invalid even if the audit path happens to compute. Hash-algorithm confusion is a known CVE class.
- **The leaf hash includes the path.** Two files with identical content at different paths have different leaf hashes. The predicate carries both `leafPath` and `fileDigest`, so a verifier can refuse a proof whose path or digest does not match the file the consumer is asking about.
- **The proof is meaningless without a signed root.** Always verify the product/material attestation's signature before trusting its claimed root as the proof's terminator. ([GHSA-jp26-88mw-89qr](https://github.com/sigstore/sigstore-java/security/advisories/GHSA-jp26-88mw-89qr) is the canonical example of skipping this step.)
- **The sidecar tree is not evidence.** `` `<outfile>.product.tree.json` `` / `` `<outfile>.material.tree.json` `` are unsigned and producer-only. A consumer who somehow obtained one has no signed claim to verify against — only the producer's signature on the inclusion-proof attestation makes the proof trustworthy.

## CLI example

```bash
cilock prove \
  --tree-sidecar attestation.product.tree.json \
  --file dist/binary \
  --signer-file-key-path key.pem \
  --outfile dist-binary.inclusion-proof.json
```

The output is a standalone signed DSSE envelope. Archive it alongside the build's other evidence, upload it to Archivista, or attach it to the release bundle.

## Wiring into a policy

Unlike other cilock predicates, an inclusion-proof envelope is a **bare DSSE predicate, not a `Collection`**. That means it cannot be referenced as one of a step's `attestations[].type` entries — the policy engine's Collection-walking code path won't unmarshal it (it tries to decode the bare predicate as a `Collection` body and silently produces an empty struct).

The correct wiring uses `Policy.externalAttestations` + `Step.externalFrom`:

```json
{
  "externalAttestations": {
    "binaryInclusionProof": { "type": "https://aflock.ai/attestations/inclusion-proof/v0.1" }
  },
  "steps": {
    "release": {
      "externalFrom": ["binaryInclusionProof"],
      "attestations": [ /* ... */ ],
      "regopolicies": [ /* ... */ ]
    }
  }
}
```

That lifts the inclusion-proof predicate into the Rego module's `input.external.binaryInclusionProof`, where the release-gate rule can compare `treeRoot` against `input.steps.build["https://aflock.ai/attestations/product/v0.3"].merkleRoot` to verify the proof is bound to the artifact the build produced.

See [`multi-step-attestationsFrom`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/multi-step-attestationsFrom) for a worked policy that uses this pattern end-to-end.

## See also

- [Product attestor v0.3](./product-v0.3) — the source of the Merkle root being proved against
- [Inclusion proofs](../concepts/inclusion-proofs) — the underlying algorithm
- [The spine of the graph](../concepts/the-spine-of-the-graph) — why the subject is the file digest
- [Prove files in a build](../guides/prove-files-in-a-build) — producer-side workflow
- [Verify a specific file](../guides/verify-a-specific-file) — consumer-side workflow
- [Issue #135](https://github.com/aflock-ai/rookery/issues/135) — design rationale
