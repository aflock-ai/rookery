---
title: Inclusion proofs
sidebar_position: 10
---

# Inclusion proofs

An inclusion proof is a short list of hashes that lets a verifier confirm "this leaf is in this tree" without seeing the whole tree. It is the primitive that makes Merkle trees useful as a public, queryable evidence structure: a producer publishes a signed root over millions of entries, and a consumer who only cares about one entry pays the cost of a single proof — `O(log n)` hashes — rather than re-downloading every leaf.

This page walks through the algorithm with the worked example from [RFC 9162 §2.1.5](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.5), then shows how CI/lock binds the root to a signed in-toto Statement so the proof is meaningful.

## The audit path algorithm

Given a tree of size `n` and a target leaf at index `i`:

1. Hash the leaf with the `0x00` prefix: `leafHash = SHA-256(0x00 || d_i)`.
2. Walk from the leaf up to the root. At each level, the verifier needs the sibling hash on the path. The proof is the ordered list of those sibling hashes.
3. At each step, the verifier reconstructs the parent: if the current node is the left child, parent = `SHA-256(0x01 || current || sibling)`; if the right child, parent = `SHA-256(0x01 || sibling || current)`.
4. After consuming every sibling in the proof, the reconstructed value must equal the claimed root.

The length of the proof is `⌈log₂(n)⌉` hashes — roughly 10 for a 1k-entry tree, 15 for 30k, 20 for 1M. The proof's storage cost is logarithmic in the tree size, which is what makes the whole construction practical.

The standard algorithm is specified in [RFC 6962 §2.1.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1.1) and restated more cleanly in [RFC 9162 §2.1.3.1](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.3.1).

## Worked example (RFC 9162 §2.1.5)

The RFC's worked example uses seven leaves whose data is the integers `0`, `1`, … `6` (each as a single ASCII byte). The tree looks like this:

```
                              k                    <- root, size 7
                          /       \
                        i           j
                       / \           \
                     g     h           m
                    / \   / \         / \
                   a   b c   d       L4  L5     L6
                   |   | |   |
                   L0  L1 L2 L3

  L_i = SHA-256(0x00 || byte(i))   for i in 0..6
  a = L0   b = L1   c = L2   d = L3
  g = SHA-256(0x01 || a || b)
  h = SHA-256(0x01 || c || d)
  i = SHA-256(0x01 || g || h)
  m = SHA-256(0x01 || L4 || L5)
  j = SHA-256(0x01 || m || L6)
  k = SHA-256(0x01 || i || j)
```

The non-power-of-two split rule does the work here. At size 7, the largest power of 2 strictly less than 7 is 4 — so the left subtree is the first four leaves (a full power-of-2 tree of depth 2) and the right subtree is the last three (the unbalanced part). The right subtree splits again: 2 + 1 → `m` and `L6`. A buggy implementation that pads to 8 leaves with a duplicate or zero leaf will compute a different root.

### Proving L4 is in the tree

The audit path for index 4 (the leaf `L4`) is:

```
[ L5, L6, i ]
```

Verification:

1. Start with `current = L4 = SHA-256(0x00 || 0x04)`.
2. Index 4 in a 7-leaf tree is the left child at level 0 of the right subtree. Combine with `L5` (right sibling): `current = SHA-256(0x01 || L4 || L5) = m`.
3. At level 1, `m` is the left child. Combine with `L6` (right sibling): `current = SHA-256(0x01 || m || L6) = j`.
4. At level 2, `j` is the right child of the root. Combine with `i` (left sibling): `current = SHA-256(0x01 || i || j) = k`.
5. Compare `current` to the claimed root. Match → leaf is in the tree.

The proof length is 3 = `⌈log₂(7)⌉`. The RFC includes hex-encoded test vectors for every leaf in this tree; any CI/lock implementation must reproduce them.

## A proof is meaningless without a signed root

This is the trap. An inclusion proof in isolation says "given this root, this leaf hash is at this index." It does not say the root is genuine. An attacker can build an entirely separate Merkle tree containing whatever leaf they want and emit a valid-looking proof. The verifier still has to be sure the *root* came from the right place.

In CI/lock, the root comes from a product attestation — a signed in-toto Statement whose single subject is `tree:products` with the Merkle root as its digest. Since v0.3 [product/material attestations inline their leaves by default](../attestors/product), the verifier reads the leaf set straight from that one signed attestation: it matches the artifact's digest to a leaf and folds it through the inline tree to the signed root — no separate inclusion-proof attestation needed. A standalone inclusion-proof attestation is the *selective-disclosure* form (or for builds that suppressed inline leaves); when one is used, the verifier's contract is:

1. Verify the DSSE signature on the product attestation. Reject if the signer is not a trusted functionary per the policy.
2. Verify the DSSE signature on the inclusion-proof attestation. Same trust check.
3. Confirm the inclusion-proof attestation's `predicate.treeRoot` matches the product attestation's subject digest. Reject on mismatch.
4. Run the audit-path verification. Reject if the reconstructed root does not match.
5. Confirm the inclusion-proof attestation's *subject* matches the artifact under verify (the consumer's seed digest). Reject on mismatch.

All five checks are mandatory (the inline-leaves path performs the equivalent: trusted-signer check, leaf-to-root reconstruction, and digest cross-check, against the single product attestation). Skipping any one of them re-introduces a known CVE class. [CVE-2026-22703](https://nvd.nist.gov/vuln/detail/CVE-2026-22703) (a cosign issue) is the canonical example of step 5 being skipped: a valid proof for a different artifact was accepted because the verifier did not check that the proof's leaf hash matched the artifact the user asked about. [GHSA-jp26-88mw-89qr](https://github.com/sigstore/sigstore-java/security/advisories/GHSA-jp26-88mw-89qr) is step 1 skipped: a valid-looking proof rooted in an attacker-chosen tree was accepted because the checkpoint signature was never validated.

## Inclusion proofs and consistency proofs

A consistency proof confirms that one Merkle tree is a prefix of another — that the tree at size `N` is the same data the larger tree at size `M` extends. Logs that need to be *append-only* (Certificate Transparency, Sigstore Rekor) rely on consistency proofs to detect log tampering.

CI/lock product/material trees are per-build snapshots, not append-only logs, so v0.3 does not ship consistency proofs. The mental model still needs both — anyone who reads about Sigstore or CT will see consistency proofs alongside inclusion proofs, and presenting one without the other leaves a hole in the reader's intuition. [Stacklok's "Decoding Rekor"](https://stacklok.com/blog/decoding-rekor-understanding-sigstores-transparency-log) is the cleanest walkthrough showing both proofs working together; read it once even if CI/lock itself does not need consistency proofs today.

## Forward compatibility with SCITT

The [draft-ietf-cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/html/draft-ietf-cose-merkle-tree-proofs-18) spec defines a CBOR wire format for RFC 9162 inclusion proofs, with `alg = 1` reserved for `RFC9162_SHA256`. CI/lock's inclusion-proof predicate uses the same underlying hash construction, so the bytes that CI/lock signs are convertible to the SCITT CBOR encoding without re-hashing. The [draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture) spec wraps such proofs into "receipts" issued by a transparency service.

CI/lock does not ship SCITT receipts today. We are bytewise compatible with the underlying primitives so a future SCITT bridge is a wire-format translation rather than a re-hash. See [SCITT relationship](./scitt-relationship) for the full forward-look.

## References

- [RFC 6962 §2.1.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1.1) — inclusion proof generation
- [RFC 9162 §2.1.3.1](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.3.1) — restated algorithm
- [RFC 9162 §2.1.5](https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.5) — the worked 7-leaf example
- [draft-ietf-cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/html/draft-ietf-cose-merkle-tree-proofs-18) — COSE wire format
- [draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture) — SCITT receipts
- [Chainguard Academy — An Introduction to Rekor](https://edu.chainguard.dev/open-source/sigstore/rekor/an-introduction-to-rekor/) — worked-example template
- [Stacklok — Decoding Rekor](https://stacklok.com/blog/decoding-rekor-understanding-sigstores-transparency-log) — inclusion + consistency together
