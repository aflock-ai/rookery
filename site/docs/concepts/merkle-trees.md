---
title: Merkle trees
sidebar_position: 9
---

# Merkle trees

A Merkle tree is a binary tree where every leaf is a hash of some data and every interior node is a hash of its two children. The single hash at the top — the *root* — commits to every leaf simultaneously. If a single byte changes anywhere in the input set, the root changes.

That is the whole structural idea. The rest of this page is about why the specific construction CI/lock uses (RFC 6962) looks the way it does, and what would break if it did not.

## The construction (RFC 6962 §2.1)

For an input list of `n` data entries `d(0)`, `d(1)`, …, `d(n-1)`, the Merkle Tree Hash (MTH) is defined recursively:

- Empty list: `MTH({}) = SHA-256()` (the hash of the empty byte string).
- Single entry: `MTH({d(0)}) = SHA-256(0x00 || d(0))`.
- Multiple entries: split at `k`, the largest power of 2 strictly less than `n`. Then `MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`.

The two domain prefixes — `0x00` for leaves, `0x01` for interior nodes — are not decoration. They are load-bearing security. See "Why the prefix bytes exist" below.

The split rule (`k` is the largest power of 2 less than `n`) is important too. A naive implementation that just rounds the tree up to the next power of 2 and pads with zero or duplicate leaves will compute a *different* root for the same input set and silently disagree with every other RFC 6962 verifier on the network. The transparency-dev test vectors cover sizes 1 through 95; any production implementation must agree with them byte-for-byte.

The full standard reference is [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962). [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) §2.1.3 restates the same construction in cleaner language; the hash bytes are identical, so a 6962 root and a 9162 root over the same inputs are bytewise equal.

## A four-leaf example

```
                              root
                            /      \
                       n01            n23
                     /     \         /    \
                  L0       L1     L2      L3

  L0 = SHA-256(0x00 || d0)
  L1 = SHA-256(0x00 || d1)
  L2 = SHA-256(0x00 || d2)
  L3 = SHA-256(0x00 || d3)
  n01 = SHA-256(0x01 || L0 || L1)
  n23 = SHA-256(0x01 || L2 || L3)
  root = SHA-256(0x01 || n01 || n23)
```

The CI/lock product attestor v0.3 emits `root` as a single in-toto subject. Each `d_i` is a per-file leaf record derived from the file's path and content digest in the working directory after the step's command ran — not the bare content digest. The product/material predicate carries that `d_i` value inline as the `leafHash` field of each leaf, and the RFC tree leaf is `SHA-256(0x00 || d_i)`. Verified: for a single-file product tree, `SHA-256(0x00 || leafHash) == root`, whereas `SHA-256(0x00 || fileDigest)` does not — so the leaf preimage is path-bound, not the raw file digest.

## Why the prefix bytes exist

A SHA-256 hash is 32 bytes. An interior-node input is `0x01 || L || R`, which is 65 bytes — the prefix plus two child hashes. Without the prefix, an interior input would just be `L || R` — 64 bytes — and an attacker could compute a 64-byte leaf whose contents are byte-for-byte equal to some legitimate interior concatenation.

That attack is real. [CVE-2017-12842](https://nvd.nist.gov/vuln/detail/CVE-2017-12842) tracks it for Bitcoin SPV proofs: a malicious peer can craft a 64-byte "leaf" payload that hashes to the same value as an interior node of a real tree, then present an inclusion proof for that payload that any naive verifier will accept. Bitcoin SPV inherited the vulnerability from a Merkle construction that did not domain-separate leaves from interior nodes. Certificate Transparency designed it out from the start by mandating the two prefixes.

CI/lock's RFC 6962 implementation enforces both prefixes. A verifier that accepts an inclusion proof must hash the candidate leaf with the `0x00` prefix; an attacker who submits raw interior-shape bytes as a leaf cannot collide with any legitimate root because the verifier's hash includes the prefix byte that the attacker did not.

This is the visceral reason to read the RFC carefully before implementing one of these. The construction looks like it has spare moving parts. It does not.

## Inclusion proofs and consistency proofs together

A Merkle tree is the *data structure*. By itself it commits to a fixed snapshot of inputs. Two derived proof types make it useful as a transparency primitive:

- An **inclusion proof** lets a verifier confirm "this leaf is in this tree" by following a short path of sibling hashes up to the root. See [inclusion proofs](./inclusion-proofs).
- A **consistency proof** lets a verifier confirm "the tree of size N is a prefix of the tree of size M (M > N)" — i.e. the log is append-only, no historical entry has been edited or deleted. Sigstore's Rekor and Google's Certificate Transparency logs both rely on consistency proofs to detect log forks.

CI/lock v0.3 ships inclusion proofs as a standalone primitive; consistency proofs are not in the first cut because the product/material trees are per-build snapshots rather than an append-only log. The mental model still needs both — readers who learn inclusion proofs without learning what consistency proofs do will get confused when they read about Rekor or Sigstore. Stacklok's ["Decoding Rekor"](https://stacklok.com/blog/decoding-rekor-understanding-sigstores-transparency-log) is the cleanest walkthrough of the two together.

## How CI/lock uses them

The product v0.3 attestor computes the Merkle root over the per-file digest list of products written during a `cilock run` step. That root is the single in-toto subject of the product attestation, so the *subject* stays fixed-size no matter the file count. The predicate also carries the per-file `leaves` inline (the sole trust path in v0.3), so per-file provability comes straight from the product attestation — a verifier matches a file digest to a leaf and folds it to the signed root with nothing else. Inline DSSE-signed leaves are always present; off-envelope chain sidecars are not part of the current design.

See [the spine of the graph](./the-spine-of-the-graph) for how inclusion-proof attestations slot into CI/lock's existing subject-digest discovery.

## Models we deliberately followed

The structural presentation on this page mirrors [transparency.dev's Verifiable Data Structures page](https://transparency.dev/verifiable-data-structures/), which is the cleanest hierarchical introduction to the topic. [Cloudflare's "A Tour Through Merkle Town"](https://blog.cloudflare.com/a-tour-through-merkle-town-cloudflares-ct-ecosystem-dashboard/) is the recommended visual on-ramp if the algebra here feels dry — it shows the same construction in the live Certificate Transparency ecosystem.

## References

- [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) — Certificate Transparency
- [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) — Certificate Transparency v2
- [CVE-2017-12842](https://nvd.nist.gov/vuln/detail/CVE-2017-12842) — Bitcoin SPV second-preimage attack
- [transparency.dev — Verifiable Data Structures](https://transparency.dev/verifiable-data-structures/)
- [Cloudflare — A Tour Through Merkle Town](https://blog.cloudflare.com/a-tour-through-merkle-town-cloudflares-ct-ecosystem-dashboard/)
- [Stacklok — Decoding Rekor](https://stacklok.com/blog/decoding-rekor-understanding-sigstores-transparency-log)
