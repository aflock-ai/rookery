---
title: The spine of the graph
sidebar_position: 11
---

# The spine of the graph

CI/lock's verifier walks a subject-digest graph. The walk is BFS: start from a seed digest (whatever the user passed to `cilock verify -s sha256:…` or `-f path/to/artifact`), find every attestation whose subject set contains that digest, expand the seed set with the *back-references* those attestations declare, and iterate until the frontier stops growing.

This page is about *which digests get to grow the frontier*. It is the part of the design that decides whether inclusion proofs slot in naturally or have to be bolted on with a new index.

## What expands the frontier

The verifier expands the seed set from one source only:

```go
// attestation/policy/policy.go, lines 531–547
for _, coll := range passedCollections {
    for _, digestSet := range coll.Collection.BackRefs() {
        for _, digest := range digestSet {
            if _, seen := knownDigests[digest]; !seen {
                knownDigests[digest] = struct{}{}
                nextDepthDigests = append(nextDepthDigests, digest)
            }
        }
    }
}
```

Only `Collection.BackRefs()` grows the frontier. External-attestation subjects do not, by design — that constraint exists to keep the Collection graph isolated from arbitrary external statements that happen to mention a digest the verifier is looking at (rookery issue #39).

A *Collection* is the group of attestors a single `cilock run` step emits together. The Collection's BackRefs are the subset of digests its constituent attestors have declared safe for the verifier to chase. The Git attestor declares the commit SHA as a backref. The Product attestor declares its tree root as a backref. The Material attestor declares its tree root as a backref. The Command-Run attestor's backrefs link to materials and products.

That is the spine of the graph. Subjects that are *not* in BackRefs are still searchable (the verifier uses them for matching attestations to seeds) but they do not propagate the search outward.

## How inclusion proofs join the spine

Since v0.3, product/material attestations [inline their per-file `leaves` in the signed predicate](../attestors/product), so the common per-file path needs no standalone inclusion-proof attestation at all — the verifier folds a file digest to the signed root straight from the product attestation. Inline DSSE-signed leaves are the sole trust path in v0.3; off-envelope chain sidecars are not part of the current design. The graph walk below documents the subject-digest BFS path, which also handles any standalone inclusion-proof attestation supplied for backward compatibility with pre-v0.3 evidence, with no special-case code.

An inclusion-proof attestation's predicate names a Merkle root; its subject is the per-file digest. We want the verifier, starting from a file digest, to:

1. Find the inclusion-proof attestation by subject-digest match.
2. From it, jump to the product attestation that owns the Merkle root.
3. From the product attestation, jump to the rest of the build's evidence (the command-run attestation, the SBOM, the SARIF, the SLSA provenance) via the existing BFS.

That is exactly what the existing subject-digest BFS already does, with no new index and no special-case code. The walk:

```
  seed digest = sha256:<binary file digest>
       │
       ▼  subject-digest match
  inclusion-proof attestation
    subject:   file digest
    predicate: treeRoot = sha256:<root>
       │
       ▼  BackRef on the inclusion-proof Collection points at treeRoot
  product attestation
    subject:   tree:products = sha256:<root>
       │
       ▼  BackRefs on the product Collection (command-run, materials, git commit)
  rest of the build's evidence
```

The inclusion-proof attestation is a standalone Collection — it has its own DSSE envelope, its own signature, and its own BackRef set. Its BackRef set names the Merkle root, which lets the BFS find the product attestation. The product attestation's BackRef set names the materials' Merkle root and the git commit, which lets the BFS find the command-run, the source, the SBOM, and so on.

No new endpoint. No new index. The existing subject-digest scan that Archivista has had since day one returns the inclusion-proof attestation directly when queried by file digest, because the inclusion-proof's subject *is* the file digest.

## Why this works: BackRefs are the spine, not all subjects

A subject is what an attestation is *about*. A BackRef is a subject the verifier is *allowed to chase further*. Those are deliberately different. If every subject grew the frontier, a malicious or accidental attestation that listed an unrelated digest as a subject would pull the verifier into evidence the user did not ask about — a denial-of-service vector at best, an evidence-injection vector at worst.

By restricting frontier-growth to BackRefs declared by trusted Collections, CI/lock keeps the graph walk anchored in evidence the policy has already vetted. The inclusion-proof attestor declares only one BackRef (the Merkle root), and that BackRef is meaningful precisely because the policy has already established that the inclusion-proof signer is trusted.

This is the structural reason inclusion proofs slot in so cleanly. The v0.3 attestor was designed so its BackRef is exactly the one digest the verifier needs to make the jump from a per-file claim to the product tree that owns it.

## What we considered and rejected: the v0.2-style approach

The alternative was to keep the v0.2 design — a flat per-file digest map in the product predicate as the *only* per-file representation, with the verifier reading digests directly out of that map and **no Merkle root or inline-leaves discipline** behind it.

That approach was rejected for three reasons, none of which are inflation. v0.3's inline `leaves` avoid all three: they fold to a single signed root, the subject stays the tree root, and every per-file claim is verifiable directly from the signed envelope:

1. **Unbounded predicate size with no escape hatch.** An `npm install`-scale tree carries ~30k entries × ~80 bytes ≈ 2.4 MB of predicate per envelope, plaintext. Multiply by every build per day. The v0.2 map had no way to opt out; v0.3 inlines the leaf array which is already compact (path + digest + pre-hash per entry) rather than a full flat map.

2. **No per-file provability.** With the v0.2 flat map, the verifier had no Merkle path to walk — every per-file claim required re-decoding the full predicate. v0.3's inline leaves carry the RFC 6962 audit path preimage directly, so a single leaf check is O(log n).

3. **No clean BFS path from file to product.** The v0.2 product attestor's subject is `tree:products` (the Merkle root). Per-file digests lived only in the predicate, not the subject array, so the subject-digest BFS could not find a v0.2 product attestation by file digest at all — Judge issues #3840 and #3841 existed specifically to materialize a separate file-digest index server-side to bridge that gap. v0.3's inline leaves keep the tree-root subject *and* make every file verifiable from the one signed attestation, and the inclusion-proof attestation closes the gap on the client side when leaves are suppressed.

v0.3 is the only producer. For verification, a single `LegacyDecoder` covers both pre-cutover predicate URIs: `product-v0.1` and `product-v0.2` share the same flat `map[string]Product` predicate body (they only differ in the in-toto `Statement.Subject` array v0.2 collapsed to a single tree-root subject), so one decoder parameterized by predicate URI reads both. Existing v0.1 and v0.2 envelopes flow through `cilock verify` with no operator action — but the v0.2 hash-chain root is the design we're explicitly walking away from, not a producer worth keeping; the LegacyDecoder refuses `Attest()`. The full rationale is in [issue #135 on the rookery repo](https://github.com/aflock-ai/rookery/issues/135).

## Cross-references

- [Policy verification](./policy-verification) — what the BFS is in service of
- [Inclusion proofs](./inclusion-proofs) — the proof primitive being used
- [Product attestor v0.3](../attestors/product) — the attestation type whose subject becomes the BackRef target
- [Inclusion-proof attestor](../attestors/inclusion-proof) — the attestation type whose subject is the file digest
