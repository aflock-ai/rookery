# product attestor

The `product` attestor records the files that exist in the working directory
after a `cilock run` step completes — the *outputs* of whatever command the
step wrapped (`go build`, `pip install`, `npm install`, `cargo build`, etc.).
It is the canonical "what did this step produce" attestor and sits at the
bottom of the dependency stack for the SBOM, SARIF, SLSA, and inclusion-proof
attestors which all walk the product set.

## Predicate type

| URI                                                | Status     | Subject shape                                  |
|----------------------------------------------------|------------|------------------------------------------------|
| `https://aflock.ai/attestations/product/v0.3`      | **Current**| One `tree:products` subject (Merkle root)      |

v0.3 is a **HARD CUT** from v0.1 and v0.2. Neither older predicate type is
registered any more. Historical attestations stored under
`https://aflock.ai/attestations/product/v0.1` or `v0.2` will not deserialize
against this build; verifiers needing to read those must use an older cilock.

## Why v0.3 (briefly)

v0.1 emitted one in-toto subject per file. For large product sets (e.g.
`pip install litellm` ≈ 3,200 files; `npm install next` ≈ 29,000 files) that
exceeded MySQL's 65,535-parameter prepared-statement cap and produced 10+ MB
DSSE envelopes.

v0.2 collapsed the file set into a single `tree:products` subject whose
digest is a hand-rolled hash chain over `(name || 0x00 || file-digest || 0x00)`
per file. That fixed the placeholder explosion but did not produce a tree the
verifier could prove individual file inclusion against without re-walking the
build.

v0.3 publishes the Merkle root of an **RFC 6962** tree over the product set.
The per-file leaves live in a side-channel sidecar; verifiers (or future
auditors) can produce per-file inclusion proofs without re-walking the build.
Compatibility-mode reading of old v0.1/v0.2 statements is intentionally
dropped — the wire format changed.

## Leaf encoding

This attestor and the inclusion-proof attestor (`cilock prove`) agree on:

```
leafPreHash = sha256(path-bytes || 0x00 || file-digest-bytes-raw32)
```

The Merkle wrapper (`attestation/merkle`) accepts only fixed-length 32-byte
leaves so that its API contract stays clean. We therefore pre-hash the
path-bound leaf at this attestor, then pass the 32-byte pre-hash into
`merkle.NewTree([][]byte)`. The wrapper applies RFC 6962's own 0x00 leaf
prefix internally, so the **actual leaf hash the tree commits to** is:

```
H(0x00 || sha256(path || 0x00 || file-digest))
```

This:

- binds the file path cryptographically (two files with the same content at
  different paths produce different leaf hashes and different roots);
- preserves the wrapper's HashSize-leaf invariant;
- is portable across host operating systems because paths are normalized to
  forward slashes before hashing.

Leaves are sorted by their forward-slash-normalized path before tree
construction, so the root depends only on the logical product set — never on
filesystem walk order.

## Predicate JSON

```json
{
  "merkleRoot":    "9c6f...d3a1",
  "treeSize":      30142,
  "hashAlgorithm": "sha256",
  "construction":  "RFC6962"
}
```

The four fields are O(1) regardless of product count — that is the whole
point of the rewrite. Per-file data is **not** in the predicate; sidecars
carry it.

## Side-channel tree sidecar

Producers can stash the full leaf set in a side-channel file so
`cilock prove` can generate inclusion proofs after the fact:

```go
a.WriteSidecar("./tree.sidecar.json")
```

Schema (`https://aflock.ai/product-tree-sidecar/v0.1`):

```json
{
  "schemaVersion":  "https://aflock.ai/product-tree-sidecar/v0.1",
  "merkleRoot":     "sha256:9c6f...d3a1",
  "treeSize":       30142,
  "hashAlgorithm":  "sha256",
  "construction":   "RFC6962",
  "leaves": [
    { "path": "dist/binary", "fileDigest": "sha256:def...", "leafHash": "sha256:ghi..." },
    ...
  ]
}
```

The sidecar is **NOT signed** and **NOT** part of the attestation envelope.
Producers may discard it. Verifiers may demand it from the producer for
inclusion-proof generation. The plumbing for *where* the CLI writes this
file from `cilock run` is the inclusion-proof attestor's responsibility.

## Configuration

| Option           | Default | Purpose                                                  |
|------------------|---------|----------------------------------------------------------|
| `--include-glob` | `*`     | Only paths matching this glob are recorded as products.  |
| `--exclude-glob` | (none)  | Paths matching this glob are removed from the product set.|

Filtering happens before tree construction, so the root reflects only the
products that survive filtering.

## Determinism guarantees

- Same logical product set → same root, regardless of host OS.
- Insertion order of the underlying filesystem walk does not affect the root.
- The hash algorithm and Merkle construction are both pinned in the predicate
  so verifiers can refuse anything that claims another shape.
