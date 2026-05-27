---
title: product
description: The cilock product attestor snapshots the working directory after a step runs and emits a single RFC 6962 Merkle-root in-toto subject (tree:products) over every output file's digest.
sidebar_position: 4
---

Snapshots the working directory after the step's command runs, computes a Merkle root over every product file's digest, and emits a single in-toto subject (`tree:products`) whose digest is the root. The full per-file digest map is **not** carried in the predicate — that lives in a producer-side sidecar (`attestation.tree.json`) and is exposed to consumers via separate [inclusion-proof attestations](./inclusion-proof) on demand.

## What it captures

The v0.3 predicate is small and fixed-size. The schema:

| JSON field | Type | Source |
|---|---|---|
| `merkleRoot` | string (`<algo>:<hex>`) | The Merkle root over the sorted product list, computed via [RFC 6962 §2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1). Hex-encoded for byte hashes; gitoid URI form for gitoid hashes. |
| `treeSize` | integer | Number of files that contributed to the root (after include/exclude glob filtering). |
| `hashAlgorithm` | string | Name of the hash algorithm. Default `sha256`. Matches the algorithm cilock used to build the tree. |
| `construction` | string | Always `RFC6962` for v0.3. Future hash constructions would extend this field. |

The DSSE statement's subject array carries one entry:

```json
"subject": [
  {
    "name": "tree:products",
    "digest": { "sha256": "<merkleRoot>" }
  }
]
```

That is the entire surface area of the predicate. The full per-file list — every path and every digest — does not appear here. It lives in the `<outfile>.product.tree.json` sidecar `cilock run` writes next to the signed envelope (and a parallel `<outfile>.material.tree.json` for the material attestor).

## Why v0.3 looks like this

v0.2 carried the full per-file digest map (`map[path]Product`) inside the predicate. For source-only projects that was fine — a `go build` produces a handful of files. For package installations (`pip install litellm`, `npm install next`, `cargo build`) the map ballooned to tens of thousands of entries, which:

- Inflated DSSE envelope size to multi-megabyte territory.
- Required Archivista to materialize a separate per-file index server-side to answer the question "which build contains file digest X" without re-decoding every predicate.
- Forced consumers to download and parse the full predicate even when they only cared about one file.

v0.3 fixes all three by moving per-file claims into separate inclusion-proof attestations. The product attestation says "this tree exists and these are its properties"; an inclusion-proof attestation says "and this specific file is in it." Together they verify per-file claims. See [issue #135](https://github.com/aflock-ai/rookery/issues/135) for the full rationale.

## When to use

It always fires — there is no `--enable-attestor product` toggle and no opt-out. Shape the input file set with `--attestor-product-include-glob` and `--attestor-product-exclude-glob`. These globs apply to forward-slash-normalized paths.

## Flags

| Flag | Default | Effect |
|---|---|---|
| `--attestor-product-include-glob` | `*` | Files matching this `gobwas/glob` pattern are included as leaves in the Merkle tree. |
| `--attestor-product-exclude-glob` | `""` | Files matching this pattern are skipped; evaluated before include. |

Both globs match against the forward-slash-normalized relative path inside the working directory. On Windows, write patterns with `/` even when the on-disk separator is `\`.

## Subject behavior

`Subjects()` returns exactly one entry, `tree:products`. The digest is the Merkle root computed via the following two-step leaf encoding:

```
Sort products by forward-slash-normalized path (lexically).
For each (path, file-digest) pair:
  leafPreHash = sha256(path-bytes || 0x00 || file-digest-bytes-raw32)
  // 32-byte pre-hash; path-bytes is the UTF-8 forward-slash form,
  // file-digest-bytes-raw32 is the RAW 32-byte sha256 (NOT the hex string).
Pass the leafPreHash list into a merkle tree built per RFC 6962 §2.1.
The wrapper applies its own 0x00 leaf-domain prefix and 0x01 interior prefix,
so the actual leaf the tree commits to is:
  H(0x00 || leafPreHash) = H(0x00 || sha256(path || 0x00 || file-digest))
```

The 0x00 inside `leafPreHash` is the path/digest separator (preventing collisions like `("foo", digestA)` vs `("fooX", digestA')`). The 0x00 the merkle wrapper prepends is the RFC 6962 leaf-domain prefix (preventing the CVE-2017-12842 64-byte interior-node-as-leaf attack). They are distinct constants serving distinct purposes — see [merkle trees](../concepts/merkle-trees).

Paths are normalized with `inclusionproof.NormalizePath` (`strings.ReplaceAll(p, "\\", "/")`, not `filepath.ToSlash`) so a Windows-recorded root re-hashes identically on Linux. The same helper is the single canonical normalizer for both product and material — drift between the two would silently break verification.

If zero files survive the globs, the predicate still carries a root: the RFC 6962 empty-tree root (`sha256("")`). The `tree:products` subject is always present so verifiers can refuse a missing root rather than treating "empty" as "absent."

## Output shape

The full DSSE statement for a v0.3 product attestation:

```json
{
  "_type":         "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name":   "tree:products",
      "digest": { "sha256": "9c6f...d3a1" }
    }
  ],
  "predicateType": "https://aflock.ai/attestations/product/v0.3",
  "predicate": {
    "merkleRoot":    "sha256:9c6f...d3a1",
    "treeSize":      30142,
    "hashAlgorithm": "sha256",
    "construction":  "RFC6962"
  }
}
```

The predicate is fixed-size regardless of how many files were in the working directory. A 30,000-file build produces the same predicate length as a 3-file build.

## Sidecar tree

`cilock run` writes two sidecar files adjacent to the signed envelope whenever the product and material attestors build trees:

- `<outfile>.product.tree.json` — the product tree
- `<outfile>.material.tree.json` — the material tree

Both share the same on-disk schema: `rookery.inclusion-proof.sidecar/v0.1`, defined in `plugins/attestors/inclusion-proof`. The body carries `source` (either `"product"` or `"material"`), the Merkle root, the tree size, the pinned hash algorithm and construction constants, and the sorted list of `(path, fileDigest)` pairs — exactly the inputs needed for `cilock prove` to reconstruct the tree and emit inclusion proofs.

The sidecar is **not signed**. It is not evidence. Treat it as a build cache: regenerate by re-running the build, or discard once the inclusion proofs you need have been emitted. Do not ship it to downstream consumers — they only need the signed inclusion-proof attestations.

Path convention: for `--outfile attestation.json` the sidecars are `attestation.product.tree.json` and `attestation.material.tree.json`. If `--outfile` is empty (stdout), no sidecars are written.

See [prove files in a build](../guides/prove-files-in-a-build) for the producer flow.

## Composition with inclusion-proof attestations

The product attestation alone does not let a consumer verify a per-file claim — it says "the tree exists and its root is X" but does not expose any specific leaf. The consumer-facing piece is the inclusion-proof attestation:

- The **product attestation** says: "this tree exists; its root is X; size is N; built with sha256/RFC6962."
- An **inclusion-proof attestation** for a specific file says: "this file's digest is leaf `i` in the tree with root X; here is the audit path."

A verifier with both attestations confirms (a) the audit path reconstructs the claimed root, (b) the claimed root matches the product attestation's subject digest, and (c) the leaf hash matches the file the verifier was asked about. See [verify a specific file](../guides/verify-a-specific-file) for the full check sequence.

## Gotchas

- **Globs operate on forward-slash-normalized paths.** Write `dist/**/*` even on Windows.
- **MIME detection is gone from v0.3.** v0.2 emitted per-file MIME types so downstream attestors (SBOM, VEX, SLSA) could find SBOM files by MIME. v0.3 does not carry per-file metadata. Downstream attestors that previously walked `ctx.Products()` for MIME-typed files continue to work — they read from the attestation context's product map, which is populated by the same workdir-snapshot code, not from the v0.3 predicate.
- **Include/exclude globs affect the tree, not just the subject.** Excluded files are not leaves and do not contribute to the root. (v0.2 globs affected only the subject; v0.3 globs affect the full tree.)
- **Anything in `ctx.Materials()` at step start is not a product.** Files produced by an earlier stage become *materials* in later stages and stop appearing as products.
- **Empty product set still emits a tree subject.** Per the v0.3 spec the predicate ALWAYS carries a root — an empty workdir produces the RFC 6962 empty-tree root (`sha256("")`). Verifiers must refuse a missing-root predicate, not treat "empty" as "absent."

## CLI example

Builtin. cilock always runs this — classifies files written during the wrapped command and emits the Merkle root.

```bash
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir build/ \
  -- make build
```

The signed `attestation.json` and the unsigned `attestation.tree.json` sidecar both land in the working directory after the run completes.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the per-file claim primitive
- [Merkle trees](../concepts/merkle-trees) — the underlying construction
- [Prove files in a build](../guides/prove-files-in-a-build) — producer-side flow
- [Verify a specific file](../guides/verify-a-specific-file) — consumer-side flow
- [Issue #135](https://github.com/aflock-ai/rookery/issues/135) — design rationale
