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

## How the product set is captured

This attestor commits a Merkle root over a set of output files — but *which* files count as products, and where their digests come from, is decided by the active **capture mode**, not by the attestor itself:

- **Directory walk** (default, and the only mode without `--trace`): files created or changed in `--workingdir` during the command window become products. cilock uses mtime so a byte-identical rebuild still registers as a product.
- **Syscall trace** (`--trace`, Linux): cilock observes which files the step *and its child processes* wrote — including outputs written outside the working directory. The trace backend is `ptrace+seccomp` (always available) or `eBPF` where the kernel supports it; `CILOCK_TRACE_MODE=auto` probes eBPF and falls back to ptrace.
- **fanotify** (`--hardening standard`/`strict`): hashes product content at `FAN_CLOSE_WRITE` and anchors the set to files that still exist at process exit.

`--capture-mode auto` (the default) uses trace events when `--trace` is on and the directory walk otherwise. See [how cilock captures files](../concepts/capture-modes) for the full comparison and a selection guide.

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

## Inline leaves

Since v0.3 is the sole producer, the signed envelope always carries the full `leaves` array — every `(path, fileDigest, leafHash)` triple — inline. This means the product attestation is self-contained: a verifier can confirm any specific file's inclusion by matching its digest to a leaf, reconstructing the leaf hash via `inclusionproof.LeafHash`, and confirming it folds to the signed `tree:products` root. No sidecar, no separate inclusion-proof envelope, no additional round-trip.

## Per-file verification

The product attestation's inline `leaves` array exposes every `(path, fileDigest, leafHash)` triple, so per-file claims are verified directly from the product attestation:

1. Find the leaf whose `fileDigest` equals the file digest being verified.
2. Confirm the leaf's `leafHash` equals `sha256(leafPath-bytes || 0x00 || fileDigest-bytes-raw32)` (the canonical `inclusionproof.LeafHash` encoder).
3. Fold the leaf hash through the tree's RFC 6962 structure and confirm the result equals the attestation's `tree:products` subject digest (the Merkle root).

This is the sole trust path. Inline leaves are always present in v0.3 attestations. See [verify a specific file](../guides/verify-a-specific-file) for the full check sequence.

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

The signed `attestation.json` carries the Merkle root and all inline leaves in the predicate.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the standalone proof primitive
- [Merkle trees](../concepts/merkle-trees) — the underlying construction
- [Verify a specific file](../guides/verify-a-specific-file) — consumer-side flow
- [Issue #135](https://github.com/aflock-ai/rookery/issues/135) — design rationale
