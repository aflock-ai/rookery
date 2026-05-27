---
title: product
description: The cilock product attestor snapshots the working directory after a step runs and emits a single RFC 6962 Merkle-root in-toto subject (tree:products) over every output file's digest.
sidebar_position: 4
---

Snapshots the working directory after the step's command runs, computes a Merkle root over every product file's digest, and emits a single in-toto subject (`tree:products`) whose digest is the root. The subject stays a single fixed-size root, but **by default the predicate also carries the per-file Merkle `leaves` inline** — each `(path, fileDigest, leafHash)` — so a verifier can resolve any product file's digest to the signed tree root with no separate inclusion-proof envelope (`cilock verify <artifact> -p policy` just works). Opt out with the producer-side `WithSuppressInlineLeaves` option when envelope size matters; per-file claims then come from the sidecar + [inclusion-proof attestations](./inclusion-proof) on demand.

## What it captures

The v0.3 subject is a single fixed-size root; the predicate carries that root plus, by default, the inline leaves. The schema:

| JSON field | Type | Source |
|---|---|---|
| `merkleRoot` | string (`<algo>:<hex>`) | The Merkle root over the sorted product list, computed via [RFC 6962 §2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1). Hex-encoded for byte hashes; gitoid URI form for gitoid hashes. |
| `treeSize` | integer | Number of files that contributed to the root (after include/exclude glob filtering). |
| `hashAlgorithm` | string | Name of the hash algorithm. Default `sha256`. Matches the algorithm cilock used to build the tree. |
| `construction` | string | Always `RFC6962` for v0.3. Future hash constructions would extend this field. |
| `leaves` | array of `{path, fileDigest, leafHash}` | **Present by default.** The sorted per-file leaf set — exactly what a verifier needs to resolve a file digest to this signed root without a separate inclusion-proof envelope. Omitted when the producer sets `WithSuppressInlineLeaves` (the root subject is still emitted). |

The DSSE statement's subject array carries one entry:

```json
"subject": [
  {
    "name": "tree:products",
    "digest": { "sha256": "<merkleRoot>" }
  }
]
```

The subject array stays one fixed-size entry no matter how many files the tree has. The per-file list lives in two places: the `leaves` field **inline in the predicate by default** (so verifiers resolve a file digest to this signed root with nothing else), and the unsigned `<outfile>.product.tree.json` sidecar `cilock run` writes next to the envelope (and a parallel `<outfile>.material.tree.json`) for `cilock prove`. When the producer suppresses inline leaves, only the sidecar carries the list.

## Why v0.3 looks like this

v0.2 carried the full per-file digest map (`map[path]Product`) inside the predicate. For source-only projects that was fine — a `go build` produces a handful of files. For package installations (`pip install litellm`, `npm install next`, `cargo build`) the map ballooned to tens of thousands of entries, which:

- Inflated DSSE envelope size to multi-megabyte territory.
- Required Archivista to materialize a separate per-file index server-side to answer the question "which build contains file digest X" without re-decoding every predicate.
- Forced consumers to download and parse the full predicate even when they only cared about one file.

v0.3 fixes all three by making the **subject** a single fixed-size root instead of a `map[path]Product`. Per-file claims are served by the inline `leaves` (default) — or, when leaves are suppressed for very large trees, by separate inclusion-proof attestations. Either way the signed *subject* stays one digest, so Archivista still indexes builds by a single root and the envelope's subject array never balloons. Inlining the leaves by default is what makes `cilock verify <artifact> -p policy` resolve a file with no extra envelope; suppression trades that convenience back for the smallest possible envelope. See [issue #135](https://github.com/aflock-ai/rookery/issues/135) for the original rationale.

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
    "construction":  "RFC6962",
    "leaves": [
      { "path": "dist/app", "fileDigest": "e258...b317", "leafHash": "1227...be1f" }
      // ... one entry per product file, sorted by path
    ]
  }
}
```

The **subject** is fixed-size regardless of file count — a 30,000-file build has the same one-entry subject array as a 3-file build. The inline `leaves` list does scale with the tree; suppress it with `WithSuppressInlineLeaves` when envelope size matters and serve per-file claims from inclusion-proof attestations instead.

## Sidecar tree

`cilock run` writes two sidecar files adjacent to the signed envelope whenever the product and material attestors build trees:

- `<outfile>.product.tree.json` — the product tree
- `<outfile>.material.tree.json` — the material tree

Both share the same on-disk schema: `rookery.inclusion-proof.sidecar/v0.1`, defined in `plugins/attestors/inclusion-proof`. The body carries `source` (either `"product"` or `"material"`), the Merkle root, the tree size, the pinned hash algorithm and construction constants, and the sorted list of `(path, fileDigest)` pairs — exactly the inputs needed for `cilock prove` to reconstruct the tree and emit inclusion proofs.

The sidecar is **not signed**. It is not evidence. Treat it as a build cache: regenerate by re-running the build, or discard once the inclusion proofs you need have been emitted. Do not ship it to downstream consumers — they only need the signed inclusion-proof attestations.

Path convention: for `--outfile attestation.json` the sidecars are `attestation.product.tree.json` and `attestation.material.tree.json`. If `--outfile` is empty (stdout), no sidecars are written.

See [prove files in a build](../guides/prove-files-in-a-build) for the producer flow.

## Composition with inclusion-proof attestations

By default the product attestation is self-sufficient for per-file claims: its inline `leaves` already bind every product file's digest to the signed root, so `cilock verify <artifact> -p policy` matches the artifact's sha256 against a leaf and verifies it against the product attestation's subject — no second envelope. Inclusion-proof attestations matter in two cases:

- **Suppressed inline leaves** (very large trees): the product attestation carries only the root, and an **inclusion-proof attestation** supplies the per-file claim — "this file's digest is leaf `i` in the tree with root X; here is the audit path."
- **Selective disclosure**: publish a proof for one file without shipping the whole leaf set.

In those cases a verifier with both attestations confirms (a) the audit path reconstructs the claimed root, (b) the claimed root matches the product attestation's subject digest, and (c) the leaf hash matches the file asked about. See [verify a specific file](../guides/verify-a-specific-file) for the full sequence.

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

The signed `attestation.json` and the unsigned `attestation.product.tree.json` / `attestation.material.tree.json` sidecars all land in the working directory after the run completes.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the per-file claim primitive
- [Merkle trees](../concepts/merkle-trees) — the underlying construction
- [Prove files in a build](../guides/prove-files-in-a-build) — producer-side flow
- [Verify a specific file](../guides/verify-a-specific-file) — consumer-side flow
- [Issue #135](https://github.com/aflock-ai/rookery/issues/135) — design rationale
