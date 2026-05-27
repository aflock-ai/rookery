---
title: material
description: The cilock material attestor snapshots the working directory before a step runs and emits a single RFC 6962 Merkle-root in-toto subject (tree:materials) over every input file's digest.
sidebar_position: 2
---

Snapshots the working directory **before** the step's command runs, computes a Merkle root over every input file's digest, and emits a single in-toto subject (`tree:materials`) whose digest is the root. Like [product](./product), the predicate **carries the per-file Merkle `leaves` inline by default**, so a verifier can confirm a specific input without a separate envelope and `artifactsFrom` chains verify straight from the inline leaves (no chain sidecar). An inline-but-empty leaf set is an authoritative *"this step consumed nothing"* commitment — so isolated-workdir build steps verify flaglessly, while a collection with no inline leaves at all still fails closed. Suppress inline leaves with `WithSuppressInlineLeaves`; per-file claims then come from the sidecar + [inclusion-proof attestations](./inclusion-proof).

## What it captures

The v0.3 material subject is a single fixed-size root; the predicate carries that root plus, by default, the inline leaves. The schema:

| JSON field | Type | Source |
|---|---|---|
| `merkleRoot` | string (hex) | The Merkle root over the sorted material list, computed via [RFC 6962 §2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1). |
| `treeSize` | integer | Number of files that contributed to the root. |
| `hashAlgorithm` | string | Always `sha256` for v0.3. |
| `construction` | string | Always `RFC6962` for v0.3. |
| `leaves` | array of `{path, fileDigest, leafHash}` | **Present by default.** The sorted per-file leaf set; an empty array is the authoritative "consumed nothing" commitment for chain verification. Omitted under `WithSuppressInlineLeaves`. |

The DSSE statement's subject array carries one entry:

```json
"subject": [
  {
    "name": "tree:materials",
    "digest": { "sha256": "<merkleRoot>" }
  }
]
```

The subject array stays one fixed-size entry. The per-file list lives in the `leaves` field **inline by default**, and in the `<outfile>.material.tree.json` sidecar `cilock run` writes adjacent to the envelope for `cilock prove`. When inline leaves are suppressed, only the sidecar carries the list.

## Why v0.3 looks like this

v0.1 emitted a flat `map[path]DigestSet` directly as the predicate body, with one `file:<path>` subject per material. For source trees the cardinality was fine — a Go module produces a few dozen materials. For container builds (`COPY . /app` over a JS project's `node_modules`) the per-file subject count blew through Archivista's placeholder budget and inflated the signed envelope to multi-megabyte territory.

v0.3 publishes a single subject (the Merkle root) so the signed subject array never balloons, and serves per-file claims from the inline `leaves` by default (or from inclusion-proof attestations when leaves are suppressed for very large trees).

## How the material set is captured

This attestor commits a Merkle root over a set of input files — but *which* files, and where their digests come from, is decided by the active **capture mode**, not by the attestor itself:

- **Directory walk** (default, and the only mode without `--trace`): every regular file under `--workingdir` at step start is hashed. A portable before-snapshot of the inputs.
- **Syscall trace** (`--trace`, Linux): cilock observes the process's `openat` calls so materials reflect the inputs actually read — including files outside the working directory. The trace backend is `ptrace+seccomp` (always available) or `eBPF` where the kernel supports it; `CILOCK_TRACE_MODE=auto` probes eBPF and falls back to ptrace.
- **fanotify** (`--hardening standard`/`strict`): supplies the content hash at `FAN_OPEN_PERM` time (each inode hashed once), race-tight against an input that's modified later in the same build.

`--capture-mode auto` (the default) uses trace events when `--trace` is on and the directory walk otherwise. See [how cilock captures files](../concepts/capture-modes) for the full comparison and a selection guide.

## When to use

It always fires. Its output is the canonical "what existed on disk when the step started" record — consumed by policy to verify that a step's inputs match a known prior product (chained materials → products across steps), and used as `subjectOf` evidence for SLSA provenance.

## Flags

The `material` attestor itself registers no flags. Its behavior is controlled by the global `run` flags it reads from `AttestationContext`:

| Flag | Effect on `material` |
|---|---|
| `--workingdir` / `-d` | Root of the walk |
| `--hashes` | Hash algorithms applied to every file (default `sha256`) — v0.3 commits only the sha256 leaf to the tree |
| `--dirhash-glob` | Glob patterns of directories to collapse into a single `dirhash` digest (excluded from the v0.3 leaf set because the dirhash key isn't a raw file content sha256) |

## Subject behavior

`Subjects()` returns exactly one entry, `tree:materials`. The digest is the Merkle root computed via:

```
Walk the working directory per attestation/file.RecordArtifacts (regular files only,
symlinks bounded to the workingdir, dirhash globs honoured).
Filter to entries that have a raw sha256 digest (dirhash/gitoid entries are skipped).
Sort by inclusionproof.NormalizePath(path) (lexically).
For each (path, file-digest) pair:
  leafPreHash = sha256(path-bytes || 0x00 || file-digest-bytes-raw32)
Pass the leafPreHash list into a merkle tree built per RFC 6962 §2.1.
The wrapper applies its own 0x00 leaf-domain prefix and 0x01 interior prefix,
so the actual leaf the tree commits to is:
  H(0x00 || leafPreHash) = H(0x00 || sha256(path || 0x00 || file-digest))
```

The leaf encoder is `inclusionproof.LeafHash` — the same canonical function the product attestor uses. Any drift between the two would mean a file recorded as a product in one step could not be matched against the same file recorded as a material in the next step. There is exactly one implementation; both attestors call it.

If the working directory has no regular files with a sha256 digest, `Subjects()` returns an empty map (unlike product, no empty-tree root subject is emitted). The attestation still carries an **inline, empty `leaves` set**, which chain verification reads as an authoritative "this step consumed nothing" commitment (`HasInlineMaterials`) — an isolated-workdir build step therefore satisfies `artifactsFrom` with no sidecar, while a collection carrying *no* inline leaves at all fails closed in strict-chain mode.

## Output shape

The full DSSE statement for a v0.3 material attestation:

```json
{
  "_type":         "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name":   "tree:materials",
      "digest": { "sha256": "4f1e...aa72" }
    }
  ],
  "predicateType": "https://aflock.ai/attestations/material/v0.3",
  "predicate": {
    "merkleRoot":    "4f1e...aa72",
    "treeSize":      218,
    "hashAlgorithm": "sha256",
    "construction":  "RFC6962",
    "leaves": [
      { "path": "src/main.go", "fileDigest": "...", "leafHash": "..." }
      // ... one entry per material file, sorted by path; empty array = consumed nothing
    ]
  }
}
```

The **subject** is fixed-size regardless of file count; the inline `leaves` list scales with the tree (suppress it with `WithSuppressInlineLeaves` when envelope size matters).

## Sidecar tree

`cilock run` writes `<outfile>.material.tree.json` adjacent to the signed envelope. The schema is `rookery.inclusion-proof.sidecar/v0.1` — the same format as the product sidecar, distinguished by the `source: "material"` field at the top of the document. `cilock prove --sidecar <outfile>.material.tree.json` reconstructs the tree and emits per-file inclusion proofs.

The sidecar is **not signed**. Treat it as a build cache.

## Composition with inclusion-proof attestations

By default the inline `leaves` already let a verifier confirm a specific input was in the tree, and let `artifactsFrom` chain a step's materials to the prior step's products with no chain sidecar. A separate inclusion-proof attestation is only needed when inline leaves are suppressed or for selective disclosure; the combined check is then:

1. The inclusion-proof attestation's `treeRoot` matches the material attestation's `tree:materials` subject digest.
2. The audit path reconstructs the claimed root.
3. The leaf path + digest identify the file the consumer is asking about.

See [verify a specific file](../guides/verify-a-specific-file) for the full check sequence.

## Gotchas

- **The leaf set excludes dirhash and gitoid entries.** `--dirhash-glob` directories still appear in the in-memory `Materials()` map (so downstream attestors that walk `ctx.Materials()` continue to see them), but they do not contribute to the Merkle root because the dirhash isn't a raw file sha256.
- **Symlinks pointing outside `--workingdir` are silently dropped, not errored.** If you depend on a linked tree being recorded, place it inside the working directory.
- **`material` runs before the command.** Files created by the step appear only in `product`, never here.
- **Empty material set → no subject, but an inline empty-leaves commitment.** There's no `tree:materials` subject, yet the attestation carries an inline empty `leaves` set that chain verification treats as an authoritative "consumed nothing" — so a leaf-less collection (no inline leaves at all) is what fails closed, not an isolated-workdir step.

## CLI example

Builtin. cilock always runs this — hashes files present in workingdir BEFORE the wrapped command runs.

```bash
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir src/ \
  -- make build
```

The signed `attestation.json` and the unsigned `attestation.material.tree.json` sidecar both land in the working directory after the run completes.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the per-file claim primitive
- [Product attestor](./product) — companion attestor for outputs
- [Merkle trees](../concepts/merkle-trees) — the underlying construction
- [Prove files in a build](../guides/prove-files-in-a-build) — producer-side flow
- [Verify a specific file](../guides/verify-a-specific-file) — consumer-side flow
