---
title: material
description: The cilock material attestor snapshots the working directory before a step runs and emits a single RFC 6962 Merkle-root in-toto subject (tree:materials) over every input file's digest.
sidebar_position: 2
---

Snapshots the working directory **before** the step's command runs, computes a Merkle root over every input file's digest, and emits a single in-toto subject (`tree:materials`) whose digest is the root. The full per-file digest map is **not** carried in the predicate — it lives in a producer-side sidecar (`<outfile>.material.tree.json`) and is exposed to consumers via separate [inclusion-proof attestations](./inclusion-proof) on demand.

## What it captures

The v0.3 material predicate is small and fixed-size. The schema:

| JSON field | Type | Source |
|---|---|---|
| `merkleRoot` | string (hex) | The Merkle root over the sorted material list, computed via [RFC 6962 §2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1). |
| `treeSize` | integer | Number of files that contributed to the root. |
| `hashAlgorithm` | string | Always `sha256` for v0.3. |
| `construction` | string | Always `RFC6962` for v0.3. |

The DSSE statement's subject array carries one entry:

```json
"subject": [
  {
    "name": "tree:materials",
    "digest": { "sha256": "<merkleRoot>" }
  }
]
```

That is the entire surface area of the predicate. The full per-file list lives in the `<outfile>.material.tree.json` sidecar `cilock run` writes adjacent to the signed envelope.

## Why v0.3 looks like this

v0.1 emitted a flat `map[path]DigestSet` directly as the predicate body, with one `file:<path>` subject per material. For source trees the cardinality was fine — a Go module produces a few dozen materials. For container builds (`COPY . /app` over a JS project's `node_modules`) the per-file subject count blew through Archivista's placeholder budget and inflated the signed envelope to multi-megabyte territory.

v0.3 publishes a single subject (the Merkle root) and moves per-file claims into separate inclusion-proof attestations.

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

If the working directory has no regular files with a sha256 digest, `Subjects()` returns an empty map. (Unlike product, the material attestor does **not** emit an empty-tree root: an empty material set is treated as absent, since "the workingdir was empty before this step" is a less interesting claim than "the step produced nothing.")

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
    "construction":  "RFC6962"
  }
}
```

The predicate is fixed-size regardless of how many files were in the working directory.

## Inline leaves

Since v0.3 is the sole producer, the signed envelope always carries the full `leaves` array — every `(path, fileDigest, leafHash)` triple — inline. The material attestation is self-contained: a verifier can confirm any specific input file's inclusion from the attestation alone.

## Per-file verification

The material attestation's inline `leaves` array exposes every `(path, fileDigest, leafHash)` triple, so per-file input claims are verified directly from the attestation:

1. Find the leaf whose `fileDigest` equals the file digest being verified.
2. Confirm the leaf's `leafHash` equals `sha256(leafPath-bytes || 0x00 || fileDigest-bytes-raw32)` (the canonical `inclusionproof.LeafHash` encoder).
3. Fold the leaf hash through the tree's RFC 6962 structure and confirm the result equals the `tree:materials` subject digest.

Inline leaves are always present in v0.3 attestations. See [verify a specific file](../guides/verify-a-specific-file) for the full check sequence.

## Gotchas

- **The leaf set excludes dirhash and gitoid entries.** `--dirhash-glob` directories still appear in the in-memory `Materials()` map (so downstream attestors that walk `ctx.Materials()` continue to see them), but they do not contribute to the Merkle root because the dirhash isn't a raw file sha256.
- **Symlinks pointing outside `--workingdir` are silently dropped, not errored.** If you depend on a linked tree being recorded, place it inside the working directory.
- **`material` runs before the command.** Files created by the step appear only in `product`, never here.
- **Empty material set → no subject.** Verifiers must handle the no-`tree:materials` case (typically: a step that adds no inputs is allowed; the policy gate is elsewhere).

## CLI example

Builtin. cilock always runs this — hashes files present in workingdir BEFORE the wrapped command runs.

```bash
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir src/ \
  -- make build
```

The signed `attestation.json` carries the Merkle root and all inline leaves in the predicate.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the standalone proof primitive
- [Product attestor](./product) — companion attestor for outputs
- [Merkle trees](../concepts/merkle-trees) — the underlying construction
- [Verify a specific file](../guides/verify-a-specific-file) — consumer-side flow
