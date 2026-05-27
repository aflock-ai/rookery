---
title: material (v0.1)
description: The legacy v0.1 material wire format — a flat path→digest map of every input file. Verify-only today; current builds emit material v0.3. Documented for reading pre-cutover attestations.
examples_repo: 03-material
---

> **Status:** this documents the **historical** v0.1 wire format. It is not emitted by any current cilock build — new attestations always use the latest version (select it from the version dropdown above). The v0.1 decoder remains registered so `cilock verify` can read pre-cutover attestations.

Records a digest of every regular file under the working directory **before** the step's command runs, establishing the input baseline for the in-toto attestation.

## What it captures

The attestor walks `--workingdir` and produces a flat map keyed by the path of each file relative to the working directory. The value is a `DigestSet` — a map of `{hash-algorithm} -> {hex digest}` computed per file with the algorithms selected by the global `--hashes` flag (default `sha256`).

Walk semantics, from `attestation/file.RecordArtifacts`:

- Only **regular files** are hashed. Directories, FIFOs, device files, sockets, and other special files are skipped (FIFO skipping is an explicit DoS hardening).
- **Symlinks** are followed only when their resolved target stays within the working directory boundary (resolved via `filepath.EvalSymlinks` on both sides so `/var` ↔ `/private/var` style aliases match). Targets outside the boundary are skipped; broken symlinks are skipped; visited targets are de-duplicated.
- When a directory matches any `--dirhash-glob` pattern, the entire subtree is collapsed into a single Go-module `dirhash` entry (key gets a trailing path separator) and the walk does not descend further into it.
- Hashing is parallelized across `GOMAXPROCS` workers.

## Flags

The `material` attestor itself registers no flags. Its behavior is controlled by the global `run` flags it reads from `AttestationContext`:

| Flag | Effect on `material` |
|---|---|
| `--workingdir` / `-d` | Root of the walk |
| `--hashes` | Hash algorithms applied to every file (repeatable; default `sha256`) |
| `--dirhash-glob` | Glob patterns of directories to collapse into a single `dirhash` digest |

## Output shape

`Attestor.MarshalJSON` emits the materials map directly — there is **no wrapping object**, so the predicate body is a flat map of path → digest set:

```json
{
  "cmd/main.go": {
    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  },
  "go.mod": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "vendor/": {
    "sha256:dirhash": "h1:abc123..."
  }
}
```

The `Schema()` method reflects `map[string]cryptoutil.DigestSet{}` for exactly this reason — a struct wrapper would misrepresent the wire format.

## Gotchas

- Symlinks pointing outside `--workingdir` are silently dropped, not errored. If you depend on a linked tree being recorded, place it inside the working directory.
- `--dirhash-glob` matches **directory** paths only and short-circuits descent (`filepath.SkipDir`); individual files inside a matched directory will not appear as separate entries.
- `material` runs before the command, so files created by the step appear only in `product`, never here.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the per-file claim primitive
- Upstream: [witness/material.md](https://github.com/in-toto/witness/blob/main/docs/attestors/material.md)
