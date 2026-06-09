---
title: product (v0.1)
description: The legacy v0.1 product wire format — a flat path→Product map with per-file MIME and digest, one file subject each. Verify-only today; current builds emit product v0.3.
---

> **Status:** this documents the **historical** v0.1 wire format, not emitted by any current cilock build — new attestations use the latest version (select it from the version dropdown above). The v0.1 decoder remains registered so `cilock verify` can read pre-cutover attestations.

Snapshots the working directory after the step's command runs and records each new or changed file with its hash and detected MIME type.

## v0.1 wire format

The v0.1 predicate body is a flat `map[string]Product` keyed by file path relative to the working directory. Each entry carries the json-tagged fields of `attestation.Product`:

- `mime_type` — MIME type from `gabriel-vasile/mimetype` detection on the file contents.
- `digest` — `cryptoutil.DigestSet` of the file (sha256, plus any other algorithms the producing run configured).

Example:

```json
{
  "dist/cilock": {
    "mime_type": "application/x-mach-binary",
    "digest": {
      "sha256": "…",
      "gitoid:sha1": "gitoid:blob:sha1:…"
    }
  },
  "dist/sbom.spdx.json": {
    "mime_type": "application/spdx+json",
    "digest": { "sha256": "…" }
  }
}
```

The DSSE statement's `subject` array carries one `file:<path>` entry per product. The `product-v0.1` `LegacyDecoder` (in `plugins/attestors/product/legacy.go`) reads this shape and exposes `Subjects()` for policy BFS lookup; `BackRefs()` returns empty (per-file BackRefs on historical attestations are an explosion risk in the verify-time graph walk). `Attest()` returns `errLegacyDecodeOnly` — the decoder cannot produce.

## Why the cutover

v0.1's per-file subject array caused two real problems Archivista had to work around:

- **Placeholder explosion.** A `pip install litellm` produces ~3,200 files, each emitting its own `file:<path>` subject. Multi-file builds blew through MySQL's 65,535 prepared-statement parameter cap.
- **10+ MB DSSE envelopes.** Every file's path and digest landed in the signed predicate body.

The latest version publishes a single `tree:products` subject (the RFC 6962 Merkle root) and inlines the per-file `leaves` in the signed predicate, so every file is verifiable from the product attestation alone. See [rookery#135](https://github.com/aflock-ai/rookery/issues/135) for the full rationale.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the per-file claim primitive
- Upstream: [witness/product.md](https://github.com/in-toto/witness/blob/main/docs/attestors/product.md)
