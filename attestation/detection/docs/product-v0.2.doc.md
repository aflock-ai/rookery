---
title: product (v0.2)
description: The legacy v0.2 product wire format — same per-file map as v0.1 but a single tree:products subject via a hand-rolled hash chain. Verify-only today; current builds emit product v0.3.
---

> **Status:** this documents the **historical** v0.2 wire format, not emitted by any current cilock build — new attestations use the latest version (select it from the version dropdown above). The v0.2 decoder remains registered so `cilock verify` can read pre-cutover attestations.

Snapshots the working directory after the step's command runs, records each new or changed file with its hash and detected MIME type, and emits a single `tree:products` subject over the included product set.

## v0.2 wire format

v0.2 retained the same per-file predicate body as v0.1 — a flat `map[string]Product` (per-file `mime_type` + `digest`) — but collapsed the in-toto `Statement.Subject` array into a single `tree:products` subject whose digest was a hand-rolled hash chain over `(name || 0x00 || file-digest || 0x00)` per file. v0.2 fixed the placeholder explosion but produced a tree the verifier could not prove individual file inclusion against without re-walking the build — which is why v0.3 supersedes it.

Because the predicate body is identical between v0.1 and v0.2, both versions share a single `LegacyDecoder` (the constructor is parameterized by predicate URI). The decoder is registered against the v0.2 predicate URI `https://aflock.ai/attestations/product/v0.2` under the name `product-v0.2`, and emits `file:<path>` subjects from the decoded map so the policy engine's subject-graph BFS can match historical v0.2 attestations by per-file digest. `Attest()` returns `errLegacyDecodeOnly` — the decoder cannot produce. To emit a new product attestation, use the latest version.

## Why the cutover

v0.2 still carried the full per-file digest map inside the signed predicate (10+ MB envelopes for large installs) and, despite the single subject, gave the verifier no way to prove a specific file was in the tree without re-walking the build.

The latest version publishes a single `tree:products` subject (the RFC 6962 Merkle root) and moves the per-file claims into separate [inclusion-proof attestations](./inclusion-proof) emitted on demand by `cilock prove`. See [rookery#135](https://github.com/aflock-ai/rookery/issues/135) for the full rationale.

## See also

- [Inclusion-proof attestor](./inclusion-proof) — the per-file claim primitive
- Upstream: [witness/product.md](https://github.com/in-toto/witness/blob/main/docs/attestors/product.md)
