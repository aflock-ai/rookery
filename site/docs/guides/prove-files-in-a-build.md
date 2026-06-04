---
title: Prove files in a build
sidebar_position: 7
---

# Prove files in a build

`cilock run` emits a product attestation whose subject is a Merkle root over every file the step produced. By default that attestation also carries the per-file [inline leaves](../attestors/product), so a downstream consumer can verify *one specific file* against the signed root with nothing else — `cilock verify <artifact> -p policy` just works. **Most builds never need `cilock prove`.**

You reach for `cilock prove` (and the standalone inclusion-proof attestations it emits) in two cases:

- **Selective disclosure** — hand someone a proof for a single release binary *without* shipping the whole leaf set.
- **Suppressed inline leaves** — when a build sets `WithSuppressInlineLeaves` (e.g. an `npm install`-scale tree with ~30k entries) to keep the envelope small, then proves only the handful of files consumers actually verify.

This guide covers that producer-side workflow: what to prove, when, and how `cilock prove` ties into the build's attestations.

## When selective disclosure helps

When inline leaves are suppressed (or you want a standalone per-file proof), prove only what matters:

- **Prove these.** Release binaries. Container images. SBOMs. Public-API entry points. Anything a downstream consumer might point a verifier at.
- **Don't bother.** Intermediate build artifacts. `node_modules` contents. Object files. Anything that lives only inside the build.

In that mode, a consumer verifying a file with no inclusion-proof attestation (and no inline leaf) gets `no collections found for subject <digest>` — the producer chose not to disclose it. With inline leaves left on (the default), every product file is already verifiable and this question doesn't arise.

## What `cilock run` produces

After `cilock run --outfile attestation.json` completes a step that involves the product or material attestor (the default for any `cilock` run), the working directory contains:

- `attestation.json` — the signed DSSE envelope carrying the product v0.3 statement, the material v0.3 statement, the command-run statement, and any other attestors enabled for the step.
- `attestation.product.tree.json` — the product tree sidecar (the sorted `(path, fileDigest)` leaves and the Merkle root).
- `attestation.material.tree.json` — the material tree sidecar, same shape with `source: "material"`.

The sidecars are **not signed**. They are generation aids for the producer, not evidence in their own right. They share the canonical `rookery.inclusion-proof.sidecar/v0.1` schema and are consumed by `cilock prove`. The producer can keep them around for later prove invocations, or discard them once the inclusion-proof attestations they care about have been emitted.

If `--outfile` is empty (stdout output), no sidecars are written. Sidecar paths are derived from the outfile.

## Running `cilock prove`

The producer-side flow looks like this:

```bash
cilock prove \
  --tree-sidecar attestation.product.tree.json \
  --file dist/binary \
  --signer-file-key-path key.pem \
  --outfile dist-binary.inclusion-proof.json
```

What this does:

1. Read the sidecar tree from `--tree-sidecar`.
2. Look up `--file` by its path in the sidecar's leaf list (paths are matched in their normalised forward-slash form).
3. Reconstruct the Merkle tree from the sidecar leaves and verify the recomputed root matches the sidecar's claimed root — refusing if it does not (`ErrSidecarRootMismatch`).
4. Generate the audit path for the leaf per RFC 6962 §2.1.1.
5. Wrap the result in an in-toto Statement whose predicate type is `https://aflock.ai/attestations/inclusion-proof/v0.1` and whose single subject is `file:<leafPath>` with the file digest.
6. Sign the Statement with the same signer flags `cilock run` accepts (file key, Fulcio OIDC, KMS, etc.).
7. Write the signed DSSE envelope to `--outfile`.

The output is a standalone attestation. It can be archived alongside the build's other evidence, uploaded to Archivista, or attached to a release artifact.

`--file` may be repeated to emit multiple proofs in one invocation; with multiple files each envelope lands at `<outfile>-<sanitised-path>.json`.

## When to call `cilock prove`

A few patterns:

**At release time, for everything in `dist/`.** Most common. After the build's `cilock run` step, the release pipeline iterates over the files in the release directory and runs `cilock prove` once per file:

```bash
cilock prove \
  --tree-sidecar attestation.product.tree.json \
  $(for f in dist/*; do printf -- '--file %q ' "$f"; done) \
  --signer-file-key-path "$KEY_PATH" \
  --outfile dist.inclusion-proof.json
```

Each emitted envelope lands at `dist.inclusion-proof-<sanitised-path>.json`.

This emits one inclusion-proof attestation per release artifact. The release bundle then carries the product attestation + one inclusion-proof attestation per artifact + whatever other build evidence the pipeline emits.

**On demand, for files a specific consumer asks about.** If a consumer requests provenance for a file that was not part of the standard release set, the producer can run `cilock prove` against the stashed tree at any time after the build — the tree sidecar is the only persistent state needed. There is no requirement to know in advance every file a consumer might verify.

**Not at all, in the default (inline-leaves) case.** If the build left inline leaves on — the default — every product file is already verifiable from the product attestation, so `cilock prove` is unnecessary unless you specifically want a *standalone, separately-shippable* proof for one file.

## What gets verified downstream

The inclusion-proof attestation's predicate looks like this:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "file:dist/binary",
      "digest": { "sha256": "<file-digest>" }
    }
  ],
  "predicateType": "https://aflock.ai/attestations/inclusion-proof/v0.1",
  "predicate": {
    "treeRoot":      "<hex-merkle-root>",
    "leafIndex":     1247,
    "leafPath":      "dist/binary",
    "fileDigest":    "<hex-file-digest>",
    "auditPath":     ["<hex-sibling-0>", "<hex-sibling-1>", "..."],
    "hashAlgorithm": "sha256",
    "construction":  "RFC6962"
  }
}
```

The predicate carries the leaf identity (`leafPath` + `fileDigest`) rather than a pre-computed leaf hash: the verifier recomputes the leaf hash from those two fields using the canonical `inclusionproof.LeafHash` encoder, then folds it through the audit path. Carrying the path and digest directly means the verifier can refuse a proof that names the wrong file even if the audit path happens to verify against the claimed root — see [CVE-2026-22703](https://nvd.nist.gov/vuln/detail/CVE-2026-22703).

A consumer running `cilock verify --subjects sha256:<file-digest>` finds this attestation by subject-digest match, recomputes the root from the audit path, and cross-checks the recomputed root against the product attestation's `tree:products` subject digest. See [verify a specific file](./verify-a-specific-file) for the full verifier flow.

## Operational notes

A few details that bite if you get them wrong:

- **Hash algorithm.** The tree sidecar records which algorithm was used to build the tree (always `sha256` for v0.3). `cilock prove` refuses to operate on a sidecar that pins anything else.
- **File path vs. file content.** The Merkle root is computed from `(path, digest)` pairs framed with `\0` bytes — both the path and the content matter. `cilock prove --file` looks up by path in the sidecar. Two files with identical content at different paths produce different leaves and require different inclusion-proof attestations.
- **Sidecar lifecycle.** The `<outfile>.product.tree.json` / `<outfile>.material.tree.json` sidecars are not signed and not evidence. Treat them as build caches: regenerate by re-running the build, or delete once the inclusion proofs you need have been emitted. Don't ship them to downstream consumers; they only need the signed inclusion-proof attestations.
- **Root integrity check at prove time.** `cilock prove` reconstructs the Merkle tree from the sidecar leaves and refuses to emit a proof if the recomputed root does not match the sidecar's claimed root (`ErrSidecarRootMismatch`). A tampered sidecar fails closed instead of silently producing a proof that would never verify.
- **Key reuse.** The signer flags for `cilock prove` are the same as for `cilock run`. Most pipelines reuse the same signing identity — typically a Fulcio OIDC cert keyed off the CI job's identity. Splitting `prove`-time signing from `run`-time signing is possible but adds key-management complexity for no obvious gain.

## See also

- [Verify a specific file](./verify-a-specific-file) — the consumer counterpart
- [Inclusion-proof attestor](../attestors/inclusion-proof) — the predicate schema
- [Product attestor v0.3](../attestors/product) — what `cilock run` emits
- [Issue #135 on rookery](https://github.com/aflock-ai/rookery/issues/135) — the full design rationale and decisions
