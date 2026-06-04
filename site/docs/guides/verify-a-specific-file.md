---
title: Verify a specific file
sidebar_position: 6
---

# Verify a specific file

You have a binary digest (or any single artifact hash) and you want to know: was this file produced by a build I trust? This guide walks the v0.3 verifier flow — what the user runs, what the verifier finds, what cross-checks it does, and what causes pass or fail.

## What you need

To verify a single file you need three things:

1. The artifact's sha256 digest, or the artifact itself on disk.
2. A signed policy that names the trusted functionaries (build identities) and the attestation steps the build is expected to have produced.
3. Access to the build's attestations — either as local files, in a bundle, or via an Archivista evidence store.

**The default case needs nothing extra.** Since v0.3 product/material attestations [inline their Merkle leaves](../attestors/product), the **product attestation alone** already binds your file's digest to the signed `tree:products` root. The verifier matches your digest against a leaf and confirms it against the signed root — no separate inclusion-proof envelope:

- A **product attestation** (`https://aflock.ai/attestations/product/v0.3`) whose subject is `tree:products` and whose predicate carries the inline `leaves`.

**The inclusion-proof path is the exception**, for builds that used **selective disclosure** or **suppressed inline leaves**. There you also need:

- An **inclusion-proof attestation** (`https://aflock.ai/attestations/inclusion-proof/v0.1`) whose subject is the file digest, produced by [`cilock prove`](./prove-files-in-a-build) for that file.

Both paths are covered below.

## The command

Default (inline leaves — the product attestation resolves the file by itself):

```bash
cilock verify \
  --policy policy-signed.json \
  --publickey policy-pubkey.pem \
  --attestations product.attestation.json,build.attestation.json \
  --subjects sha256:<binary-digest>
```

Selective-disclosure / suppressed-leaves variant (add the inclusion-proof envelope):

```bash
cilock verify \
  --policy policy-signed.json --publickey policy-pubkey.pem \
  --attestations product.attestation.json,binary.inclusion-proof.json,build.attestation.json \
  --subjects sha256:<binary-digest>
```

A few notes on this command line:

- `--attestations` (`-a`) is comma-separated, not space-separated. It is a cobra `StringSlice`. Multiple files must be joined with commas, or you must pass `-a` repeatedly.
- `--subjects` (`-s`) takes one or more `<algorithm>:<digest>` strings. The digest is the seed for the BFS. For a binary you have on disk, you can pass `-f path/to/binary` instead and the verifier will hash it for you.
- If you are pulling evidence from Archivista, set `--enable-archivista` and let the seed-digest lookup fetch the relevant attestations for you.

Exit code 0 means verification passed. Any non-zero exit code means it failed; the stderr output names the failing rule.

The full set of flags is available via `cilock verify --help`.

## What the verifier does, step by step

The verifier walks a subject-digest BFS (see [the spine of the graph](../concepts/the-spine-of-the-graph)). For a single-file verification, the walk is:

1. **Seed.** The verifier starts with the file digest the user supplied.

2. **Default path — resolve via the product attestation's inline leaves.** The inclusion-proof bridge maps your seed digest to a product (or material) attestation that lists it as an inline leaf. The verifier verifies that attestation's signature against a trusted functionary, recomputes the leaf hash from the matching `(leafPath, fileDigest)` leaf via the canonical `inclusionproof.LeafHash` encoder, folds it through the inline tree, and confirms it reconstructs the attestation's signed `tree:products` root. The seed must equal a leaf's `fileDigest` (the CVE-2026-22703 cross-check). That's the whole per-file proof — one signed attestation, no extra envelope.

   **Alternative path — explicit inclusion-proof attestation** (selective disclosure / suppressed leaves): if there's no matching inline leaf, the verifier instead (a) finds an inclusion-proof attestation whose subject *is* the seed, (b) verifies its signature, (c) reconstructs the leaf and folds it through the `auditPath` to recompute the claimed `treeRoot`, (d) cross-checks `fileDigest == seed`, then (e) finds and verifies the product attestation whose `tree:products` subject equals that `treeRoot`. Same guarantee, reached through a separate signed proof.

3. **Continue the BFS.** From the product attestation, the BackRefs name the materials' tree root, the command-run, the git commit, and any other build evidence. The verifier walks those to confirm the policy's other steps are satisfied (SBOM present, SARIF clean, etc.).

4. **Policy evaluation.** Rego rules in the policy evaluate the collected predicates. If every step's `regopolicy` rules pass, exit 0. If any rule denies, exit non-zero with the deny message.

## When verification fails

Five common failure modes and what they mean:

| Failure | Cause |
|---|---|
| `no collections found for subject <digest>` | No product/material attestation lists that digest as an inline leaf, and no inclusion-proof attestation has it as a subject. Usual cause: the attestation set you passed is incomplete, or the build suppressed inline leaves and you didn't pass the matching inclusion proof (run `cilock prove` for the file). |
| `inclusion proof: root mismatch` | The audit path does not reconstruct the claimed root. The proof was tampered with, was for a different tree, or was generated against a different RFC 6962 implementation than the verifier expects. |
| `inclusion proof: fileDigest does not match subject digest` | The proof verifies in isolation but the predicate's `fileDigest` does not match the file the user asked the verifier to check. Symptom of [CVE-2026-22703](https://nvd.nist.gov/vuln/detail/CVE-2026-22703) if the verifier had skipped this check. |
| `attestation signature invalid` | DSSE signature did not verify against the policy's trusted functionaries. The signer is wrong, the policy is wrong, or the envelope was modified after signing. |
| `step <name> rego policy: deny` | The Rego policy block on a specific step returned a deny. Check the deny message — usually a missing SBOM, a failing SARIF rule, or a constraint on the git commit. |

The verifier never returns "success but with caveats." Any non-zero exit code is a real failure.

## Recording the verification result

`cilock verify` automatically runs its built-in `policyverify` attestor, which emits a [SLSA Verification Summary Attestation](../attestors/policyverify) (VSA) describing the verify result. Use `--vsa-outfile` to write that VSA to disk on both pass and fail — a failed VSA is still useful evidence that the gate was run.

```bash
cilock verify \
  --policy policy-signed.json --publickey policy-pubkey.pem \
  --attestations product.attestation.json,binary.inclusion-proof.json \
  --subjects sha256:<binary-digest> \
  --vsa-outfile binary-verify.vsa.json \
  --signer-file-key-path verify-key.pem
```

The signer flags are required if you want the VSA itself signed; without them the VSA writes as an unsigned in-toto Statement.

## See also

- [Inclusion proofs](../concepts/inclusion-proofs) — the underlying primitive
- [Prove files in a build](./prove-files-in-a-build) — the producer-side counterpart
- [The spine of the graph](../concepts/the-spine-of-the-graph) — why the BFS finds the right attestations
- [Verify in a release gate](./verify-in-a-release-gate) — wiring this into CI
