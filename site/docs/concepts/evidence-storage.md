---
title: Evidence storage
sidebar_position: 12
---

# Evidence storage

A signed attestation is only useful if you can find it again. CI/lock supports several places to put the evidence after signing.

## Storage options

CI/lock has two **built-in** sinks (configured via flags on `cilock run`) and several common layered patterns (where you use external tooling to forward the file-output attestation onward).

| Sink | Built into CI/lock? | How |
|---|---|---|
| **File output** | Yes | `-o, --outfile <path>` writes the signed DSSE envelope. Surface it as a CI workflow artifact for the lowest-friction option. |
| **Archivista** | Yes | `--enable-archivista --archivista-server <url>` pushes the envelope into a searchable evidence store. The default for production setups. |
| **OCI registry (as referrer)** | Layered | After CI/lock writes the file output, attach it to an image with [`cosign attach attestation`](https://docs.sigstore.dev/cosign/verifying/attestation/) or the OCI registry's referrers API. The attestation then rides alongside the image. |
| **Blob storage (S3, GCS, etc.)** | Layered | After CI/lock writes the file output, copy with `aws s3 cp`, `gsutil cp`, or your archive tool of choice. Common for compliance archives and long-term retention. |

A single `cilock` run can use both built-in sinks at once, file output for the CI artifact view *and* Archivista for centralized search. The layered options compose with either.

## Archivista in one paragraph

[Archivista](https://github.com/in-toto/archivista) is a searchable evidence store for signed attestations. Think of it as a queryable database for build provenance, instead of grep-ing CI logs to answer "did the SBOM step actually run for release v1.4.7?", you query Archivista by subject digest or workflow run and get the structured envelope back. It scales well past what workflow-artifact storage can handle, and verifiers (release gates, admission controllers, audit jobs) can fetch from it directly.

For setup, see [Store attestations in Archivista](../guides/store-attestations-in-archivista). For broader ecosystem context, see [ecosystem → Archivista](../ecosystem/archivista).

## Picking a sink

A practical default:

- **Day one:** file output (`-o`), surfaced as a CI workflow artifact. Zero infrastructure required.
- **First production use:** add Archivista (`--enable-archivista`) so other systems can verify without re-running CI.
- **Container-heavy:** layer `cosign attach attestation` (or your registry's referrers API) on top of the file output so the attestation lives wherever the image lives.
- **Regulated:** mirror the file output to a long-term blob store (S3, GCS, etc.) with restricted access for audit retention.
