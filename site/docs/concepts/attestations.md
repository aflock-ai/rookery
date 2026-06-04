---
title: Attestations
sidebar_position: 1
---

# Attestations

An **attestation** is a signed statement about something that happened in your pipeline.

Example: "this command ran on this commit and produced these files."

Concretely, an attestation is a signed DSSE envelope wrapping a typed in-toto Statement. The Statement carries:

- A **subject:** what the statement is about (a commit, an artifact digest, an image reference)
- A **predicate type:** a URI naming the kind of claim (e.g. `https://aflock.ai/attestations/git/v0.1`, `https://cyclonedx.org/bom`)
- A **predicate:** the typed payload itself (the build provenance record, the SBOM, etc.)

The surrounding DSSE envelope adds:

- A **payload type** and base64-encoded payload (the Statement)
- One or more **signatures** so verifiers can check authenticity

## Logs vs. attestations

| | Logs | Attestations |
|---|---|---|
| **Format** | Free text | Structured (typed predicate) |
| **Trust** | Whatever the CI UI shows you | Cryptographically signed |
| **Portable** | Tied to a CI run UI | Travels with the artifact |
| **Machine-readable** | Sometimes, with parsing | Yes, by spec |
| **Survives the pipeline** | Until log retention expires | As long as you store it |

Logs are useful, but they are not equivalent to portable, signed, structured evidence.

## Why portability matters

A pipeline log lives inside one CI tool's UI. An attestation can be:

- Attached to a container image in an OCI registry
- Pushed into an evidence store like [Archivista](../ecosystem/archivista)
- Bundled with a release artifact
- Forwarded to a downstream verification gate

That portability is what makes attestations the right substrate for policy verification, audit, and cross-system trust.

For envelope and predicate format details, see [DSSE & in-toto](./dsse-and-in-toto).
