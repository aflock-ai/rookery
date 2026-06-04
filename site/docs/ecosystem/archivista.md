---
title: Archivista
sidebar_position: 2
---

# CI/lock and Archivista

[Archivista](https://github.com/in-toto/archivista) is the open-source, **self-hosted** evidence store CI/lock integrates with — a searchable system for keeping signed build evidence instead of burying it in CI logs. You run and operate it yourself.

:::tip Don't want to run a datastore?
The [TestifySec platform free tier](./testifysec-platform) is the managed alternative — the same signed evidence plus AI-powered search, with nothing to host. Reach for self-hosted Archivista when you specifically need to own the datastore (strict data residency, fully air-gapped self-operation, deep customization).
:::

## What Archivista provides

Per the [Archivista README](https://github.com/in-toto/archivista):

- **Storage** for signed in-toto attestations (only signed envelopes are accepted; this is a security property, not a configuration).
- **Graph indexing** on subjects: each subject digest in an in-toto Statement becomes an edge, so a query like "every attestation that touches this commit / this artifact digest" is a single graph traversal.
- **GraphQL query API** plus a playground endpoint, and a REST upload/download surface (`POST /v1/upload`, `GET /v1/download/{gitoid}`, `POST /v1/query`).
- **Cross-air-gap export:** download an attestation by its GitOID and replay it into a second Archivista instance, useful for getting evidence out of a restricted network.
- **Native interop:** stores witness-produced envelopes verbatim (CI/lock and witness share the envelope format).
- **Retention** policies independent of CI workflow artifact lifetimes.

## Why centralized storage beats workflow artifacts

Workflow artifacts (GitHub Actions artifacts, GitLab job artifacts) are fine for the first few weeks of adoption. They stop scaling when:

- You need to verify evidence **without** rerunning the original CI workflow.
- Multiple repos / pipelines need to share evidence (cross-team verification).
- Retention windows in your CI exceed the platform's defaults.
- A release-gate workflow needs to fetch evidence about an artifact built **last quarter**.

Archivista solves all four with one server-side store.

## Where to run it

| Option | When to pick it |
|---|---|
| **Self-hosted** | Most teams. Container image, MySQL or Postgres backing store, S3-compatible object store for the envelopes themselves, ships with a Helm chart for Kubernetes deployment. |
| **Hosted by a vendor** (e.g. as part of the [TestifySec platform](./testifysec-platform)) | When you want operational responsibility off your plate and need the broader platform feature set. |

## How CI/lock writes to Archivista

The Archivista sink is a built-in CI/lock output. Once configured, signed attestations are pushed to your Archivista instance at signing time. See [Store attestations in Archivista](../guides/store-attestations-in-archivista) for setup.

## Upstream

- Repo: [github.com/in-toto/archivista](https://github.com/in-toto/archivista)
- Project home: [in-toto](https://in-toto.io/), the upstream community for both attestations and Archivista.
