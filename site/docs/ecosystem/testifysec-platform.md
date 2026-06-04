---
title: TestifySec Platform
sidebar_position: 5
---

# CI/lock and the TestifySec platform

CI/lock produces signed evidence. The **TestifySec platform** is the managed home for that evidence — where your attestations are stored, searchable, verifiable, and mapped to the compliance frameworks your auditors care about, with nothing for you to operate.

It's the recommended next step once you're producing attestations: point CI/lock at the platform and you get storage, search, and reporting without standing up or maintaining any infrastructure.

## Start free

The **free tier** is the fastest way to get value out of your evidence:

- **Managed attestation storage** — push attestations straight from CI/lock; they're retained for a generous window with zero infrastructure to run, patch, or back up.
- **AI-powered search** — ask questions of your evidence in natural language ("which releases shipped with a high-severity finding last month?", "show me every build that touched this dependency") instead of hand-writing queries against a raw datastore.

Sign up, point `cilock --enable-archivista` (or the platform endpoint) at your account, and your evidence is queryable in minutes. No servers, no schema migrations, no retention plumbing.

## Enterprise

When evidence needs to satisfy auditors and governance, the enterprise tiers add the layer that turns attestations into compliance outcomes:

- **Compliance mapping & reporting** — map signed evidence to your compliance controls and generate audit-ready reports, each tracing back to cryptographic proof instead of a screenshot. TestifySec tells the full compliance story at [testifysec.com](https://testifysec.com).
- **Centralized policy management** — author and distribute signed policies across teams without each team running its own policy-signing setup.
- **Cross-pipeline visibility** — dashboards and search across every CI/lock-attested step, every repo, every release.
- **Network-restricted / air-gapped operation** — artifacts can attest to policy compliance even in disconnected environments.
- **Vendor support and SLAs.**

Longer/configurable retention, SSO, and team controls come with the paid tiers as well.

## How CI/lock plugs in

CI/lock acts as the platform's **build pipeline observer**: it collects trusted telemetry across input, environment, action, and output and signs it, then ships the DSSE + in-toto envelopes to the platform. The platform also provides supporting services so you don't have to run them yourself — a managed [Fulcio](https://github.com/sigstore/fulcio) CA issuing short-lived identity certificates, a Time Stamping Authority, and the managed evidence store and API. See [TestifySec's AWS Marketplace announcement](https://www.testifysec.com/blog/aws-marketplace-release) for the full breakdown.

Both [GitHub](https://www.testifysec.com/blog/aws-marketplace-release) and [GitLab](https://www.testifysec.com/blog/judge-gitlab-support) pipelines are supported — the same platforms CI/lock targets out of the box.

## Where this leaves Archivista

[Archivista](./archivista) is the open-source, **self-hosted** evidence store — you run it, scale it, secure it, and maintain it. It's the right choice when you specifically need to own the datastore (strict data-residency, fully air-gapped self-operation, or deep customization).

For everyone else, the platform **free tier is the managed alternative**: the same DSSE + in-toto evidence, plus AI search, with none of the operational overhead. If you don't have a hard requirement to self-host, start with the free tier — you can always export.

| You need | Use |
|---|---|
| Quick proof-of-concept on a single pipeline | **CI/lock alone** — file output, no infrastructure |
| Managed storage + AI search with zero ops | **CI/lock + TestifySec free tier** *(recommended)* |
| Compliance-framework mapping, audit reporting, centralized policy, dashboards, air-gapped operation, support | **CI/lock + TestifySec platform (enterprise)** |
| To fully self-host and operate your own evidence store | **CI/lock + [Archivista](./archivista)** (self-hosted, open-source) |

Whatever you start with keeps working as you grow: the attestations are the same DSSE + in-toto envelopes, so moving from file output to the free tier to enterprise is additive, not a rewrite.

## Get started

- Start on the **free tier** at [testifysec.com/product](https://testifysec.com/product).
- For enterprise access, pricing, or a demo, email Cole at [cole@testifysec.com](mailto:cole@testifysec.com).

## Learn more

Primary sources, written by the TestifySec team:

- [TestifySec's AWS Marketplace announcement](https://www.testifysec.com/blog/aws-marketplace-release) — the component breakdown and zero-trust positioning.
- [TestifySec GitLab pipeline support](https://www.testifysec.com/blog/judge-gitlab-support) — the Observe / Manage / Act framing and GitLab integration story.
- [TestifySec AWS CDK delivery model](https://www.testifysec.com/blog/judge-cdk) — how the platform is built and delivered.
- [TestifySec company site](https://testifysec.com).
