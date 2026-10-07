---
title: TestifySec Platform
sidebar_position: 5
---

# Connect CI/lock to the TestifySec platform

CI/lock captures signed execution evidence. Pushgate uses evidence at the Git push checkpoint. The TestifySec platform manages repository gates, their policies and evidence, and mappings from technical test results to compliance controls.

## Connect your evidence

Follow [Connect to the platform](../getting-started/connect-to-the-platform) for the current setup and authentication steps. See [Signing and verification trust](https://testifysec.com/docs/cilock/trust) for identity and verification boundaries.

A passing test provides scoped evidence. It does not, by itself, establish that an entire compliance control is satisfied. Control mappings depend on the configured requirements, evidence, catalog, and assessment scope.

## Choose your next step

- [Explore the platform](https://testifysec.com/product): multiple gates, shared evidence, and technical controls.
- [Explore Pushgate](https://pushgate.dev/): require evidence before accepting a push through a repository gate.
- [Deployment options](https://testifysec.com/solutions/private-deployment): hosted platform and software appliance evaluation.
- [Platform pricing](https://testifysec.com/pricing): current commercial plans and support options.
- [Documentation hub](https://testifysec.com/docs): technical entry points across the three products.

Platform features, commercial entitlements, and deployment guidance are maintained on TestifySec’s site instead of duplicated here. [Archivista](./archivista) remains the open-source evidence storage project; it is one component of the wider ecosystem.
