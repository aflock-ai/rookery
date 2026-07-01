---
id: faq
title: FAQ
sidebar_position: 99
---

# Frequently asked questions

## Do I need to understand cryptography to use CI/lock well?

No. You need to understand **what evidence you care about** and **what release decisions should depend on that evidence**. The cryptography exists to make the evidence trustworthy, CI/lock handles the signing primitives so you don't have to.

If you can describe your release rules in plain English ("must come from main, must include an SBOM, must be signed by our CI"), CI/lock's policy + embedded OPA Rego model can encode them.

## Is this only for regulated or highly secure environments?

No. CI/lock is also useful for ordinary platform engineering, incident response, and release governance:

- "What exactly produced this binary?" is a question every team has at some point.
- Compliance just makes the value easier to *justify* on a budget line, but the operational benefits exist regardless.

## Can CI/lock work with existing CI pipelines?

Yes. The normal operating model is to **wrap existing commands and actions**, not to replace your CI platform. CI/lock runs as a step inside GitHub Actions, GitLab CI, Jenkins, or any runner that can execute a binary.

You don't migrate **to** CI/lock, you add it **alongside** what you already run.

## What is the practical payoff?

- Better release confidence: you know what shipped came from where, with what.
- Better provenance: artifacts carry their own evidence instead of depending on log retention.
- Less audit reconstruction: structured evidence beats screenshot collection.
- A cleaner path to automated policy enforcement: rules become code instead of conventions.

## How does CI/lock relate to Witness?

[Witness](https://witness.dev) originated at TestifySec and was donated to the CNCF in-toto ecosystem. CI/lock is a witness-compatible CI attestation CLI: the prebuilt binary ships every attestor and two signers (`file`, `fulcio`); the other seven signers (`debug-signer`, `kms/{aws,gcp,azure}`, `spiffe`, `vault`, `vault-transit`) are opt-in via the builder. CI/lock registers legacy `witness.dev` type aliases on startup, so:

- CI/lock can verify attestations produced by witness.
- Witness can verify attestations produced by CI/lock.

If you're coming from witness, the mental model, attestors, collections, functionaries, signed-DSSE policies, embedded Rego, carries over directly. See [ecosystem → Witness](./ecosystem/witness) for migration notes.

## Where does the TestifySec platform fit?

The TestifySec platform is a larger compliance and evidence product. CI/lock is one of the **evidence-producing clients** that can feed it. You can use CI/lock without the platform, but if you need workflow, dashboards, and reporting on top of attestations, the platform is the path. See [ecosystem → TestifySec Platform](./ecosystem/testifysec-platform).

## Can I use CI/lock without Archivista?

Yes. The simplest setup writes attestations to a file and surfaces them as a CI workflow artifact. [Archivista](./ecosystem/archivista) becomes valuable when you need cross-team search, long-term retention, or verifiers that fetch evidence without rerunning CI.

## Self-hosted vs. hosted Fulcio/TSA: which should I pick?

For most teams: start with the **public Sigstore** Fulcio + TSA. They're free and operationally simple. Move to self-hosted only if you need:

- Air-gapped operation
- Custom CA / identity provider
- Stricter audit logging on the CA itself

See [Choose a signer](./guides/choose-a-signer) for the full decision tree.

## Does CI/lock support FIPS-validated cryptography?

Yes. The `cilock` binary is built with Go's `fips140=on` debug flag, so the FIPS 140 mode is on by default, no separate FIPS build required. See [trust model](./concepts/trust-model#fips-mode).

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Do I need to understand cryptography to use CI/lock well?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. You need to understand what evidence you care about and what release decisions should depend on that evidence. The cryptography exists to make the evidence trustworthy, CI/lock handles the signing primitives so you don't have to. If you can describe your release rules in plain English (\"must come from main, must include an SBOM, must be signed by our CI\"), CI/lock's policy + embedded OPA Rego model can encode them."
      }
    },
    {
      "@type": "Question",
      "name": "Is this only for regulated or highly secure environments?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. CI/lock is also useful for ordinary platform engineering, incident response, and release governance: \"What exactly produced this binary?\" is a question every team has at some point. Compliance just makes the value easier to justify on a budget line, but the operational benefits exist regardless."
      }
    },
    {
      "@type": "Question",
      "name": "Can CI/lock work with existing CI pipelines?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes. The normal operating model is to wrap existing commands and actions, not to replace your CI platform. CI/lock runs as a step inside GitHub Actions, GitLab CI, Jenkins, or any runner that can execute a binary. You don't migrate to CI/lock, you add it alongside what you already run."
      }
    },
    {
      "@type": "Question",
      "name": "What is the practical payoff?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Better release confidence: you know what shipped came from where, with what. Better provenance: artifacts carry their own evidence instead of depending on log retention. Less audit reconstruction: structured evidence beats screenshot collection. A cleaner path to automated policy enforcement: rules become code instead of conventions."
      }
    },
    {
      "@type": "Question",
      "name": "How does CI/lock relate to Witness?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Witness originated at TestifySec and was donated to the CNCF in-toto ecosystem. CI/lock is a witness-compatible CI attestation CLI: the prebuilt binary ships every attestor and two signers (file, fulcio); the other seven signers (debug-signer, kms/{aws,gcp,azure}, spiffe, vault, vault-transit) are opt-in via the builder. CI/lock registers legacy witness.dev type aliases on startup, so: CI/lock can verify attestations produced by witness. Witness can verify attestations produced by CI/lock. If you're coming from witness, the mental model, attestors, collections, functionaries, signed-DSSE policies, embedded Rego, carries over directly."
      }
    },
    {
      "@type": "Question",
      "name": "Where does the TestifySec platform fit?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The TestifySec platform is a larger compliance and evidence product. CI/lock is one of the evidence-producing clients that can feed it. You can use CI/lock without the platform, but if you need workflow, dashboards, and reporting on top of attestations, the platform is the path."
      }
    },
    {
      "@type": "Question",
      "name": "Can I use CI/lock without Archivista?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes. The simplest setup writes attestations to a file and surfaces them as a CI workflow artifact. Archivista becomes valuable when you need cross-team search, long-term retention, or verifiers that fetch evidence without rerunning CI."
      }
    },
    {
      "@type": "Question",
      "name": "Self-hosted vs. hosted Fulcio/TSA: which should I pick?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "For most teams: start with the public Sigstore Fulcio + TSA. They're free and operationally simple. Move to self-hosted only if you need: Air-gapped operation. Custom CA / identity provider. Stricter audit logging on the CA itself."
      }
    },
    {
      "@type": "Question",
      "name": "Does CI/lock support FIPS-validated cryptography?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes. The cilock binary is built with Go's fips140=on debug flag, so the FIPS 140 mode is on by default, no separate FIPS build required."
      }
    }
  ]
})}} />
