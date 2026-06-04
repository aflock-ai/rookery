---
title: Timestamping
sidebar_position: 5
---

# Timestamping

A **timestamp authority (TSA)** adds trusted time information to a signature.

Without a timestamp, a signature only answers "who signed this?" With a timestamp, it also answers "when was it signed?"

## Why timestamps matter

Most signing identities in CI are **short-lived**. A Fulcio certificate is typically valid for a few minutes; a KMS key may rotate quarterly. Without a timestamp:

- A signature made by a now-expired Fulcio cert looks invalid forever.
- A signature made by a key that was later revoked or compromised cannot be distinguished from a fresh signature made *after* the compromise.

A trusted timestamp bound to the signature solves both:

- Verifiers can check whether the signing certificate was valid **at the time of signing**, not just right now.
- Compromise windows can be reasoned about, signatures from before the compromise stay trustworthy.

## How CI/lock uses TSAs

CI/lock supports [RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) timestamp authorities. Pass one or more TSA URLs via `--timestamp-servers` (alias `-t`). When configured, every signed attestation is timestamped at signing time. The timestamp (type `tsp` in the DSSE signature record) is included in the attestation envelope so it travels with the evidence.

You can use:

- A public Sigstore-operated TSA (default for keyless workflows when the cilock-action defaults are accepted)
- The TestifySec platform TSA (derived from `--platform-url`)
- Your own internal TSA, for environments that can't reach the public one

## Verification with timestamps

When `cilock verify` encounters a timestamped envelope, it:

1. Validates the timestamp against the TSA's trust root.
2. Checks the signing certificate against the timestamped time, not the current time.
3. Reports the signing time alongside the identity in verification output.

This is what makes CI/lock evidence **archive-quality** rather than only useful while certificates are still fresh.

## See also

- [Signing & identity](./signing-and-identity) — the keys and certificates a timestamp anchors in time.
- [Trust model](./trust-model) — where long-term, timestamped evidence fits in CI/lock's threat model.
- [Policy verification](./policy-verification) — how verification checks the signing certificate against the timestamped time, not the current time.
