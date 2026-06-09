---
title: Witness
sidebar_position: 3
---

# CI/lock and Witness

[Witness](https://witness.dev) originated at [TestifySec](https://www.testifysec.com) and was donated to the CNCF [in-toto](https://in-toto.io/) ecosystem. It is now maintained by the open community.

CI/lock is described in its own source as "**a witness-compatible CI attestation CLI with all attestors and signers**." It shares Witness's DSSE + in-toto envelope format, but the interop is **asymmetric** — CI/lock consumes Witness evidence, not the other way around for everything (see [How CI/lock relates](#how-cilock-relates)).

## At a glance

| What it does | Witness | CI/lock |
| --- | --- | --- |
| Trust setup (Fulcio, TSA, Archivista, keyless CI) | First-class, wired per endpoint with its own flag. | Adds one `--platform-url` that derives the hosted Archivista, Fulcio, TSA, and OIDC audience; in GitHub Actions it signs keylessly off the runner's ambient OIDC token, no login or stored secret. Every endpoint stays overridable. |
| Capturing what ran | `commandrun` traces the process with ptrace. | Keeps ptrace as a mode and adds an eBPF kprobe backend at the kernel boundary; default `auto` probes eBPF and falls back to ptrace. |
| Integrity over the build's files | `product`/`material` record each file as an in-toto subject with a digest set. | The same per-file digests, plus an RFC 6962 Merkle root over the set and standalone inclusion proofs. |
| Support and backing | A CNCF / in-toto project, maintained by a global open-source community. | Open source as well, with a commercial SLA from TestifySec, a US company, behind it. |

For attestation-format interop, see [Interop direction, precisely](#interop-direction-precisely) below.

## What witness provides

From the witness project itself:

- ✏️ **Attests:** a CLI that integrates into pipelines to create an audit trail using the in-toto specification.
- 🧐 **Verifies:** a policy engine with embedded OPA Rego support.
- Implements in-toto including [ITE-5, ITE-6, and ITE-7](https://github.com/in-toto/ITE).
- Keyless signing with Sigstore (Fulcio) and SPIFFE/SPIRE.
- RFC 3161 timestamp authority support.
- Process tracing and process tampering prevention (experimental).
- Attestation storage with [Archivista](./archivista).
- Integrations with GitLab, GitHub, AWS, and GCP.

## How CI/lock relates

CI/lock is built on the same attestation core that powers witness, both live in the [rookery](./rookery) monorepo and share the `attestation/` library plus the full set of attestor and signer plugins.

What CI/lock adds:

- A **CI-focused binary** that bundles the attestor and signer set most relevant to CI/CD.
- **Verifies Witness evidence directly** via legacy type aliases (`attestation.RegisterLegacyAliases()` is called on startup) — anything `witness` produced verifies under `cilock`.
- **Advanced evidence Witness can't validate.** CI/lock extends the model with the v0.3 Merkle-tree `product`/`material` attestations (a `tree:products` root plus inline leaves), standalone inclusion proofs, and richer syscall tracing. These use predicates and subject structures Witness doesn't implement, so **`witness verify` cannot validate most CI/lock attestations** — the interop runs Witness → CI/lock, not the reverse.
- **FIPS mode on by default** (`//go:debug fips140=on`).

### Interop direction, precisely

| Direction | Works? | Notes |
|---|---|---|
| Witness-produced → verified by CI/lock | ✅ | Legacy type aliases registered on startup. |
| CI/lock (shared base attestors) → verified by Witness | ✅ | Same DSSE + in-toto envelope, predicates Witness knows. |
| CI/lock (Merkle `product`/`material` v0.3, inclusion proofs, trace) → verified by Witness | ❌ | Witness doesn't implement these predicates or the Merkle/inclusion-proof verification, so it can't resolve the evidence. |

## Migration notes

If you're coming from witness:

- The CLI surface (`run`, `sign`, `verify`) maps directly.
- Attestation envelopes you produced with witness will verify under CI/lock without modification.
- Policies signed under witness, the DSSE payload type is `https://witness.testifysec.com/policy/v0.1`, work with CI/lock.
- The full attestor set is the same; CI/lock's binary registers a CI-focused subset by default. If you depended on an attestor not in CI/lock's default list (e.g. `inspec`, `kube-bench`, `nessus`, `oscap`, `prowler`, `vsa`), build a custom binary using the [rookery builder](./rookery).

## Upstream

- Project home: [witness.dev](https://witness.dev)
- Repo: [github.com/in-toto/witness](https://github.com/in-toto/witness)
- License: Apache 2.0
