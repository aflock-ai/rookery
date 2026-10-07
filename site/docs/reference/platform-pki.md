---
title: Platform PKI & trust
sidebar_position: 8
---

# Platform PKI & trust

This page explains the public-key infrastructure behind the TestifySec platform —
the certificate authorities `cilock` signs and verifies against, how your client
discovers them, and the one mistake that breaks supply-chain verification in a way
the error messages don't make obvious: **trusting the wrong platform's roots when
the Common Names happen to match.**

If you only need to *connect and run*, start with
[Connect to the platform](../getting-started/connect-to-the-platform). This page is
the reference for *why* that works and *what* you are trusting. For the conceptual
threat model (what CI/lock does and does not protect against), see
[Trust model](../concepts/trust-model); for signer identities, see
[Signing & identity](../concepts/signing-and-identity).

## One root, two CAs

A TestifySec platform derives its entire PKI from a **single root key**. The root
key HKDF-derives (RFC 5869) three things, in memory, at startup:

- a self-signed **Root CA** (the trust anchor),
- a **Fulcio CA** (intermediate) that mints the short-lived **signing** leaves, and
- a **TSA** leaf that signs RFC 3161 **timestamps**.

```mermaid
flowchart TB
    RK["Root key (KMS HMAC in prod / key file otherwise)"]
    RK -->|"HKDF 'root-ca'"| ROOT["Root CA (self-signed)<br/>CN: TestifySec Platform Root CA"]
    RK -->|"HKDF 'fulcio-ca'"| FCA["Fulcio CA (intermediate)<br/>issues short-lived signing leaves"]
    RK -->|"HKDF 'tsa'"| TSA["TSA leaf<br/>issues RFC 3161 timestamps"]
    ROOT -->|"issues"| FCA
    ROOT -->|"issues"| TSA
```

Because derivation is deterministic, every replica of the platform derives the
**same** CA public keys — so a signature minted on one replica verifies on any
other. The hosted platform runs three replicas behind one URL; you never see this,
but it's why keyless signing is reliable under load.

Choose an explicit verification trust posture. CI/lock can use operator-supplied roots, policy trust embedded in a particular release, or platform discovery with the applicable pinning rules. Discovery alone is not independent confirmation that a platform is the authority you intended.

## Discovery: where trust comes from

Every platform publishes one unauthenticated document:

```bash
curl -fsSL "$PLATFORM_URL/.well-known/judge-configuration" | jq .
```

```jsonc
{
  "archivista_url":   "https://platform.testifysec.com/archivista",
  "fulcio_grpc_addr": "[::]:5554",
  "graphql_url":      "https://platform.testifysec.com/query",
  "tsa_url":          "https://platform.testifysec.com/api/v1/timestamp",
  "signing": {
    "assurance_level":    "aal1",
    "fulcio_oidc_issuer": "https://platform.testifysec.com/fulcio/oidc",
    "fulcio_url":         "https://platform.testifysec.com",
    "oidc_audience":      "sigstore",
    "trust_bundle_pem":   "-----BEGIN CERTIFICATE-----…",   // Fulcio CA + Root CA
    "trust_bundle_url":   "https://platform.testifysec.com/api/v1/fulcio/trustbundle",
    "tsa_cert_chain_url": "https://platform.testifysec.com/api/v1/timestamp/certchain"
  }
}
```

The field that matters most is **`signing.trust_bundle_pem`** — it inlines the
Fulcio CA *and* the Root CA, so one fetch tells your client both *where to sign* and
*what to trust*. `tsa_cert_chain_url` serves the TSA leaf + Root CA, used to validate
timestamps (and to validate a keyless signature after its short-lived leaf expires).

`$PLATFORM_URL` is `https://platform.testifysec.com` for the hosted platform, or your
own host for a self-hosted / `--standalone` instance.

## Signing and uploading use separate authority

This is the single most useful distinction to internalize:

| What you're doing | What it proves | Authority |
|---|---|---|
| **Sign** (Fulcio + TSA) | the certificate principal signed these exact bytes at this time | CI workflow OIDC (GitHub Actions, GitLab.com, Buildkite, CircleCI); an enrolled agent's own SPIFFE identity (`cilock enroll agent`); or a person's `cilock login` credential, whose login must have reached AAL2 unless the tenant opted out |
| **Upload** (Archivista) | this evidence belongs to this tenant/subject | A separate purpose-scoped tenant credential |

**Signing is keyless.** On GitHub Actions, with `id-token: write`, the runner mints an
ambient OIDC token; the platform Fulcio exchanges it for a leaf that lives ~10 minutes —
long enough to sign, too short to be worth stealing. The TSA timestamps the
signature so it stays verifiable long after the leaf expires. A workflow OIDC
request is a workload principal. The platform Fulcio also accepts GitLab.com,
Buildkite and CircleCI workload identities, and `cilock run --platform-url` fetches the
job's token on those too. On Kubernetes, sign keyless against public Sigstore, and on
other CI sign with a key. See the
[support matrix](./support-matrix) for the level each environment reaches.

On a workstation, an agent signs as itself: `cilock enroll agent` mints a
time-bound agent principal with its own SPIFFE ID after a person approves it at AAL2
(passkey or second factor), and `cilock run` then signs as that agent, never as the person. A person's
own `cilock login` credential mints a token at the assurance level its login reached.
By default the tenant requires AAL2 (a passkey) for that exchange; a tenant that opts
out still lets the local client exchange a stored API credential non-interactively for an AAL1 token
naming its creator's email. Either way the level belongs to the login, not to each
signature: it does not prove a person was present when a given signature was made,
and agents must not use that path. The platform's explicit, server-observed human/agent ceremony remains a target
for binding a person's signature to the exact bytes signed.

**Uploading binds evidence to your tenant**, so it needs a different credential.
`cilock login` supplies a human tenant session;
`cilock login --workflow-identity` exchanges exact workload identity in CI.
Neither path changes the principal already bound into the signing certificate.

```mermaid
sequenceDiagram
    autonumber
    participant CI as CI job (id-token: write)
    participant GH as GitHub OIDC
    participant FUL as Platform Fulcio
    participant TSA as Platform TSA
    participant ARCH as Archivista

    CI->>GH: request ambient OIDC token
    GH-->>CI: short-lived OIDC JWT
    CI->>FUL: exchange token for signing cert
    FUL-->>CI: ~10-min leaf (chains Fulcio CA → Root CA)
    CI->>CI: sign DSSE envelope with the leaf
    CI->>TSA: RFC 3161 timestamp the signature
    TSA-->>CI: timestamp token
    Note over CI,ARCH: Signing is done — no upload credential needed yet.
    CI->>ARCH: exchange exact workflow identity, then upload (tenant-bound)
    ARCH-->>CI: stored — addressable by subject digest
```

## Verifying

With an appropriate platform session and trust configuration, `cilock verify` can derive policy-signer trust from discovery. Pinnable sessions retain the adopted trust pin; changed roots are refused until a verified rotation is explicitly accepted. A session that cannot retain a pin requires an explicit trust decision or supplied roots. Review the installed release and its configured trust posture before relying on defaults:

```bash
cilock verify ./myapp -p policy.json --platform-url "$PLATFORM_URL" --enable-archivista
```

Offline (no session, air-gapped), you supply trust yourself:

```bash
cilock verify ./myapp -p policy.json \
  --policy-ca-roots roots.pem \
  -a attestation-1.json -a attestation-2.json
```

Under the hood, verify chains each signing leaf to the Fulcio CA and then to the
Root CA, and validates the RFC 3161 timestamp against the TSA chain — which is what
lets a years-old signature still verify after its leaf has long expired.

```mermaid
sequenceDiagram
    autonumber
    participant V as cilock verify
    participant DISC as discovery doc
    participant ARCH as Archivista
    participant POL as Policy

    V->>DISC: GET trust_bundle_pem + tsa_cert_chain_url
    DISC-->>V: Fulcio CA + Root CA, TSA chain
    V->>ARCH: fetch attestations by artifact digest
    ARCH-->>V: signed DSSE envelopes + timestamps
    V->>V: chain leaf → Fulcio CA → Root CA
    V->>V: validate RFC 3161 timestamp (verifies leaf as of signing time)
    V->>POL: evaluate steps, functionaries, Rego
    POL-->>V: pass / fail
```

## :warning: Same CN, different key = wrong platform

This is the failure that looks like a bug in `cilock` but is actually a trust
**misconfiguration**, and it is easy to hit because every TestifySec platform
derives its certificates from the same code — so they all share the **same Common
Names**:

- Root CA CN: `TestifySec Platform Root CA`
- Fulcio CA CN: `TestifySec Platform Fulcio CA`
- TSA CN: `TestifySec Platform TSA`

Production and staging are **different platforms with identical CNs but different
keys.** A Common Name tells you a certificate's *role*; it tells you **nothing**
about *which platform* issued it. Only the **key** does.

**Symptom.** Verification fails with `verifiers=0` on every collection, and any
timestamp check fails with `x509: ECDSA verification failure` — against a Root CA
whose name matches what you expected.

**Cause.** Something on the verify side trusts platform A while the evidence was
signed by platform B. The classic case: a release policy that embeds **staging**
roots while the binaries were **production**-signed. A prod leaf cannot chain to a
staging Root CA, no matter how identical the names are.

**How to confirm it.** Compare the Root CA *key* fingerprint from each side. They
must match.

```bash
# Root CA public-key fingerprint (SPKI) from a platform's discovery
curl -fsSL "$PLATFORM_URL/.well-known/judge-configuration" \
  | jq -r '.signing.trust_bundle_pem' \
  | awk 'BEGIN{n=0} /BEGIN CERT/{n++} {if(n==2) print}' \
  | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 | cut -c1-8
```

If the fingerprint from the platform you signed against differs from the Root CA
embedded in your policy (or passed via `--policy-ca-roots`), you are trusting the
wrong platform. Re-fetch trust from the **same** `$PLATFORM_URL` you signed against,
and re-sign any signed policy against that platform.

> **Rule of thumb:** when two roots have the same CN, compare their **keys** (SPKI),
> never their names. Same name + different key = different platform = verification
> fails closed.

## See also

- [Connect to the platform](../getting-started/connect-to-the-platform) — `cilock login`, `cilock use`, `cilock doctor`, `cilock trust`.
- [Trust model](../concepts/trust-model) — what CI/lock protects against (and what it doesn't).
- [Signing & identity](../concepts/signing-and-identity) — signer providers and how functionaries are matched.
- [Timestamping](../concepts/timestamping) — verifying expired-certificate signatures.
- [Policy schema](./policy-schema) — `roots`, `timestampauthorities`, functionaries, Rego.
- [CLI reference](./cli) — `cilock login`, `cilock verify`, `cilock sign` flags.
