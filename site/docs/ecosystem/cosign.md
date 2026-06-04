---
title: Cosign
sidebar_position: 4
---

# CI/lock and cosign

[Cosign](https://github.com/sigstore/cosign) is the [Sigstore](https://www.sigstore.dev) project's CLI for signing container images, blobs, and SLSA / in-toto attestations. CI/lock and cosign **share the wire format** — both produce and consume DSSE-wrapped in-toto Statements — and they sit at **different abstraction levels** in a supply chain. They are complementary, not competitive.

The user story below is validated end-to-end against cosign v3.0.2 in the [`interop-cosign-dsse` example](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/interop-cosign-dsse).

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "Verify a cosign-signed DSSE attestation with a cilock policy",
  "description": "End-to-end recipe for using a cosign-signed in-toto DSSE attestation as required external evidence in a cilock policy via Policy.externalAttestations.",
  "tool": [
    { "@type": "HowToTool", "name": "cilock", "url": "https://cilock.dev" },
    { "@type": "HowToTool", "name": "cosign", "url": "https://github.com/sigstore/cosign" }
  ],
  "step": [
    { "@type": "HowToStep", "name": "Cosign attests the artifact", "text": "cosign attest-blob --key cosign.key --predicate predicate.json --type slsaprovenance --new-bundle-format=false --use-signing-config=false --yes hello > cosign-dsse.json" },
    { "@type": "HowToStep", "name": "Cilock attests the build step", "text": "cilock run --step build --signer-file-key-path cilock-key.pem --attestations environment,material,product -- go build -o hello hello.go" },
    { "@type": "HowToStep", "name": "Write a policy with externalAttestations", "text": "Add an externalAttestations entry keyed by predicateType (https://slsa.dev/provenance/v0.2) with required=true and a functionary whose publickeyid matches the cosign key's PEM-SHA256 hex." },
    { "@type": "HowToStep", "name": "Sign the policy", "text": "cilock sign --signer-file-key-path cilock-key.pem -f policy.json -o policy-signed.json" },
    { "@type": "HowToStep", "name": "Verify", "text": "cilock verify -p policy-signed.json -k cilock-pub.pem -a cilock-attestation.json -a cosign-dsse.json -f hello -s sha256:<materials-root> -s sha256:<products-root>" }
  ]
})}} />

## Different abstraction levels

| Layer | Cosign | Cilock |
|---|---|---|
| **What it signs** | An artifact's digest (blob, OCI image, SBOM file) | A pipeline step's full evidence — argv, materials, products, environment, embedded findings |
| **Predicate body** | Whatever you pass to `--predicate` (often SLSA Provenance or a custom JSON) | A `Collection` predicate that bundles every per-attestor record from the step |
| **Subject in the Statement** | The artifact digest | Merkle roots over the step's materials and products trees |
| **Evidence model** | One signed envelope per artifact | One signed envelope per pipeline step, structured by attestor |
| **Verification surface** | "Is this signature valid? Is the signer in Rekor? Does the cert SAN match?" | "Did every step the policy requires happen, signed by the right functionary, with the right embedded evidence — and any required external attestations from upstream?" |
| **Native verification language** | `cosign verify-blob` / `cosign verify-attestation` per file | A Rego-evaluated policy spanning multiple steps + externals, gating release |

Put plainly:

- **Cosign answers "is this artifact's signature trustworthy?"**
- **Cilock answers "is the *pipeline* that produced this artifact trustworthy under my policy?"**

Both questions are valid. Pipelines that already use cosign for image signing can keep doing exactly that, then use cilock policy to **verify the cosign attestation as one input** alongside cilock's per-step evidence.

## Shared wire format

Both tools emit and consume DSSE envelopes carrying in-toto Statements. The relevant primitives:

| Spec | What it standardises |
|---|---|
| [DSSE](https://github.com/secure-systems-lab/dsse) | The signed envelope: `{ "payloadType", "payload", "signatures": [...] }` |
| [in-toto Statement v0.1 / v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) | The payload shape: `{ "_type", "predicateType", "subject", "predicate" }` |
| [SLSA Provenance v0.2 / v1](https://slsa.dev/provenance/v1) | A common predicate type both tools handle natively |
| [VSA](https://slsa.dev/verification_summary/v1) | A Verification Summary Attestation cilock also emits via `cilock verify --vsa-outfile` |

Because the wire format is shared, an envelope cosign produces is structurally indistinguishable from one cilock produces in cases where the predicate type matches. The signature is verified by ECDSA / ED25519 / RSA the same way on both sides.

## The user story: cilock verifies a cosign attestation

**Scenario.** A pipeline uses cosign to sign release artifacts (a long-established practice). The release-gate team wants to add a richer policy that requires the cosign-signed provenance **plus** cilock per-step evidence from the same build. They don't want to throw out the cosign signing flow.

**Solution.** Add the cosign predicate type to the cilock policy as an `externalAttestations` entry. Cilock will verify the cosign signature using the embedded public key and treat the cosign envelope as required evidence.

### Step 1: cosign produces the attestation (no change to the existing flow)

```bash
cosign attest-blob \
  --key cosign.key \
  --predicate predicate.json \
  --type slsaprovenance \
  --new-bundle-format=false \
  --use-signing-config=false \
  --yes \
  hello > cosign-dsse.json
```

The result is a classic DSSE envelope (`payloadType=application/vnd.in-toto+json`) carrying an SLSA Provenance v0.2 predicate over `hello`.

:::note Why `--new-bundle-format=false`
Cosign v3 defaults to the new bundle format which wraps the DSSE envelope in additional verification material. Cilock policy currently ingests classic DSSE envelopes directly. Both forms carry the same in-toto Statement under the signature; the classic form is what you want to feed cilock today.
:::

### Step 2: cilock attests the build step (in addition)

```bash
cilock run --step build \
  --signer-file-key-path cilock-key.pem \
  --outfile cilock-attestation.json \
  --attestations environment,material,product \
  -- go build -o hello hello.go
```

This produces a cilock collection envelope. The pipeline keeps both the cosign envelope and the cilock collection envelope as release artifacts.

### Step 3: write a policy that requires both

```json
{
  "expires": "2030-01-01T00:00:00Z",
  "publickeys": {
    "<cilock-keyid>": { "key": "..." },
    "<cosign-keyid>": { "key": "..." }
  },
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [{ "publickeyid": "<cilock-keyid>" }],
      "attestations": [
        { "type": "https://aflock.ai/attestations/material/v0.3" },
        { "type": "https://aflock.ai/attestations/product/v0.3" },
        { "type": "https://aflock.ai/attestations/command-run/v0.1" }
      ]
    }
  },
  "externalAttestations": {
    "slsa-provenance-from-cosign": {
      "name": "slsa-provenance-from-cosign",
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "required": true,
      "functionaries": [{ "publickeyid": "<cosign-keyid>" }]
    }
  }
}
```

Two keys in `publickeys`: one trusts cilock-signed envelopes (the build step), one trusts cosign-signed envelopes (the external SLSA Provenance). Both are functionaries on their respective evidence requirements.

The `<cosign-keyid>` is the hex-encoded SHA-256 hash of the cosign public key's PEM bytes — this is how cilock derives key identifiers for any public-key cryptographic material. For an ECDSA P-256 cosign key, that's straightforward:

```bash
shasum -a 256 cosign.pub | awk '{print $1}'
```

### Step 4: verify

```bash
cilock verify \
  -p policy-signed.json \
  -k cilock-pub.pem \
  -a cilock-attestation.json \
  -a cosign-dsse.json \
  -f hello \
  -s "sha256:<materials-root>" \
  -s "sha256:<products-root>" \
  --enable-archivista=false
```

On a clean run:

```
level=info msg="Verification succeeded"
level=info msg="Step: build"
```

If the cosign envelope is missing:

```
required external attestation "slsa-provenance-from-cosign"
(predicateType=https://slsa.dev/provenance/v0.2) not found
```

If the cosign signature is tampered:

```
required external attestation "slsa-provenance-from-cosign" ... rejected by all 1 matching envelopes:
failed to verify envelope: no valid signatures for the provided verifiers found
```

All three outcomes are reproduced in [`interop-cosign-dsse/reproduce.sh`](https://github.com/aflock-ai/attestor-compliance-examples/blob/main/interop-cosign-dsse/reproduce.sh).

## When to use which

| You want to... | Use cosign | Use cilock | Use both |
|---|---|---|---|
| Sign a container image's layers + manifest | ✅ | | |
| Sign an SBOM blob | ✅ | | |
| Capture every command-run, environment variable, materials/products digest of a CI step | | ✅ | |
| Run an OPA Rego policy across multiple pipeline steps before release | | ✅ | |
| Verify, in one policy decision, that an artifact came from a trusted pipeline **and** carries a cosign-signed SLSA Provenance from the build farm | | | ✅ |
| Migrate from an existing cosign-signed flow to richer per-step evidence without re-signing artifacts | | | ✅ — keep cosign envelopes, layer cilock policy on top via `externalAttestations` |

## Cosign-signed VSAs and policies

Two natural extensions of the pattern above:

- **Cosign-signed VSAs.** When cilock verifies a policy with `--vsa-outfile + --signer-*`, it emits a [Verification Summary Attestation](https://slsa.dev/verification_summary/v1) as a DSSE envelope. That VSA can itself be required as an external attestation in a downstream cilock policy — chaining verification across stages. The VSA could equally have been signed by cosign in a pipeline that signs everything through cosign.
- **Cosign-signed policies.** Today `cilock verify -p policy.json` expects a policy envelope signed under the cilock policy payload type. The roadmap includes accepting cosign-signed policy envelopes; track [rookery#39](https://github.com/aflock-ai/rookery/issues/39) for that and the broader externalAttestations work.

## Rekor and transparency

Cosign supports recording every signature in [Rekor](https://github.com/sigstore/rekor), a public transparency log. Cilock policy doesn't natively query Rekor today, but the cosign-signed envelope still carries an embedded `bundle` with the Rekor SET when produced with the new bundle format. A `rego_policy` on the external can decode and assert that the SET is present and matches the verifier's expected log ID — surfacing transparency-log verification as a first-class policy check.

If you have a use case for fetching Rekor entries during cilock verification, please open an issue against [rookery](https://github.com/aflock-ai/rookery/issues).

## Upstream and acknowledgements

- [Cosign](https://github.com/sigstore/cosign) is a [Sigstore](https://www.sigstore.dev) project (CNCF graduated).
- Cosign and cilock are both Apache-2.0.
- The in-toto + DSSE specifications that make this interop possible are open and community-governed.

## See also

- [DSSE and in-toto](../concepts/dsse-and-in-toto) — the shared wire format
- [Policy verification](../concepts/policy-verification) — how cilock evaluates policies
- [`interop-cosign-dsse` example](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/interop-cosign-dsse) — the validated workflow this page documents
- [rookery#39](https://github.com/aflock-ai/rookery/issues/39) — `externalAttestations` design and roadmap
