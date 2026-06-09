---
title: Policy schema
sidebar_position: 5
---

# Policy schema

A CI/lock policy is a signed DSSE document that declares which attestation collections must appear, which functionaries are trusted to sign each step, and which OPA Rego rules must pass against attestation contents.

> This page mirrors the witness policy schema, since CI/lock and witness use the same policy format. Source of truth: [`witness/docs/concepts/policy.md`](https://github.com/in-toto/witness/blob/main/docs/concepts/policy.md). Cilock-specific notes are called out where they exist.

## DSSE wrapper

Policies are JSON documents wrapped in a [DSSE](../concepts/dsse-and-in-toto) envelope and signed with `cilock sign`. CI/lock accepts two `payloadType` values for the same schema:

```
https://aflock.ai/policy/v0.1                  # current canonical
https://witness.testifysec.com/policy/v0.1     # legacy (still accepted; default for `cilock sign --datatype`)
```

The default of `cilock sign --datatype` is the legacy witness type for backward compatibility; witness-signed policies verify under CI/lock unchanged. Both constants live at `rookery/attestation/policy/policy.go` (`PolicyPredicate`, `LegacyPolicyPredicate`); CI/lock's verifier accepts either in `rookery/cilock/internal/policy/validate.go`.

## Top-level `policy` object

| Key | Type | Description |
|---|---|---|
| `expires` | string | ISO-8601 timestamp. Evaluation of expired policies always fails. |
| `roots` | object | Trusted X.509 root certificates. Keys are the root certificate's Key ID (sha256 of the cert), values are a `root` object. Used for X.509 functionaries. |
| `publickeys` | object | Trusted public keys. Keys are the public key's Key ID (sha256 of the key, or KMS reference URI), values are a `publickey` object. |
| `steps` | object | Expected steps that must appear to satisfy the policy. Keys are step names (must match `cilock run --step <name>`), values are a `step` object. |
| `timestampauthorities` | object | Trusted X.509 roots for [RFC 3161](../concepts/timestamping) timestamp authorities. Same shape as `roots`. |
| `externalAttestations` | object | Bare-predicate DSSE envelopes verified as first-class policy evidence (SLSA provenance, VSAs, cosign attestations, inclusion-proofs). Keys are local names referenced by `Step.externalFrom`, values are an `externalAttestation` object. See [§externalAttestation](#externalattestation-object). |

## `root` object

| Key | Type | Description |
|---|---|---|
| `certificate` | string | Base64-encoded PEM block of the X.509 root certificate. |
| `intermediates` | array&lt;string&gt; | Base64-encoded PEM blocks of intermediate certificates belonging to `certificate`. |

## `publickey` object

| Key | Type | Description |
|---|---|---|
| `keyid` | string | sha256 of the public key, or a KMS reference URI like `awskms:///arn:aws:kms:...` or `gcpkms://projects/...`. |
| `key` | string | Base64-encoded PEM-formatted public key. May be omitted when `keyid` is a KMS URI and online verification is acceptable. |

## `step` object

| Key | Type | Description |
|---|---|---|
| `name` | string | Step name. Must match a `cilock run --step <name>` invocation that produced an attestation collection. |
| `functionaries` | array&lt;`functionary`&gt; | Identities trusted to sign attestation collections for this step. |
| `attestations` | array&lt;`attestation`&gt; | Attestation types that must appear in the collection to satisfy this step. |
| `artifactsFrom` | array&lt;string&gt; | Names of upstream steps. The materials of this step must match the products of every step listed here — chain-of-custody verification across the supply chain (per-file digest, evaluated independently of Rego). |
| `attestationsFrom` | array&lt;string&gt; | Names of other steps whose collected attestations are lifted into this step's Rego evaluation context as `input.steps.<step>.<predicateType>`. Use when a step's Rego rule must reference data produced by a sibling step (e.g. a release-gate rule that reads the SBOM emitted in the `scan` step). |
| `externalFrom` | array&lt;string&gt; | Names of bare-predicate envelopes declared in the top-level `externalAttestations` map. Each referenced predicate is lifted into the step's Rego context as `input.external.<name>`. Use when a policy must reference DSSE envelopes whose predicate is *not* wrapped in a CI/lock `Collection` — SLSA provenance, VSAs, cosign attestations, inclusion-proofs (the inclusion-proof attestor is a bare predicate and **must** be wired this way, not via `step.attestations`). |

## `functionary` object

| Key | Type | Description |
|---|---|---|
| `type` | string | `"root"` or `"publickey"`. |
| `certConstraint` | `certConstraint` object | Constraints on the signer's X.509 certificate. Only valid when `type = "root"`. |
| `publickeyid` | string | Key ID of a trusted public key (must appear in policy `publickeys`). Only valid when `type = "publickey"`. |

## `certConstraint` object

Every attribute must match the certificate exactly. A certificate must satisfy at least one constraint to pass. `*` is allowed as a wildcard if it's the only element in the array.

| Key | Type | Description |
|---|---|---|
| `commonname` | string | Required Common Name on the cert subject. |
| `dnsnames` | array&lt;string&gt; | Required DNS SANs. |
| `emails` | array&lt;string&gt; | Required email SANs. |
| `organizations` | array&lt;string&gt; | Required Organization fields on the subject. |
| `uris` | array&lt;string&gt; | Required URI SANs, including SPIFFE IDs. |
| `roots` | array&lt;string&gt; | Trust roots (Key IDs from policy `roots`) the cert must chain to. |

### Wildcard constraint (allow any cert from a trusted root)

```json
{
  "commonname": "*",
  "dnsnames": ["*"],
  "emails": ["*"],
  "organizations": ["*"],
  "uris": ["*"],
  "roots": ["*"]
}
```

### SPIFFE ID constraint

```json
{
  "commonname": "*",
  "dnsnames": ["*"],
  "emails": ["*"],
  "organizations": ["*"],
  "uris": ["spiffe://example.com/step1"],
  "roots": ["*"]
}
```

## `attestation` object

| Key | Type | Description |
|---|---|---|
| `type` | string | Attestation predicate type URL. Cilock-native types use `https://aflock.ai/attestations/<name>/v0.1`; legacy witness types `https://witness.dev/attestations/<name>/v0.1` are also accepted via aliases. SBOM attestations use the native CycloneDX (`https://cyclonedx.org/bom`) or SPDX (`https://spdx.dev/Document`) URI. See [attestor catalog](./attestor-catalog). |
| `regopolicies` | array&lt;`regopolicy`&gt; | OPA Rego policies that will be run against the attestation. **All must pass.** |
| `aipolicies` | array&lt;`aipolicy`&gt; | AI-evaluated policies that will be run against the attestation predicate. Each policy sends the predicate body to the AI server configured via `--ai-server-url` and expects `\{"status":"PASS","reason":"..."\}` back. **All must return `PASS`.** See [§aipolicy](#aipolicy-object). |

## `externalAttestation` object

A bare-predicate DSSE envelope (not wrapped in a `Collection`) that the policy treats as first-class evidence. Used for SLSA provenance, VSAs, cosign attestations, and the inclusion-proof attestor — anything whose envelope payload is a single in-toto Statement whose `predicate` is the attestation body itself, with no surrounding `Collection`.

| Key | Type | Description |
|---|---|---|
| `name` | string | Local name; the same string used in any `Step.externalFrom` referencing this envelope. Surfaces as `input.external.<name>` to Rego policies. |
| `predicateType` | string | Statement `predicateType` URI to match — e.g. `https://slsa.dev/provenance/v1`, `https://in-toto.io/attestation/vsa/v1`, `https://aflock.ai/attestations/inclusion-proof/v0.1`. |
| `functionaries` | array&lt;`functionary`&gt; | Identities trusted to sign this envelope. Same shape as a step's functionaries — public-key or X.509 with cert constraints. |
| `regopolicies` | array&lt;`regopolicy`&gt; | Rego policies evaluated against the bare predicate body (the Rego `input` *is* the predicate itself, not the surrounding Statement). |
| `aipolicies` | array&lt;`aipolicy`&gt; | AI policies evaluated against the bare predicate. |
| `required` | bool | When `true` (default), verification fails if no matching envelope is supplied. When `false`, absence is tolerated and the named predicate is simply absent from `input.external`. Use `false` for optional evidence (e.g. an inclusion-proof that's only emitted on demand). |

## `regopolicy` object

| Key | Type | Description |
|---|---|---|
| `name` | string | Name of the rego policy. Reported on failure. |
| `module` | string | Base64-encoded Rego module. |

The Rego module must export a `deny` rule. `deny` should be a string or array of strings, populated only when the policy fails. Anything else the module outputs is ignored.

## `aipolicy` object

| Key | Type | Description |
|---|---|---|
| `name` | string | Human-readable name; reported on failure. |
| `prompt` | string | Prompt sent to the AI model along with the predicate body. The AI is required to reply with a JSON object `\{"status":"PASS\|FAIL","reason":"..."\}`. |
| `model` | string | AI model name to evaluate the prompt against. |

The AI server URL is configured via `--ai-server-url`. SSRF protection limits the URL to `http`/`https` schemes with a non-empty host. Each policy gets one shot — a non-`PASS` response counts as a failure.

```rego
package commandrun.exitcode

deny[msg] {
    input.exitcode != 0
    msg := "exitcode not 0"
}
```

## Verification process

`cilock verify` runs the following checks in order, all must pass:

1. **Verify signatures** on each collection against `policy.publickeys` and `policy.roots`. Anything failing signature verification is dropped. Same check runs against `externalAttestations` envelopes.
2. **Map signers to functionaries:** each collection's signer must satisfy a functionary entry for the step. Same for each external envelope's functionaries.
3. **Verify timestamps** (if present) against `policy.timestampauthorities`. The signing certificate must have been valid at the timestamped time.
4. **Verify materials/products consistency:** the materials of each step must match the products of any step in `artifactsFrom`. (Per-file digest match, independent of Rego.)
5. **Lift cross-step + external evidence into Rego context.** For each step:
   - The step's own collection attestations land at `input.attestations.<predicateType>`.
   - Every step named in `attestationsFrom` is lifted to `input.steps.<step>.<predicateType>`.
   - Every external envelope named in `externalFrom` is lifted to `input.external.<name>` (the predicate body itself, not the surrounding Statement).
6. **Evaluate every embedded Rego policy** against its target. All `deny` rules must be empty.
7. **Evaluate every embedded AI policy** against its target. All must return `{"status":"PASS"}`. The AI server must be reachable; AI policies fail closed.

Exit code 0 on pass, non-zero on any failure.

## Worked example

A two-step policy where `clone` produces source files, `build` produces a binary, and the build's command-run is constrained by a Rego rule that the build command must be exactly `go build -o=testapp .`:

```json
{
  "expires": "2030-12-17T23:57:40-05:00",
  "steps": {
    "clone": {
      "name": "clone",
      "attestations": [
        { "type": "https://aflock.ai/attestations/material/v0.3" },
        { "type": "https://aflock.ai/attestations/command-run/v0.1" },
        { "type": "https://aflock.ai/attestations/product/v0.3" }
      ],
      "functionaries": [
        { "type": "publickey", "publickeyid": "ae2dcc..." }
      ]
    },
    "build": {
      "name": "build",
      "artifactsFrom": ["clone"],
      "attestations": [
        { "type": "https://aflock.ai/attestations/material/v0.3" },
        {
          "type": "https://aflock.ai/attestations/command-run/v0.1",
          "regopolicies": [
            {
              "name": "expected command",
              "module": "cGFja2FnZSBjb21tYW5kcnVuLmNtZAoKZGVueVttc2ddIHsKCWlucHV0LmNtZCAhPSBbImdvIiwgImJ1aWxkIiwgIi1vPXRlc3RhcHAiLCAiLiJdCgltc2cgOj0gInVuZXhwZWN0ZWQgY21kIgp9Cg=="
            }
          ]
        },
        { "type": "https://aflock.ai/attestations/product/v0.3" }
      ],
      "functionaries": [
        { "type": "publickey", "publickeyid": "ae2dcc..." }
      ]
    }
  },
  "publickeys": {
    "ae2dcc...": {
      "keyid": "ae2dcc...",
      "key": "<base64 PEM>"
    }
  }
}
```

The base64 module above decodes to:

```rego
package commandrun.cmd

deny[msg] {
    input.cmd != ["go", "build", "-o=testapp", "."]
    msg := "unexpected cmd"
}
```

Sign this policy with `cilock sign` before distribution:

```bash
cilock sign --signer-file-key-path policy-key.pem -f policy.json -o policy-signed.json
```

## Cross-step + external-evidence example

A release-gate policy that pulls a build step's products through to a release step's Rego, and additionally requires a separately-signed inclusion-proof envelope whose `treeRoot` matches the build's `product/v0.3` Merkle root:

```json
{
  "expires": "2030-12-17T23:57:40-05:00",
  "externalAttestations": {
    "binaryInclusionProof": {
      "name": "binaryInclusionProof",
      "predicateType": "https://aflock.ai/attestations/inclusion-proof/v0.1",
      "functionaries": [{ "type": "publickey", "publickeyid": "ae2dcc..." }],
      "required": true
    }
  },
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        { "type": "https://aflock.ai/attestations/product/v0.3" },
        { "type": "https://aflock.ai/attestations/command-run/v0.1" }
      ],
      "functionaries": [{ "type": "publickey", "publickeyid": "ae2dcc..." }]
    },
    "release": {
      "name": "release",
      "attestationsFrom": ["build"],
      "externalFrom": ["binaryInclusionProof"],
      "attestations": [
        {
          "type": "https://aflock.ai/attestations/command-run/v0.1",
          "regopolicies": [{ "name": "inclusion-proof binds build artifact", "module": "<base64>" }]
        }
      ],
      "functionaries": [{ "type": "publickey", "publickeyid": "ae2dcc..." }]
    }
  },
  "publickeys": { "ae2dcc...": { "keyid": "ae2dcc...", "key": "<base64 PEM>" } }
}
```

The Rego module on the release step reads:

```rego
package release.gate

deny[msg] {
    build_root := input.steps.build["https://aflock.ai/attestations/product/v0.3"].merkleRoot
    proof_root := input.external.binaryInclusionProof.treeRoot
    build_root != proof_root
    msg := sprintf("inclusion-proof root %s does not match build merkleRoot %s", [proof_root, build_root])
}
```

The full worked example — including the build/scan steps and the `cilock verify` recipe — lives at [`multi-step-attestationsFrom`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/multi-step-attestationsFrom) in the examples repo.

## See also

- [Policy verification](../concepts/policy-verification) — the verification model
- [The spine of the graph](../concepts/the-spine-of-the-graph) — how cross-step links resolve via subject digests
- [Verify in a release gate](../guides/verify-in-a-release-gate) — practical recipes
- [witness/docs/concepts/policy.md](https://github.com/in-toto/witness/blob/main/docs/concepts/policy.md) — upstream reference (CI/lock mirrors)
