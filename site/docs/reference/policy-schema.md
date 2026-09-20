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
| `aipolicies` | array&lt;`aipolicy`&gt; | AI-evaluated policies that will be run against the attestation predicate. In the generative form, each policy sends the predicate body to the AI server configured via `--ai-server-url` and expects `\{"status":"PASS","reason":"..."\}` back; in the typed `decision` form the model answers a constrained question and the policy derives the verdict. **All must return `PASS`.** Names must be unique within this attestation. See [§aipolicy](#aipolicy-object). |

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

The Rego module must export a `deny` rule. `deny` should be a string or array of strings, populated only when the policy fails. Anything else the module outputs is ignored. Modules are parsed as Rego v0 by default; add `import rego.v1` at the top of a module that uses the `if`, `contains` or `in` keywords.

### What `input` looks like

`input` is the attestor's own JSON: the predicate body the attestor registered, marshaled as-is. For a step with neither `attestationsFrom` nor `externalFrom` there is no wrapper of any kind, so a command-run policy reads `input.cmd` and `input.exitcode` at the top level:

```rego
package commandrun.exitcode

deny[msg] {
    input.exitcode != 0
    msg := sprintf("build exited with status %d", [input.exitcode])
}
```

As soon as a step lists anything in `attestationsFrom` or `externalFrom`, the verifier re-shapes `input` for every Rego policy on that step into three keys:

| Key | Contents |
|---|---|
| `input.attestation` | The step's own attestor JSON: the object that was the whole `input` in the plain shape. |
| `input.steps.<step>.collections` | One entry per passed collection of each step in `attestationsFrom`: `{reference, name, attestations}` with `attestations` keyed by predicate type URI. Ordered by collection reference, so a rule sees every passed collection and its order does not depend on which source answered first. Read this. |
| `input.steps.<step>.<predicateType>` | **Deprecated.** The attestor of that type from the first collection in `collections` order only. Kept so existing policies keep verifying; the verifier logs a deprecation warning per module that reads it. A rule that must hold for every run of a step cannot be written against this key. |
| `input.external.<name>` | The predicate body of each envelope in `externalFrom` that passed. An external that was skipped or never supplied is absent, so `not input.external.<name>` fires. |

The switch is keyed on the step *declaring* the lists, not on the referenced data being present: a dependency that has not verified yet still produces the wrapped shape, with an empty `input.steps`. A top-level path such as `input.exitcode` is undefined under the wrapped shape, so a module written for the plain shape silently stops matching the moment its step gains an `attestationsFrom` entry. Move its reads under `input.attestation`. The verifier logs a warning whenever the wrapped shape is active.

```rego
package deploy.provenance

# The deploy step's own command-run attestation moved under input.attestation.
deny[msg] {
    input.attestation.exitcode != 0
    msg := sprintf("deploy exited with status %d", [input.attestation.exitcode])
}

# Steps named in attestationsFrom: input.steps.<step>.collections[] (preferred) or the
# deprecated input.steps.<step>.<predicateType> (first passed collection only).
deny[msg] {
    c := input.steps.build.collections[_]
    c.attestations["https://aflock.ai/attestations/command-run/v0.2"].exitcode != 0
    msg := sprintf("build collection %v exited non-zero", [c.reference])
}

deny[msg] {
    build := input.steps.build["https://aflock.ai/attestations/command-run/v0.2"]
    build.cmd[0] != "go"
    msg := sprintf("build step ran %v, expected a go build", [build.cmd])
}

deny[msg] {
    not input.steps.build["https://aflock.ai/attestations/command-run/v0.2"]
    msg := "build step provided no command-run attestation"
}

# Envelopes named in externalFrom: input.external.<name>, absent when not supplied.
deny[msg] {
    not input.external.releaseApproval.approved
    msg := "release approval missing or not granted"
}
```

Both modules above are extracted from this page and run through the real verifier by `attestation/policy/rego_input_shape_doc_test.go`, so they cannot drift from what `cilock verify` actually passes in.

**What `input` is.** With no `attestationsFrom`/`externalFrom` on the step, `input` is the JSON of the registered attestor struct, the same bytes signed inside the collection. For most attestors that puts the predicate's fields at the top level: `input.exitcode` (command-run), `input.commithash` (git), `input.findings` (secretscan). Four attestors register a struct that wraps the predicate in a `predicate` field, so their fields are one level down: `test-results`, `steampipe`, `scubagoggles`, and `structured-data` are read as `input.predicate.<field>`, for example `input.predicate.summary.failed`, not `input.summary.failed`. Rego treats an undefined path in a `deny` body as "this rule does not fire", never as an error, so a flat read against a wrapped attestor passes a failing suite silently. Check the shape with `cilock tools show <name>` (the attestor page states it under "Rego input shape") or by base64-decoding the attestation in a real collection; `cilock policy validate` warns when a module bound to `test-results/v0.1` reads a top-level predicate field.

## `aipolicy` object

An `aipolicy` has two mutually exclusive forms. **Exactly one of `prompt` or `decision` must be set** — both, or neither, is a policy error and verification refuses before any request leaves the process.

| Key | Type | Description |
|---|---|---|
| `name` | string | Human-readable name; reported on failure. Must be non-empty and **unique within an `attestation`** — it is the question id when several questions go to the model in one request. |
| `model` | string | AI model name to evaluate against. Required; there is no default. |
| `prompt` | string | **Generative form.** Free text sent to the AI model along with the predicate body. The AI is required to reply with a JSON object `\{"status":"PASS\|FAIL","reason":"..."\}`. Mutually exclusive with `decision`. |
| `decision` | `decision` | **Typed form.** The model answers a constrained question; the POLICY decides PASS/FAIL from the answer. Mutually exclusive with `prompt`. See [§decision](#decision-object). |

The AI server URL is configured via `--ai-server-url`. SSRF protection limits the URL to `http`/`https` schemes with a non-empty host. Each policy gets one shot — a non-`PASS` response counts as a failure.

### Generative example

```json
{
  "name": "no-secrets-in-diff",
  "model": "llama3",
  "prompt": "Does this diff introduce a hardcoded credential? Return PASS if it does not."
}
```

## `decision` object

The generative form asks the model to be the judge: it returns the verdict, and the policy takes its word for it. The typed form splits those jobs. The model answers a **constrained question** — a probability, a choice from a fixed list, an ordinal score — and the **policy** turns that answer into PASS/FAIL using assertions written into the signed policy. What the gate accepts is therefore readable from the policy alone.

Exactly one of `yesNo`, `choice` or `score` must be set.

| Key | Type | Description |
|---|---|---|
| `state` | `regopolicy` | Optional Rego projection selecting the part of the attestor the question is about. Omitted means the whole attestor is the question's state. |
| `yesNo` | `yesNo` | A boolean question scored as a probability. |
| `choice` | `choice` | A single selection from a fixed set of named options. |
| `score` | `score` | An ordinal score over a fixed ladder of levels. |

### `yesNo`

| Key | Type | Description |
|---|---|---|
| `instructions` | string | The yes/no question put to the model. |
| `criteria` | map&lt;string,string&gt; | Named clarifications the model must weigh. |
| `minProbability` | number | The probability of "yes" must be at least this, in `[0,1]`. |
| `maxProbability` | number | The probability of "yes" must be at most this, in `[0,1]`. `0` asserts impossibility. |

### `choice`

| Key | Type | Description |
|---|---|---|
| `instructions` | string | The question put to the model. |
| `options` | map&lt;string,string&gt; | The selectable options as `id` → description. Must be non-empty; the model answers with one `id`. |
| `allow` | array&lt;string&gt; | Option ids that PASS. Every entry must be a key of `options`. |
| `deny` | array&lt;string&gt; | Option ids that FAIL. Every entry must be a key of `options`. |
| `minConfidence` | number | The chosen option's confidence must be at least this, in `[0,1]`. |

### `score`

| Key | Type | Description |
|---|---|---|
| `instructions` | string | The question put to the model. |
| `levels` | array&lt;string&gt; | The ordered ladder of levels, lowest first. Must be non-empty; the score is an **index** into this list. |
| `minScore` | number | The score must be at least this. Within `[0, len(levels)-1]`. |
| `maxScore` | number | The score must be at most this. Within `[0, len(levels)-1]`. |

### Decision example

```json
{
  "name": "tamper-risk",
  "model": "llama3",
  "decision": {
    "yesNo": {
      "instructions": "Does this command-run attestation show the build step executing a command it did not declare?",
      "criteria": {
        "undeclared": "a process in the trace whose argv is absent from the declared step command"
      },
      "maxProbability": 0.05
    }
  }
}
```

And with a choice:

```json
{
  "name": "change-risk-tier",
  "model": "llama3",
  "decision": {
    "choice": {
      "instructions": "Classify the risk of this diff.",
      "options": {
        "routine": "docs, tests, comments",
        "behavioural": "changes runtime behaviour",
        "security": "touches auth, crypto, or a trust boundary"
      },
      "deny": ["security"],
      "minConfidence": 0.7
    }
  }
}
```

### Rules the verifier enforces

Every rule below fails **closed**, and all of them are checked before any AI request is made.

1. Exactly one of `prompt` / `decision`.
2. Exactly one of `decision.yesNo` / `.choice` / `.score`.
3. `model` is required.
4. Every decision kind sets **at least one assertion** (`minProbability`/`maxProbability`, `allow`/`deny`/`minConfidence`, `minScore`/`maxScore`). A decision that asserts nothing about the answer would pass whatever the model said — an unasserted gate reads as coverage while providing none.
5. `choice.options` and `score.levels` are non-empty.
6. Every `choice.allow` / `choice.deny` entry is a key of `choice.options`. An assertion naming an option the model can never return never fires.
7. Probabilities and confidences are in `[0,1]`; `minProbability <= maxProbability`; `minScore <= maxScore`; score bounds within `[0, len(levels)-1]`.
8. `name` is non-empty and unique within its `attestation`.

:::caution Decision policies are not evaluated yet
The typed shape is accepted, validated and signed, but no backend answers a constrained question today. A policy carrying `decision` is **refused** at verification time with `no provider configured for decision policies` — it is never silently treated as a pass. Only the generative `prompt` form is evaluated by the shipped Ollama-compatible provider.
:::

## Verification process

`cilock verify` runs the following checks in order, all must pass:

1. **Verify signatures** on each collection against `policy.publickeys` and `policy.roots`. Anything failing signature verification is dropped. Same check runs against `externalAttestations` envelopes.
2. **Map signers to functionaries:** each collection's signer must satisfy a functionary entry for the step. Same for each external envelope's functionaries.
3. **Verify timestamps** (if present) against `policy.timestampauthorities`. The signing certificate must have been valid at the timestamped time.
4. **Verify materials/products consistency:** the materials of each step must match the products of any step in `artifactsFrom`. (Per-file digest match, independent of Rego.)
5. **Lift cross-step + external evidence into Rego context.** For a step with neither `attestationsFrom` nor `externalFrom`, each Rego policy's `input` is the attestor it is attached to, unwrapped. For a step that declares either list, `input` becomes:
   - `input.attestation`: the step's own attestor (the one the policy is attached to), as a single object.
   - `input.steps.<step>.<predicateType>`: every attestor from each step named in `attestationsFrom`.
   - `input.external.<name>`: the predicate body of each envelope named in `externalFrom` (not the surrounding Statement); absent when the envelope was skipped or missing.

   See [What `input` looks like](#what-input-looks-like) for both shapes with runnable examples.
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
        { "type": "https://aflock.ai/attestations/command-run/v0.2" },
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
          "type": "https://aflock.ai/attestations/command-run/v0.2",
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
        { "type": "https://aflock.ai/attestations/command-run/v0.2" }
      ],
      "functionaries": [{ "type": "publickey", "publickeyid": "ae2dcc..." }]
    },
    "release": {
      "name": "release",
      "attestationsFrom": ["build"],
      "externalFrom": ["binaryInclusionProof"],
      "attestations": [
        {
          "type": "https://aflock.ai/attestations/command-run/v0.2",
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
