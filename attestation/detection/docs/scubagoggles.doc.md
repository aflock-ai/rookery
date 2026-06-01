---
title: ScubaGoggles
description: "Capture a Google Workspace tenant's raw configuration with CISA ScubaGoggles under cilock — the provider settings become a signed scubagoggles/v0.1 attestation that your own Rego policy evaluates. Facts in the evidence, verdict in the policy."
sidebar_position: 60
examples_repo: tool-scubagoggles-gws
---

ScubaGoggles is CISA's SCuBA Secure Configuration Baseline assessment tool for Google Workspace (the GWS counterpart to ScubaGear for M365). Under cilock we use it as a **collector**: it pulls the tenant's actual configuration via the Google Admin SDK, and the `scubagoggles` attestor signs that **raw configuration** as evidence. It deliberately does **not** sign ScubaGoggles' own Pass/Fail verdict — the compliance decision lives in *your* policy (Rego evaluated by `policyverify`), not baked into the attestation.

## Validated invocation

cilock invokes `scubagoggles` **directly** as the wrapped command — no `bash -c "cp …"` shim. The real tool is what cilock executes and whose output it records. The validated invocation against a live tenant:

```bash
cilock run --step gws-assessment \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations scubagoggles,environment \
  --enable-archivista=false \
  -- scubagoggles gws -b commoncontrols -c credentials.json -o ./out --quiet
```

This is the exact line validated end-to-end in [`tool-scubagoggles-gws`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-scubagoggles-gws) — don't paraphrase it.

ScubaGoggles is a **Python package** (`pip install scubagoggles`), not a standalone binary, and it has two prerequisites cilock does **not** provide:

- **OPA** — ScubaGoggles runs CISA's baselines through OPA. Install it once with `scubagoggles getopa` (lands in `~/.scubagoggles/`). cilock ignores the verdict OPA produces; only the collected config is attested.
- **Google auth** — pass a GCP OAuth client (`-c credentials.json`) and authenticate once as a Workspace **super-admin** in the browser (`scubagoggles` caches the token next to the credentials file, so cilock runs are headless thereafter). A service account with domain-wide delegation also works (`--subjectemail`) if the delegated scopes include the read-only Admin SDK / Cloud Identity / Groups Settings scopes. cilock **records** ScubaGoggles' output; it does not perform the auth.

`scubagoggles gws` exits non-zero only on collection errors, not on baseline failures — the findings never gate the run, because in this model the run only *collects*. Drop `-b commoncontrols` to assess all ten baselines.

## What gets captured

A single run with `--attestations scubagoggles,environment` produces these predicate types in the signed envelope:

- `https://aflock.ai/attestations/command-run/v0.1` — the actual `argv` and exit code of `scubagoggles`.
- `https://aflock.ai/attestations/material/v0.3` — Merkle hashes of every input file the run read.
- `https://aflock.ai/attestations/product/v0.3` — Merkle hash of the `ScubaResults*.json` the run wrote.
- `https://aflock.ai/attestations/scubagoggles/v0.1` — the **raw Google Workspace provider configuration** (policies, super-admins, OU layout, DNS records, group settings), ready for policy. **Not** a verdict.
- `https://aflock.ai/attestations/environment/v0.1` — host OS, kernel, env vars (with redaction).

## Why this shape

The defining choice for this attestor is **facts, not verdict**:

| Antipattern | Correct shape (this attestor) |
|---|---|
| Attest ScubaGoggles' `Results` (per-control Pass/Fail from CISA's OPA) | Attest the `Raw` provider config — the actual settings |
| The verdict is baked into the evidence; you inherit one tool's opinion | The evidence is reusable ground truth; **your** policy renders the verdict |
| Rego sees `input` = pre-decided results | Rego sees `input.predicate.config` = the exact configuration ScubaGoggles fed to OPA |
| Re-running with stricter rules means re-running ScubaGoggles | Re-evaluate the same signed config against a new policy — no re-collection |

The attestor reads the `Raw` section of `ScubaResults*.json` (or a bare `ProviderSettingsExport.json`) — which is byte-for-byte the object ScubaGoggles passes to OPA — and signs it. That makes the predicate directly evaluable by Rego: a policy reads `input.predicate.config.policies`, `…super_admins`, etc.

## Validate it locally

After running the invocation above:

```bash
# Predicate types present — scubagoggles/v0.1 among them.
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[].type] | sort'
```

```json
[
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/scubagoggles/v0.1"
]
```

Confirm the predicate identifies the tenant and carries **facts, not a verdict**:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("scubagoggles/v0.1")) | .attestation.predicate
        | {tenantId, domainName, tool, orgUnits: (.orgUnits|length), leakedVerdict: (.config|has("Results"))}'
# { "tenantId": "C0153amby", "domainName": "example.com", "tool": "ScubaGoggles",
#   "orgUnits": 9, "leakedVerdict": false }
```

`leakedVerdict: false` is the contract: `config` holds raw settings (`policies`, `super_admins`, `domains`, …), never ScubaGoggles' `Results`.

## Deciding the verdict (your policy)

Because the attestation is facts, a Rego policy decides compliance. The example ships a TestifySec-authored, deny-based Common Controls policy that reads `input.predicate.config` directly (see [`tool-scubagoggles-gws`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-scubagoggles-gws)):

```rego
package gws_commoncontrols

# GWS.COMMONCONTROLS.6.2 — 2..8 distinct super-admins.
deny contains msg if {
	n := count(input.predicate.config.super_admins)
	n < 2
	msg := sprintf("super-admin count %d is below the minimum of 2 (GWS.COMMONCONTROLS.6.2)", [n])
}
```

This is **our** Rego, not CISA's. CISA's baselines read `input.policies` at top level and emit a `tests` set; `policyverify` feeds `input.predicate.config` and queries `<package>.deny` on every module — so consuming CISA's rego unchanged would mean forking it. Purpose-built deny rules avoid that and keep the verdict in your trust domain. The control intent is informed by CISA's SCuBA Common Controls baseline ([ScubaGoggles](https://github.com/cisagov/ScubaGoggles), CC0-1.0). Gate it with [`policyverify`](./policyverify):

```bash
cilock verify -p gws-commoncontrols.policy.json -k policy-pub.pem -a attestation.json
```

## How a verifier consumes this

The `scubagoggles` attestor is a `postproduct` lifecycle attestor with predicate type `https://aflock.ai/attestations/scubagoggles/v0.1`. It locates the provider config among the attestation products (the `Raw` section of a `ScubaResults*.json`, or a top-level `ProviderSettingsExport.json`), validates it is Google Workspace data, and signs:

- `tool` / `toolVersion` / `collectedAt` — provenance from the ScubaResults `MetaData` when present.
- `tenantId` — the GWS customer ID.
- `domainName` / `displayName` — primary domain and org name.
- `domains` / `orgUnits` — deduped, sorted, for addressability.
- `config` — the raw provider settings verbatim (the Rego `input`).
- `sourceFile` / `sourceDigest` — the consumed file and its `cryptoutil.DigestSet`, matching the product digest.

Subjects emitted for graph linking (SHA-256 of the identifier string):

- `googleworkspace:tenant:<customerId>`
- `googleworkspace:domain:<domain>` for the primary domain and each entry in `domains`
- `googleworkspace:orgunit:<path>` for each org unit

Because the tenant subject hashes the GWS customer ID, a [`steampipe`](./steampipe) run using the `googledirectory` plugin converges with this attestation on the same `customer_id` / `domain_name` digests in the verifier's subject graph.

## Notes

- ScubaGoggles ships only as a pip package; there is no release binary. The attestor execs whatever `scubagoggles` is on `PATH`, exactly like the (also-Python) [`prowler`](./prowler) attestor.
- cilock does not authenticate to Google for you, and it ignores ScubaGoggles' OPA verdict. It records the configuration the run collected; nothing about the tenant is mutated (all scopes are read-only).
- A bare `ProviderSettingsExport.json` is accepted as the product too, for pipelines that collect config without the full baseline run.

## FAQ

**Why not attest the Pass/Fail results ScubaGoggles already computes?**
That is a verdict, and the attestor model is facts-in / policy-decides. Signing the verdict couples your evidence to one tool's ruleset and version; signing the config lets any policy — yours, an auditor's, a future stricter one — evaluate the same ground truth.

**Do I still need CISA's baselines?**
You need their *intent*. The example policy re-expresses Common Controls as deny rules over the attested config. ScubaGoggles' own OPA run is not used for the verdict here.

## See also

- [`steampipe`](./steampipe) — alternative Google Workspace config collector (via the `googledirectory` plugin); converges with this attestor by tenant/domain digest.
- [`policyverify`](./policyverify) — evaluates your Rego over the attested config to produce the verdict.
- [`prowler`](./prowler) — the same collector-plus-policy pattern for AWS/GCP/Azure/M365.
