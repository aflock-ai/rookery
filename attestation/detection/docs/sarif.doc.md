---
title: sarif
description: The cilock sarif attestor captures a SARIF result file emitted by a code scanner (CodeQL, Semgrep, gosec, Trivy) and embeds it byte-identical in a signed in-toto attestation under a .report field.
sidebar_position: 21
examples_repo: 36-sarif
---

Captures a SARIF result file emitted by a code-scanning tool (CodeQL, Semgrep, gosec, Trivy, etc.) and embeds it verbatim in the attestation.

## What it captures

The attestor's struct fields define the predicate schema exactly:

| JSON field | Go type | Source |
|---|---|---|
| `report` | `json.RawMessage` | Raw bytes of the SARIF file, preserved byte-identical to the input. |
| `reportFileName` | `string` | Path of the SARIF product, as reported by the attestation context. |
| `reportDigestSet` | `cryptoutil.DigestSet` | Digest set computed by the product attestor for that file. |

The `report` field is a `json.RawMessage`, not a typed SARIF struct. The previous implementation deserialized into `owenrumney/go-sarif` and re-encoded; the current attestor stores raw bytes so the predicate is byte-identical to the file on disk. The bytes are validated as JSON via `json.Valid` before being recorded.

## When to use

After a SAST scan, container scan, or any tool that emits SARIF as a product. Pair with `product` so the SARIF file is also recorded as a subject:

```bash
cilock run --step sast \
  --attestations command-run,material,product,sarif \
  -- semgrep --config=auto --sarif --output=sast.sarif .
```

## Policy gotcha

The cilock SARIF predicate **wraps** the SARIF document inside a `.report` field. Rego policies must reference `input.report.runs`, not `input.runs`:

```rego
package cilock.verify

deny contains msg if {
  some run in input.report.runs
  some result in run.results
  result.level == "error"
  msg := sprintf("SAST found %s: %s", [result.ruleId, result.message.text])
}
```

A policy written against the raw SARIF schema (`input.runs[_].results[_]`) will silently match nothing.

## Flags

None.

## Output shape

```json
{
  "report":          { "/* ... raw SARIF 2.1.0 document ... */": true },
  "reportFileName":  "sast.sarif",
  "reportDigestSet": { "sha256": "…", "sha1": "…" }
}
```

## Gotchas

- **Candidate selection is MIME-driven.** The attestor walks `ctx.Products()` and considers only products whose `MimeType` is `text/plain` or `application/json`. Files with any other detected MIME are skipped — debug-logged with the detected MIME so `--log-level=debug` makes the mismatch visible.
- **SARIF shape is enforced.** A candidate must be a SARIF *log*, checked against the members the SARIF 2.1.0 spec marks REQUIRED: a top-level JSON **object** (§3.13), `version` exactly `2.1.0` (§3.13.2), `runs` present and an **array** (§3.13.4), and every run an **object** carrying `tool` (§3.14.6) with `driver` (§3.18.1) with a non-empty `name` (§3.19.8). Anything else — a scanner's native report, an OCI image manifest, a bare array, `runs: [null]`, a run with no tool, a driver with no name, invalid JSON — is rejected and never recorded under `report`. The check is purely structural: it never keys on file name, step name or tool name to *decide acceptance*, because foreign formats arrive under names the attestor does not control. `"runs": []` is accepted as a genuine clean scan; a missing or `null` `runs` is not. `results` is deliberately **not** required — the spec marks it optional, and the platform-side parser already fails closed on an absent results array rather than projecting it as "no findings".
- **Why `driver.name` is enforced rather than defaulted.** It is the field the platform's evidence classifier keys on to identify the producing scanner. A blank name does not degrade to "unrecognized tool" — it reads as **no signal**, a different state the platform keeps deliberately distinct. Rejecting a nameless driver at the producer is what keeps that distinction meaningful for every downstream consumer.
- **`version` is pinned, not merely required.** `2.1.0` is the only value the spec permits and the only one this predicate type (`…/attestations/sarif/v0.1`) claims to carry. A genuinely new SARIF major needs a new predicate version rather than a widened check that would let an unreadable document be signed as if it were understood.
- **Typed validation, not JSON-schema validation.** The checks are hand-rolled against the spec's required members rather than run against the published SARIF schema: this attestor holds the report as `json.RawMessage` specifically to shed the go-sarif library "plus its jsonschema validation tree", and rookery gates linked-dependency growth through `.dep-budget.yaml`.
- **Digest re-verification.** The attestor recomputes the digest of the candidate file under `ctx.WorkingDir()` and compares it against the product's recorded digest; mismatches are skipped, not errored.
- **Selection is deterministic.** Products are walked in **sorted path order** and the first SARIF-valid, digest-matching candidate becomes the report. Ranging `ctx.Products()` directly is randomized, which previously made the recorded report a coin flip whenever a step left more than one JSON product in its workdir. Only one report is recorded, so a step emitting several SARIF files still needs splitting — but which one wins is now reproducible from the product set alone.
- **Large reports bloat the envelope.** Thousands of results inflate the signed payload; run scanning as its own `cilock run` step rather than mixing with build.
- **No products → error.** `Attest` fails with `no products to attest` if the context has no products, and `no sarif file found` if none pass the MIME, digest and SARIF-shape checks. The latter names every rejected candidate and its reason, and it is a **fatal** attestor error (not a `SoftError`), so `cilock run` exits non-zero rather than quietly shipping a step with no scan evidence.

## CLI example

Real SARIF 2.1.0 report (semgrep / gosec / codeql / trivy) ingested as a JSON product, byte-preserved into the attestation predicate.

```bash
# With a real SARIF report as a product (any SARIF-emitting scanner works):
cilock run --step sast \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations sarif \
  -- semgrep --sarif --output app.sarif .
```

## See also

- [`sbom` attestor](./sbom)
- Upstream: [witness/sarif.md](https://github.com/in-toto/witness/blob/main/docs/attestors/sarif.md)
