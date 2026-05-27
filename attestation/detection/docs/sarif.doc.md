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
- **JSON validity is enforced.** After reading the file, the bytes are passed through `json.Valid`; non-JSON candidates are rejected even if MIME matched.
- **Digest re-verification.** The attestor recomputes the digest of the candidate file under `ctx.WorkingDir()` and compares it against the product's recorded digest; mismatches are skipped, not errored.
- **First match wins.** Products are iterated and the first JSON-valid, digest-matching candidate becomes the report. If multiple SARIF files are products, deterministic selection is not guaranteed — emit only one, or run the step in isolation.
- **No SARIF schema validation.** The attestor does not check `$schema`, `version`, or the presence of `runs[]`. Any valid JSON under a JSON-ish MIME will be recorded under `report`.
- **Large reports bloat the envelope.** Thousands of results inflate the signed payload; run scanning as its own `cilock run` step rather than mixing with build.
- **No products → error.** `Attest` fails with `no products to attest` if the context has no products, and `no sarif file found` if none of them pass MIME + JSON checks.

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
