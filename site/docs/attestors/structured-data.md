---
title: structured-data
sidebar_position: 41
---

# `structured-data` attestor

Generic JSON-ingestion attestor: reads a recipe-pointed JSON product, canonicalizes it (RFC 8785 JCS) for a stable digest, selects in-toto subjects with an RFC 9535 JSONPath subset, and emits a signed envelope keyed on those subjects.

| | |
|---|---|
| Name | `structured-data` |
| Predicate type | `https://aflock.ai/attestations/structured-data/v0.1` |
| Lifecycle | `postproduct` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The `Predicate` struct defines the signed payload:

| JSON field | Go type | Source |
|---|---|---|
| `dataType` | `string` | Recipe-supplied label for the data shape (free-form). |
| `collectedAt` | `time.Time` | UTC timestamp at attestation time. |
| `subjectQuery` | `string` | The JSONPath used to select subjects. |
| `subjectPrefix` | `string` (omitempty) | Optional prefix applied to each subject key. |
| `subjectCount` | `int` | Number of subjects derived from the query. |
| `data` | `json.RawMessage` (omitempty) | The full JCS-canonical bytes — only when `embed-data` is true. |
| `dataDigest` | `string` | SHA-256 (hex) of the JCS-canonical encoding of the data file. |
| `subjectDigests` | `map[string]string` (omitempty) | Per-subject `key → sha256(identity)` map. |
| `sourceFile` | `string` (omitempty) | Product path the bytes were read from. |
| `sourceDigest` | `cryptoutil.DigestSet` (omitempty) | Re-computed digest of the source file (verified against the product digest before reading). |

## When to use

When you have JSON evidence from a source that doesn't have a dedicated attestor (Kratos admin-API responses, Splunk saved-search results, Snyk project exports, custom compliance API outputs) and shipping a bespoke attestor would be overkill. The combination of JCS canonicalization plus JSONPath subject selection lets policy join across attestations on stable identity values rather than file hashes.

## Flags

Configuration is supplied via package-level `With*` ConfigOptions (typically wired by a recipe):

| Option | Required | Purpose |
|---|---|---|
| `WithDataFile(path)` | No | Explicit product path to attest over. If unset, the first product with a JSON MIME wins. |
| `WithSubjectQuery(jsonpath)` | **Yes** | RFC 9535 JSONPath expression selecting subject identity values. `Attest` errors if empty. |
| `WithSubjectPrefix(prefix)` | No | String prepended to each subject key. |
| `WithDataType(label)` | No | Recipe-defined label written into `dataType`. |
| `WithEmbedData(bool)` | No | When true, include the canonical bytes in `predicate.data`. Default false — only the digest is recorded. |

## Output shape

```json
{
  "dataType": "kratos.identities.v1",
  "collectedAt": "2026-05-21T14:02:11Z",
  "subjectQuery": "$.identities[*].id",
  "subjectPrefix": "kratos:identity:",
  "subjectCount": 3,
  "dataDigest": "9f2c…",
  "subjectDigests": {
    "kratos:identity:abc-123": "ba78…",
    "kratos:identity:def-456": "1d44…"
  },
  "sourceFile": "kratos-identities.json",
  "sourceDigest": { "sha256": "…" }
}
```

## Gotchas

- **JSON only.** `resolveDataFile` matches products by `strings.Contains(p.MimeType, "json")`. YAML, XML, and plain-text products are not picked up — pre-convert to JSON in the recipe.
- **Subject identity is the path's *value*, not the path.** Subjects are keyed `subjectPrefix + stringifyIdentity(value)` with `digest = sha256(identity-string)`. This matches the convention shared with `prowler`, `aws-config`, `asff`, and `steampipe` so cross-attestation graph joins work.
- **Only scalar matches become subjects.** Strings, JSON numbers (whole numbers render as integers, never scientific notation), and booleans (`"true"`/`"false"`) are kept. Maps, arrays, and nulls are logged at debug and dropped.
- **Subject query is required.** Calling `Attest` without `WithSubjectQuery` errors out — there is no default selector.
- **Source file is re-digested on read.** The attestor recomputes the file digest under the context's hash list and compares it to the product's recorded digest; a mismatch errors with "concurrent write?".
- **Data is not embedded by default.** Without `WithEmbedData(true)`, only `dataDigest` is signed. Verifiers needing the raw values must keep the source file out-of-band or opt in.
- **Each envelope is exported standalone.** `Export()` returns true, so per-recipe envelopes are addressable independently rather than merged into the parent Collection — designed for FedRAMP 20x per-KSI VSA consumption.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/32-structured-data](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/32-structured-data). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`sarif`](./sarif.mdx), [`sbom`](./sbom.mdx) — typed equivalents
