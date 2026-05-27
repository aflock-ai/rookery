---
title: vex
description: The cilock vex attestor captures an OpenVEX document found among a step's product files and attaches it as in-toto evidence under the canonical OpenVEX predicate type URI.
sidebar_position: 25
examples_repo: 37-vex
---

Captures an OpenVEX document discovered among the step's product files and attaches it as an in-toto predicate with the canonical OpenVEX type URI.

## What it captures

The attestor walks `ctx.Products()`, recomputes each file's digest, verifies it matches the recorded product digest, then attempts to `json.Unmarshal` the bytes into the inlined `openvex.VEX` type. The first product whose bytes decode cleanly into a VEX document is captured. The serialized predicate has three fields:

- `vexDocument` (`openvex.VEX`) — the full parsed OpenVEX document (see types below).
- `reportFileName` (`string`) — path of the source product file.
- `reportDigestSet` (`cryptoutil.DigestSet`) — digest set carried over from the product, recorded so verifiers can re-anchor the document to the step's product attestor.

The `openvex` types are **inlined** at `plugins/attestors/vex/internal/openvex/types.go` from `github.com/openvex/go-vex` commit `3185a64ed27703fc3fe4af8cd5e1ce0ed2fa2569` (tag `v0.2.7`, Apache-2.0). Only the type definitions and constants required for JSON decode/encode are present — no upstream methods (`Validate`, `Matches`, `Builder`, etc.) are reproduced. The inlined surface:

- `VEX` — embeds `Metadata` plus `Statements []Statement`. Has a custom `MarshalJSON` that normalizes `timestamp` / `last_updated` to UTC RFC3339 (no nanoseconds), byte-compatible with upstream go-vex output.
- `Metadata` — `@context`, `@id`, `author`, `role`, `timestamp`, `last_updated`, `version`, `tooling`, `supplier`.
- `Statement` — `@id`, `vulnerability`, `timestamp`, `last_updated`, `products`, `status`, `status_notes`, `justification`, `impact_statement`, `action_statement`, `action_statement_timestamp`.
- `Vulnerability` — `@id`, `name` (`VulnerabilityID`), `description`, `aliases`.
- `Product` — embeds `Component`, plus `subcomponents []Subcomponent`.
- `Subcomponent` — embeds `Component`.
- `Component` — `@id`, `hashes` (`map[Algorithm]Hash`), `identifiers` (`map[IdentifierType]string`), `supplier`.
- `Status` constants: `not_affected`, `affected`, `fixed`, `under_investigation`.
- `Justification` constants: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.
- `IdentifierType` constants: `purl`, `cpe22`, `cpe23`.
- `Algorithm` constants: `md5`, `sha1`, `sha-256`, `sha-384`, `sha-512`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `blake2s-256`, `blake2b-256`, `blake2b-512`, `blake3`.

## When to use

Pair with the `sbom` attestor to deliver SBOM + VEX evidence in a single step: the SBOM enumerates components, the VEX document records exploitability statements (not_affected / affected / fixed / under_investigation) against those components. Policies can then gate releases on the presence and contents of both predicate types.

## Flags

None. The attestor takes no configuration — selection is implicit via product unmarshal probing.

## Output shape

```json
{
  "vexDocument": {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://openvex.example/docs/vex-001",
    "author": "Example, Inc.",
    "timestamp": "2026-05-21T12:00:00Z",
    "version": 1,
    "statements": [
      {
        "vulnerability": { "name": "CVE-2024-12345" },
        "products": [
          { "@id": "pkg:oci/example@sha256:abcd..." }
        ],
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path"
      }
    ]
  },
  "reportFileName": "build/vex.json",
  "reportDigestSet": {
    "sha256": "..."
  }
}
```

## Gotchas

- **Detection is unmarshal-probing, not MIME-based.** The attestor calls `json.Unmarshal` against every product in turn and picks the first that parses into `openvex.VEX`. There is no content-type check, file-extension filter, or `@context` validation — any JSON whose top-level shape happens to fit (e.g. a document with a `statements` array) will be accepted. Keep VEX files distinct in the product set.
- **`Attest` returns `no VEX file found` if no product decodes.** Add the VEX file to the step's products (e.g. via the `product` attestor's path config) or the step will fail.
- **Digest mismatches are skipped, not fatal.** If `CalculateDigestSetFromFile` disagrees with the recorded product digest, the file is logged at debug and skipped — no error is surfaced unless every candidate fails.
- **Inlined types, not the upstream library.** Documents are decoded against the rookery-internal `openvex` package, which is byte-compatible with OpenVEX 0.2.0 but does not call upstream `Validate` / `Matches`. Schema drift in newer OpenVEX versions will silently lose unknown fields.
- **Timestamps re-serialize to RFC3339 UTC.** `VEX.MarshalJSON` strips sub-second precision and forces UTC. Round-tripping a document through the attestor produces a canonical form, not a byte-identical copy of the input.

## CLI example

Real OpenVEX statement emitted alongside an SBOM, expressing CVE-not-affected status.

```bash
cilock run --step vex-capture \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations vex,environment,git \
  -- vexctl create --product pkg:apk/alpine/curl@8.0.0 --vuln CVE-2023-38545 --status not_affected --justification vulnerable_code_not_in_execute_path --file app.openvex.json
```

Validated with a real OpenVEX (openvex.dev/ns) statement. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/37-vex](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/37-vex).

## See also
- [Catalog row](../reference/attestor-catalog)
- [`sbom`](./sbom)
- [OpenVEX spec](https://github.com/openvex/spec)
- Upstream: [witness/vex.md](https://github.com/in-toto/witness/blob/main/docs/attestors/vex.md)
