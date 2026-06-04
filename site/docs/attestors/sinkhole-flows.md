---
title: sinkhole-flows
sidebar_position: 39
---

# `sinkhole-flows` attestor

Attaches HTTP(S) flow data captured by a mitmproxy sidecar — request/response pairs and TLS ClientHello events — to a signed attestation collection, so policy can reason about exactly which hosts a scan or build talked to.

| | |
|---|---|
| Name | `sinkhole-flows` |
| Predicate type | `https://aflock.ai/attestations/sinkhole-flows/v0.1` |
| Lifecycle | `postproduct` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The attestor reads JSON Lines from `/flows/out.jsonl` (a bind mount from the host sinkhole/flows directory written by a mitmproxy addon sidecar) and emits a predicate with these fields:

- `scanId` — value of the `PIPW_SCAN_ID` env var; flows are filtered to this id so concurrent scans sharing one sidecar stay attributable.
- `packageName`, `packageVersion` — from `PIPW_PACKAGE_NAME` / `PIPW_PACKAGE_VERSION`; used to emit a `pip://NAME@VERSION` subject byte-identical to `pip-install`'s for subject-digest joins in Archivista.
- `summary` — aggregate counters: `totalFlows`, `uniqueHosts`, `uniqueSnis`, `schemeCounts`, `statusCounts`, `totalBytesOut`, `totalBytesIn`, `flowsPath`, `flowsFileSha256` (sha256 of the raw `out.jsonl`).
- `flows[]` — each entry has `scanId`, `timestamp`, `event` (`"http"` or `"tls_clienthello"`), `sni`, `alpnProtocols`, `method`, `scheme`, `host`, `port`, `path`, `httpVersion`, `requestHeaders`, `requestBody`, `responseStatus`, `responseReason`, `responseHeaders`, `responseBody`.
- Bodies use a `FlowBody` shape: `encoding`, `length`, `truncated`, `text`, `b64`, `empty` — text or base64 as the mitmproxy addon recorded it.

Subjects emitted: `pip://NAME@VERSION` (digest of `NAME==VERSION`), `pipw-sinkhole-scan://<scanId>`, and `pipw-sinkhole-flows-file://<scanId>` (digest = the recorded `flowsFileSha256`).

A missing `/flows/out.jsonl` is **not** an error — the attestor returns an empty-but-valid statement so it can run in both sinkhole-enabled and sinkhole-disabled container configs.

## When to use

Designed for the `pipw_sinkhole` workflow: a pip-witness scan container with all egress routed through a mitmproxy sidecar. Use it whenever you want a signed, queryable record of every HTTP(S) host a scan or build contacted, paired with a no-egress-except-via-proxy network policy for the strongest "this build only talked to expected hosts" signal.

## Flags

None. Behavior is driven by environment variables: `PIPW_SCAN_ID`, `PIPW_PACKAGE_NAME`, `PIPW_PACKAGE_VERSION`.

## Output shape

```json
{
  "scanId": "scan-abc123",
  "packageName": "requests",
  "packageVersion": "2.31.0",
  "summary": {
    "scanId": "scan-abc123",
    "totalFlows": 4,
    "uniqueHosts": ["pypi.org", "files.pythonhosted.org"],
    "uniqueSnis": ["pypi.org", "files.pythonhosted.org"],
    "schemeCounts": {"https": 4},
    "statusCounts": {"200": 4},
    "totalBytesOut": 1820,
    "totalBytesIn": 248113,
    "flowsPath": "/flows/out.jsonl",
    "flowsFileSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  },
  "flows": [
    {
      "scanId": "scan-abc123",
      "timestamp": "2026-05-21T17:04:11Z",
      "event": "tls_clienthello",
      "sni": "pypi.org",
      "alpnProtocols": ["h2", "http/1.1"]
    },
    {
      "scanId": "scan-abc123",
      "timestamp": "2026-05-21T17:04:11Z",
      "event": "http",
      "method": "GET",
      "scheme": "https",
      "host": "pypi.org",
      "port": 443,
      "path": "/simple/requests/",
      "httpVersion": "HTTP/2.0",
      "responseStatus": 200
    }
  ]
}
```

## Gotchas

- Requires a cooperating mitmproxy sidecar addon writing JSONL to `/flows/out.jsonl`. Without that sidecar (and the `pipw_sinkhole` Docker network routing traffic through it), the attestation will simply be empty.
- The scanner buffer is sized to 32 MB per line so large captured bodies (the addon caps body size at 4 MB but base64 + JSON envelope can push a single entry past 8 MB on disk) don't trip a `bufio.Scanner` "token too long" error.
- Lines that fail to parse, or whose `scan_id` does not match the current `PIPW_SCAN_ID`, are silently skipped — concurrent scans sharing one sidecar do not cross-contaminate.
- The `pip://NAME@VERSION` subject is intentionally byte-identical to the one `pip-install` emits (digest of `"NAME==VERSION"`). Changing either side breaks the Archivista subject-digest join.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/40-sinkhole-flows](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/40-sinkhole-flows). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`command-run`](./command-run.mdx) — pair with `--trace`
- [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks.md)
