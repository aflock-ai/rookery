# sinkhole-flows — live-only attestor reproduction

`sinkhole-flows` is a **live-only** attestor: it cannot be proven by the hermetic
catalog harness, by design.

## Why it can't ride the hermetic gate

`sinkhole-flows` is `PostProduct` and reads a **hardcoded absolute path**,
`/flows/out.jsonl`, that is written **only** by the `pip-witness` mitmproxy
"sinkhole" sidecar while a `pip install` runs through it
(`plugins/attestors/sinkhole-flows/sinkhole-flows.go`, `FlowsPath` constant).

The predicate embeds the **raw captured HTTP(S) flows** — per-flow timestamps,
request/response headers and bodies, byte counts, and a sha256 of the live
capture file. Every one of those varies per run (see the contract's
`volatile_fields`). There is no stable, recordable artifact the replay harness
could inject and cross-check, so the recorded-vs-replay proof that backs every
other attestor has nothing to bite on. It is therefore proven by the real
end-to-end reproduction in `reproduce.sh`, on a separate cadence from the merge
gate — not by a `testdata/fixtures/` entry.

## What the attestor emits (from the source, verified)

Subjects (only those whose driving env var is set):

- `pip://<name>@<version>` — when `PIPW_PACKAGE_NAME` + `PIPW_PACKAGE_VERSION`
  are set; byte-identical to the `pip-install` attestor's subject
  (digest = sha256 of `"<name>==<version>"`).
- `pipw-sinkhole-scan://<scan-id>` — when `PIPW_SCAN_ID` is set.
- `pipw-sinkhole-flows-file://<scan-id>` — digest = sha256 of the captured
  `/flows/out.jsonl`.

## Status of this reproduction

`reproduce.sh` is **derived from the attestor source and the `pip-witness`
sidecar interface** (env vars `PIPW_SCAN_ID` / `PIPW_PACKAGE_NAME` /
`PIPW_PACKAGE_VERSION`, the `/flows/out.jsonl` bind mount, and the
`product,sinkhole-flows` cilock invocation). `pip-witness` is TestifySec's own
tool (<https://github.com/testifysec/pip-witness>, Apache-2.0) but lives in a
**separate repo**, so this recipe has **not been executed end-to-end inside this
catalog** — the mitmproxy CA + sidecar setup are outside the rookery tree.

To produce a real signed `attestation.json` here: stand up `pip-witness` per its
README, run the recipe, and drop the resulting envelope next to this file (it
will be secret-scanned by the catalog gate like any other public-synced
artifact). Unlike `pip-install`, there is currently no committed
`attestation.json` here because the live sidecar was not run in this session.
