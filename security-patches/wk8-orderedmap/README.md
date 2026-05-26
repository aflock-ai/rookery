# Vendored fork: github.com/wk8/go-ordered-map/v2

This directory contains a TestifySec-maintained rewrite of
`github.com/wk8/go-ordered-map/v2@v2.1.8`. The public API is unchanged; the
on-wire JSON representation is identical. **Only `json.go` is different.**

## Why we vendor this

The upstream `wk8/go-ordered-map/v2` `MarshalJSON` / `UnmarshalJSON`
implementations are built on top of two third-party JSON libraries with
material supply-chain risk:

- **`github.com/buger/jsonparser`** — single-author, last upstream commit
  August 2020, carries the unfixed **GHSA-6g7g-w4f8-9c9x / CVE-2026-32285**
  denial-of-service in `Delete()`. We already maintain a tiny security
  patch fork at `security-patches/buger-jsonparser/`, but
  `wk8/go-ordered-map` is the actual chokepoint: through
  `invopop/jsonschema → wk8/go-ordered-map → buger/jsonparser`, it pulls
  `buger` into **every shipping binary** (`judge-api`, `jade`, `cilock`)
  via the rookery attestor plugins' `Schema()` reflection.

- **`github.com/mailru/easyjson`** — single-author, only used by `wk8` for
  its fast string writer. Same long-tail trust domain.

Both libraries are pulled in **only** for what stdlib `encoding/json`
already does perfectly well. The cost-benefit is bad: we accept two
single-author supply-chain risks to save a few microseconds in attestor
schema generation, which runs once per attestor at boot.

## What changed vs upstream v2.1.8

| File          | Change vs upstream                                    |
| ------------- | ----------------------------------------------------- |
| `orderedmap.go` | unchanged (byte-for-byte copy)                      |
| `yaml.go`     | unchanged (byte-for-byte copy)                        |
| `json.go`     | **rewritten** — see below                             |
| `go.mod`      | trimmed (no `buger/jsonparser`, no `mailru/easyjson`) |

### json.go rewrite

- **`MarshalJSON`** — uses `bytes.Buffer` + `json.Marshal` on each value.
  Key encoding logic (string keys, integer keys formatted as quoted numbers,
  `encoding.TextMarshaler` keys, wrapper types around primitives) is
  preserved so the on-wire JSON object matches what upstream produced.

- **`UnmarshalJSON`** — uses `json.Decoder` with `dec.Token()` iteration
  to walk a JSON object key-by-key in stream order. This is the stdlib
  primitive that preserves insertion order on decode — exactly the same
  guarantee upstream got from `jsonparser.ObjectEach`.

Both functions are intentionally identical in behavior to upstream — the
JSON round-trip is bit-perfect with the exception of insignificant
whitespace (which upstream also did not preserve).

## How it's wired

Each consumer module that links into a TestifySec shipping binary adds a
`replace` directive pointing here, e.g. in `judge-api/go.mod`:

```
replace github.com/wk8/go-ordered-map/v2 => ../security-patches/wk8-orderedmap/v2
```

The module path stays the upstream path, so import statements throughout
the codebase do not change. Plugin go.mods inside `subtrees/rookery/`
build standalone with upstream `wk8` for local development convenience;
the shipping binaries always link our vendored copy.

## Maintenance

When upstream releases a new version we want to take, replay this README
change list: copy `orderedmap.go` and `yaml.go` verbatim, then re-apply
the `json.go` rewrite (which has no upstream equivalent to merge against —
it is wholly TestifySec-owned). Keep `go.mod` clean of `buger/jsonparser`
and `mailru/easyjson`.
