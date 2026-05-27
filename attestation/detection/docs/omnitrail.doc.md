---
title: omnitrail
description: The cilock omnitrail attestor captures a content-addressed trail of every file and directory under the working directory with POSIX metadata, signed into in-toto evidence for cross-tool provenance correlation.
sidebar_position: 27
examples_repo: 12-omnitrail
---

Captures a content-addressed trail of every file and directory under the working directory, with POSIX metadata, suitable for cross-tool provenance correlation.

## What it captures

The attestor wraps the upstream [`omnitrail-go`](https://github.com/fkautz/omnitrail-go) factory, which walks `ctx.WorkingDir()` and produces a single `Envelope` with three default plugins active: file, directory, and POSIX.

The attestor struct itself has exactly one json-tagged field:

| Field | Type | Description |
|---|---|---|
| `Envelope` | `*omnitrail.Envelope` | Trail envelope — header + per-path mapping |

`Envelope.Header.Features` records which hash algorithms were enabled (SHA1 is on by default). `Envelope.Mapping` is a `map[string]*Element` keyed by path. Each `Element` records:

- `type` — `file` or `directory`
- `sha1`, `sha256` — content hashes (when the corresponding algorithm is enabled)
- `gitoid:sha1`, `gitoid:sha256` — OmniBOR artifact dependency graph identifiers
- `posix` — atime, ctime, mtime, creation_time, file_inode, file_device_id, file_system_id, file_type, file_flags, hard_link_count, owner_uid, owner_gid, permissions, size, extended_attributes, metadata_ctime

> **Note:** Despite the name, omnitrail does **not** auto-detect toolchains (go, cargo, node, pip, gcc, etc.). It is a filesystem trail, not a tool inventory. For toolchain provenance, layer in `command-run` or language-specific attestors.

## When to use

Use omnitrail when downstream verifiers need a stable, content-addressed reference for every input file in the workspace — particularly for OmniBOR/ADG-based correlation across pipeline stages or between independent reproducible builds. Because it runs in the `prematerial` phase, it sees the workspace before any user command mutates it.

## Flags

None. The attestor exposes no CLI flags; the upstream library is constructed with defaults (SHA1 enabled, no allow-list, all three plugins active).

## Output shape

```json
{
  "Envelope": {
    "header": {
      "features": {
        "sha1": { "algorithms": ["sha1"] }
      }
    },
    "mapping": {
      "src/main.go": {
        "type": "file",
        "sha1": "…",
        "gitoid:sha1": "gitoid:blob:sha1:…",
        "posix": {
          "mtime": "2026-05-21T12:00:00Z",
          "owner_uid": "501",
          "permissions": "0644",
          "size": "4096"
        }
      },
      "src": {
        "type": "directory",
        "sha1": "…",
        "gitoid:sha1": "gitoid:tree:sha1:…"
      }
    }
  }
}
```

## Gotchas

- **Windows exclusion.** `omnitrail.go` carries `//go:build !windows`. Custom binaries built for Windows via `cilock build` silently omit this attestor; policies that require it will fail on Windows runners.
- **POSIX plugin is Unix-only.** Upstream `posix_plugin_unix.go` is gated on Unix; even on macOS/Linux the POSIX fields depend on filesystem support for the relevant syscalls.
- **No allow-list wiring.** The upstream `SetAllowList` hook exists but the cilock adapter never calls it — every file under the working directory is walked. Large workspaces produce large envelopes.
- **No tool detection.** This attestor records files, not toolchain binaries. Documentation that claims otherwise (including any prior version of this page) was wrong.
- **SHA256 off by default.** `NewTrail()` enables SHA1 unless an option flips SHA256 on; the cilock adapter passes no options.

## CLI example

Real omnitrail SBOM emission tied to a real material set.

```bash
cilock run --step omnitrail-emit \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations omnitrail \
  -- echo "captured omnitrail bom" 
```

Validated against a real material set. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/12-omnitrail](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/12-omnitrail).

## See also

- [Catalog row](../reference/attestor-catalog)
- Upstream: [witness/omnitrail.md](https://github.com/in-toto/witness/blob/main/docs/attestors/omnitrail.md)
- Library: [fkautz/omnitrail-go](https://github.com/fkautz/omnitrail-go)
