---
title: configuration
description: The cilock configuration attestor captures the raw CLI flags, config file path, digest, and parsed contents that drove a run, signing them into in-toto evidence.
sidebar_position: 6
examples_repo: 06-configuration
---

Captures the cilock CLI flags and `.witness.yaml`-style config file that drove this run.

## What it captures

The attestor reads `os.Args` and the active config file directly — it does not call into cilock's option resolver, so it records the raw CLI surface, not post-resolution defaults.

- `flags` — map of flag name to value, parsed from `os.Args` up to (but not including) the `--` separator that delimits cilock args from the wrapped command. Handles `--flag value`, `-f value`, `--flag=value`, `-f=value`, and bare boolean flags (recorded as `"true"`). Leading dashes are stripped from keys.
- `config_path` — path of the config file actually read. Resolved from `-c` / `--config` in the parsed flags; falls back to `.witness.yaml` in the working directory. Only populated when the file was successfully opened.
- `config_digest` — SHA-256 digest set of the config file's raw bytes.
- `config_content` — the config file parsed as YAML into a generic `map[string]interface{}`. Omitted if YAML parsing fails.
- `working_directory` — the process working directory at attest time (`os.Getwd()`).

Environment variables are **not** captured by this attestor — see [`environment`](./environment) for that.

## When to use

Audit trails where "which flags and config file produced this attestation" needs to be provable after the fact. Most pipelines do not need it; reach for it when a single runner invokes cilock with varying configs and each variant's settings must be frozen alongside its attestation.

## Flags

None.

## Output shape

```json
{
  "flags": {
    "c": "policy.yaml",
    "step": "build",
    "trace": "true"
  },
  "config_path": ".witness.yaml",
  "config_digest": {
    "sha256": "..."
  },
  "config_content": {
    "run": {
      "step": "build",
      "attestations": ["git", "environment"]
    }
  },
  "working_directory": "/workspace"
}
```

All fields are `omitempty`; absent fields mean the corresponding source was missing or unreadable.

## Gotchas

- The flag parser is positional and naive: it does not consult cilock's option definitions. A value that happens to start with `-` (e.g. a negative number) will be treated as the next flag, not as the previous flag's value, and the previous flag will be recorded as `"true"`.
- `flags` reflects what was typed on the command line, not the resolved configuration. Defaults applied by cilock and values sourced from the config file are not merged into `flags`; consult `config_content` for those.
- The default config path is hard-coded to `.witness.yaml` (the upstream witness name), not a cilock-specific filename.
- If the config file exists but is not valid YAML, `config_path` and `config_digest` are still recorded but `config_content` is omitted.
- The file is read with the user-supplied path; secrets embedded in the config file will appear verbatim in `config_content` and contribute to `config_digest`.

## CLI example

Captures the cilock config file (`.witness.yaml` or `--config` path) when present.

```bash
# With a .witness.yaml in workingdir:
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations configuration \
  -- echo hi 
```

Validated. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/06-configuration](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/06-configuration).

## See also

- [Catalog row](../reference/attestor-catalog)
- [Configuration reference](../reference/configuration)
