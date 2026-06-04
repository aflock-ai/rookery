---
title: Auto-detection and default attestors
description: CI/lock auto-detects which attestors to attach by inspecting the workspace and the wrapped command — but only when you don't pass -a. This page explains the default set, the --workload modes, and how to dry-run with --validate-only.
sidebar_position: 7
---

# Auto-detection and default attestors

`cilock run -- <command>` tries to do the right thing without a wall of flags. Two mechanisms make that work: a small **always-on default set**, and **detector-driven auto-attachment**.

## The default attestor set

Some attestors always run and cannot be turned off with `-a` (drop them only with `--no-default-attestor`):

- **`product`** and **`material`** — the input/output Merkle trees. Always on.
- **`command-run`** — the wrapped argv, exit code, and stdio digests.

Two more are on by default but are part of the `-a` list, so they're replaced if you pass your own `-a`:

- **`environment`** — OS, arch, working dir, (obfuscated) env vars.
- **`git`** — commit, branch, remotes, tag.

So a bare `cilock run -- go build ./...` already yields environment + git + command-run + material + product, signed.

## `--workload`: when detection runs

`cilock` can inspect the workspace (and the wrapped command's argv) and attach the attestors that match — `go-build` for a `go build`, `git` for a `.git/` directory, `sbom`/`sarif` for a tool that emits those formats, and so on. Whether that detection runs depends on `--workload` (default `auto`) **and** whether you passed `-a`:

| You ran | What you get |
|---|---|
| `cilock run -- go build ./...` (no `-a`) | Defaults **plus** auto-detected attestors (e.g. `go-build`). |
| `cilock run -a sarif -- trivy fs .` | **Exactly** `sarif` (+ always-on product/material/command-run). No detection. |
| `cilock run -a sarif --workload auto -- trivy fs .` | `sarif` **plus** auto-detected attestors. `auto` forces detection even alongside `-a`. |
| `cilock run --workload manual -- go build ./...` | Defaults only, **no detection** — `-a` (or its default) is the exact set. |

The rule in one sentence: **detection runs by default only when you don't pass `-a`; passing `-a` means "this exact set" unless you also say `--workload auto`.** This is so `cilock run -a sarif -- …` means what you wrote, while the zero-config path stays smart.

Detection rules live in the catalog (`detector.yaml` per tool), so the set of things CI/lock can auto-attach is exactly what [`cilock tools list`](../tools) shows. See [the detector catalog](../tools) for every rule, and [step categories](./step-categories) for how a detected tool also infers `--step`.

## `--validate-only`: dry-run the plan

Before committing a CI/lock invocation to CI, run it with `--validate-only`:

```bash
cilock run --validate-only -- go build ./...
```

It performs the pre-flight workload + tool-availability checks, prints the planned attestor set and any warnings, and exits **without running your command**. Use it to confirm detection picks what you expect.

## See also

- [How CI/lock captures files](./capture-modes) — walk vs trace vs fanotify (separate from *which* attestors run)
- [Step categories](./step-categories) — the lexicon and `--step` inference
- [Tools / detector catalog](../tools) — every auto-detection rule
- [CLI reference](../reference/cli) — `--workload`, `--validate-only`, `--no-default-attestor`
