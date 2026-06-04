---
title: How CI/lock captures files (walk, ptrace, fanotify)
description: CI/lock determines a step's materials (inputs) and products (outputs) by directory walk, syscall tracing (ptrace+seccomp, or eBPF where available), and fanotify content hashing — this page explains each, how to select it, and the tradeoffs.
sidebar_position: 6
---

# How CI/lock captures files

The [`material`](../attestors/material) and [`product`](../attestors/product) attestors don't decide *how* the file set is gathered — they commit a Merkle root over whatever set the **capture pipeline** hands them. `--capture-mode` picks where that set comes from:

| `--capture-mode` | Source | Platform |
|---|---|---|
| `walk` | Directory snapshot before (materials) and after (products) the command | All (Linux, macOS, Windows) |
| `trace` | Syscall tracing — what the process actually opened and wrote (requires `--trace`) | Linux |
| `auto` (default) | Trace events when `--trace` is on, otherwise the walk | — |
| `ima` | Kernel IMA measurements (requires `CONFIG_IMA`) — **not yet wired**, reserved for a future release | Linux |

On top of whichever mode is active, **fanotify** can supply kernel-synchronous content hashes; it's controlled by `--hardening`.

## Directory walk (the portable default)

Without `--trace`, CI/lock records artifacts by walking `--workingdir`:

- **Materials** — every regular file present *before* the command runs is hashed (sha256), bounded to the working directory, honouring `--dirhash-glob`. The input baseline.
- **Products** — after the command exits, files that were created or changed during the command window become products. CI/lock uses mtime to catch byte-identical rebuilds a pure content diff would miss.

The walk is simple, deterministic, and works everywhere, but it sees only the *net* before/after state of the working directory — not what the process actually touched, and nothing outside `--workingdir`.

## Syscall tracing (what the process actually did)

On Linux, `--trace` observes the process tree's syscalls so CI/lock knows *which* files were opened (inputs) and written (outputs) — including files outside the working directory — instead of inferring it from a snapshot. There are two backends, selected with the optional `:<backend>` suffix on the trace capture mode:

- **`ptrace+seccomp`** — the portable, always-available backend. A seccomp filter traps the file-relevant syscalls and CI/lock inspects them via `ptrace`. This is what most runs use in practice.
- **`eBPF`** — a CO-RE eBPF program that observes the same events with less per-syscall overhead, used **when the kernel supports it**.

`--capture-mode trace:auto` (the default when `--trace` is on) probes eBPF and, if it isn't available, **silently falls back to `ptrace+seccomp`** — so tracing works either way. `--capture-mode trace:ebpf` forces eBPF and fails loudly if it can't load; `--capture-mode trace:ptrace` skips the probe and uses ptrace directly.

> eBPF availability varies a lot by host. On many CI runners the eBPF object can't load (kernel/BTF skew or missing capabilities), so `auto` lands on ptrace+seccomp. Use `--diagnose` to see which backend was chosen and why.

## fanotify (kernel-synchronous content)

Tracing reports *that* a file was opened or written; **fanotify** supplies the actual *content hash* at the moment it happens, which is race-tight against a file that's modified again later in the build:

- **Materials** are hashed at `FAN_OPEN_PERM` time (each inode hashed once via `FAN_MARK_IGNORE`).
- **Products** are hashed at `FAN_CLOSE_WRITE`, then anchored to the set that still exists at process exit.

fanotify is enabled by `--hardening standard` (the default) and required by `--hardening strict`; toggle it directly with `CILOCK_FANOTIFY`.

## Choosing a mode

- **Local / portable / non-Linux:** the default walk is fine — `cilock run -- <cmd>`.
- **CI on Linux, accurate input/output attribution:** add `--trace`. `--capture-mode auto` uses tracing when available (eBPF if the kernel allows, else ptrace+seccomp) and falls back to the walk otherwise.
- **Release-grade, fail-closed:** `--hardening strict --trace` requires fanotify + fs-verity and fails on any dropped event (`--require-zero-drops`).

See the [`material`](../attestors/material) and [`product`](../attestors/product) attestor pages for the predicate each emits, and the [CLI reference](../reference/cli) for every capture flag.
