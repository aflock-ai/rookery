---
sidebar_position: 8
title: High-assurance attestation
---

# High-assurance attestation (zero-drop mode)

For release builds where "the attestation is complete or it doesn't ship,"
CI/lock supports a zero-drop capture mode that combines kernel-synchronous
file hashing (fanotify), opportunistic Merkle-root sealing (fs-verity),
and a fail-closed verification gate. This page documents the flag matrix
and what each guarantee means.

## Quick start (release-grade)

```yaml
- uses: aflock-ai/cilock-action@v1.0.4
  env:
    CILOCK_FANOTIFY: "1"          # require synchronous file capture
    CILOCK_FSVERITY: "auto"       # opportunistic Merkle seal on products
  with:
    cilock-args: "--capture-mode trace:ebpf"  # require eBPF backend (fail loudly if unavailable)
    require-zero-drops: "true"     # reject attestation if any drops occurred
    attestations: "environment git github product sbom command-run"
    command: ./build.sh
```

The build will run measurably slower (a typical 60% overhead on small
workloads, less on builds dominated by compile time). In exchange you get:

- **Zero silent drops** on file content. Every open() under the workspace
  mount is hashed synchronously by the kernel-blocking fanotify handler.
- **Kernel-rooted product digests** when fs-verity is available on the
  filesystem. The kernel refuses to read corrupted blocks downstream.
- **Fail-closed verification** — if ANY drop / timeout / queue overflow /
  unhashed open occurred at end-of-trace, the attestation is rejected
  with a structured error.
- **Tracee privilege drop** — the build process runs as the invoker's
  user (via SUDO_UID), not root, even though CI/lock retains the
  capabilities it needs for kernel observation.

## Environment flag matrix

### `CILOCK_FANOTIFY`

| value | behavior |
|-------|----------|
| `` (unset) / `0` / `off` | Disabled. BPF-only capture (default). |
| `auto` | Probe for fanotify availability; activate if probe succeeds, fall back to BPF silently otherwise. |
| `1` / `on` | REQUIRE fanotify. Error if probe fails (e.g., CAP_SYS_ADMIN missing). |

**Capabilities:** CAP_SYS_ADMIN required. cilock-action's sudo path
provides this automatically on hosted GitHub Actions runners.

**Filesystem support:** ext4, xfs, btrfs (most production filesystems).
Probes both `FAN_MARK_FILESYSTEM` and `FAN_MARK_MOUNT`; one of them
works on every supported fs.

**Coverage limits:** see [Known gaps](#known-gaps) below.

### `CILOCK_FSVERITY`

| value | behavior |
|-------|----------|
| `` (unset) / `0` / `off` | Disabled. |
| `auto` | Probe FS at startup; opportunistically seal each product on close. |
| `1` / `on` | REQUIRE fs-verity availability. Error if FS doesn't support it. |

**Filesystem support:** ext4 with the `verity` feature flag enabled
at `mkfs` time (rare on hosted CI; common on Android, ChromeOS,
some private k8s clusters). Probe gracefully returns EOPNOTSUPP
otherwise.

### `--require-zero-drops` (CLI flag) / `WithRequireZeroDrops()` (API)

When set, the attestor returns a `ZeroDropsError` instead of
emitting the attestation if ANY of the following counters are
non-zero at end-of-trace:

| counter | meaning |
|---------|---------|
| `bpfOpenatDrops` | BPF ringbuf dropped openat events |
| `bpfReadtapDrops` | BPF ringbuf dropped read-tap chunks |
| `fanotifyTimeouts` | Handler took longer than 2s; kernel default-allowed |
| `fanotifyQueueOverflows` | Kernel emitted FAN_Q_OVERFLOW |
| `fanotifyCapHit` | Per-trace 200K digest cap reached |
| `unhashedOpens` | Files observed open but couldn't be hashed |
| `fallbackHashFailures` | Aggregate hash failures |
| `fsverityFailures` | Kernel ioctl returned error |

PartialReadFallbacks is explicitly NOT counted — partial reads are
correct behavior (the openat-time path-hash remains authoritative).

## Diagnostic surface

Every trace populates `summary.diagnostics` with these fields. Use
them in Rego policies, dashboards, or alerts:

```json
{
  "summary": {
    "diagnostics": {
      "fanotifyAvailable": true,
      "fanotifyEventsHashed": 2004,
      "fanotifyDigestsMerged": 198,
      "fanotifyTimeouts": 0,
      "fanotifyQueueOverflows": 0,
      "fanotifyDigestsCapHit": 0,
      "fsVerityAvailable": false,
      "fsVerityFilesSealed": 0,
      "fsVeritySealFailures": 0,
      "ringbufOpenatDrops": 0,
      "ringbufReadTapDrops": 0,
      "unhashedOpensTotal": 0,
      "fallbackHashFailures": 0
    },
    "fanotifyOnlyDigests": {
      "/usr/lib/ld-linux-x86-64.so.2": "ab12cd34..."
    }
  }
}
```

`fanotifyOnlyDigests` is the kernel-rooted digest for paths fanotify
hashed where no tracee process recorded an open — represents
BPF-missed events that fanotify still caught.

Each `SyscallEvent` carries a `digestSource` field tagging the
provenance per event:

| source | trust level |
|--------|-------------|
| `fanotify-open-time` | Kernel-synchronous hash; race-tight at open time |
| `openat-path-hash` | Hashed via `/proc/<pid>/fd` at openat time; small race window |
| `bpf-streaming` | Accumulated via sys_read kretprobe; what the tracee actually saw |
| `fanotify-only` | Look up in `summary.fanotifyOnlyDigests` |
| `` (empty) | No digest captured (mmap-read with no prior hash; zero-copy syscall) |

## Recommended policy.rego snippet

```rego
package cilock

default allow := false

allow if {
  count(violations) == 0
}

violations[msg] {
  diagnostics := input.predicate.summary.diagnostics
  not diagnostics.fanotifyAvailable
  msg := "release-grade attestation requires fanotify; CILOCK_FANOTIFY=1 not set or unavailable"
}

violations[msg] {
  diagnostics := input.predicate.summary.diagnostics
  diagnostics.fanotifyTimeouts > 0
  msg := sprintf("fanotify handler timeouts > 0 (got %d) — degraded attestation",
    [diagnostics.fanotifyTimeouts])
}

violations[msg] {
  diagnostics := input.predicate.summary.diagnostics
  diagnostics.ringbufReadTapDrops > 0
  msg := sprintf("BPF read-tap drops > 0 (got %d)", [diagnostics.ringbufReadTapDrops])
}
```

## Known gaps

These are documented in the trace metadata; verifier policy decides
whether to accept attestations with them:

1. **mmap-read content** — when a tracee opens a file then reads via
   page faults (JVM classpath, ld.so loader, memory-mapped DBs),
   fanotify hashes at open time. If the file mutates between open
   and the page fault, the digest is stale. The SyscallEvent for
   mmap surfaces the file path so verifiers can policy on it.
2. **Zero-copy syscalls** — `copy_file_range`, `splice`, `sendfile`
   transfer bytes kernel-side without firing fanotify or read-tap.
   The SyscallEvent records source + destination paths but no
   content digest.
3. **memfd_create / O_PATH opens** — no path to mark; not captured.
4. **Files outside the workspace mount** — fanotify marks one mount;
   system libraries on the rootfs come from BPF read-tap with its
   drop characteristics.

## Cost profile

Measured on a synthetic 200-file burst on Ubuntu 24.04 GHA runner:

| mode | hash completeness | overhead vs baseline |
|------|-------------------|----------------------|
| BPF-only | 86-99% (with ~1% wrong-digest cases) | baseline |
| BPF + fanotify | **100%** | ~60% on small workloads; less on compile-heavy |

The overhead amortizes on builds dominated by compute time. For a
typical Go monorepo build (~10s baseline), expect ~16s with
fanotify. For a kernel `make -j$(nproc)` build (~10 min baseline),
expect ~12 min — the per-open overhead is dwarfed by compile time.

## When NOT to enable fanotify

- Builds with extreme file open rates where the synchronous block
  overhead is unacceptable (e.g., Bazel's per-action sandbox setup
  that opens 100K+ files per action).
- Filesystems that reject FAN_MARK_FILESYSTEM AND FAN_MARK_MOUNT
  (rare; FUSE-mounted volumes).
- Environments without CAP_SYS_ADMIN (most non-sudo container
  workloads).

In these cases use the BPF-only path (default) and accept the
~1-4% drop rate. Surface `summary.diagnostics.ringbufReadTapDrops`
in your CI dashboard so you know when it's degrading.
