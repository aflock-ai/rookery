# command-run attestor

Trace-based build attestation. Captures every file, syscall, fork,
and exec a wrapped command performs so a verifier can prove what
the command actually did — not what the caller claims it did.

## Version status

| Version | Status | Predicate URI |
|---|---|---|
| **v0.2** | producer (current) | `https://aflock.ai/attestations/command-run/v0.2` |
| v0.1 | verify-only (legacy) | `https://aflock.ai/attestations/command-run/v0.1` |

`cilock run --attestations command-run` always selects the v0.2
producer. Verifiers handed a v0.1 envelope route through `LegacyDecoder`
(registry name `command-run-v0.1`) automatically — see `legacy.go`.

## v0.2 — what changed from v0.1

The semantic content is the same; the wire format is reshaped.

### 1. Interned tables (the size win)

v0.1 stored every file path, comm, and digest inline per-process. A
`cilock` build with 100 compile workers each touching the same 200
glibc headers produced ~50 KB of duplicate path strings.

v0.2 promotes paths, digests, and comms to top-level interned arrays;
per-process records hold integer ids.

**Measured: 66.5% size reduction on a 100-process synthetic workload**
(see `TestV02_SmallerThan_V01`). Plan target was ≥50%.

```jsonc
{
  "_meta": {...},
  "summary": {...},
  "digests": [
    { "sha256": "abc...", "src": "trace-readtap" },
    { "sha256": "def...", "src": "fs-verity" }
  ],
  "paths": ["/usr/include/stdio.h", "/home/user/main.c"],
  "comms": ["gcc", "cc1", "ld"],
  "processes": [
    {
      "processid": 1234,
      "commId": 1,
      "openedFiles": [{ "pathId": 0, "digestId": 0 }]
    }
  ]
}
```

### 2. _meta block first

`_meta` is the leading top-level key. Operators and AI agents reading
a small prefix learn the document's shape, capture mode, trace
backend, and cardinality of every interned table without parsing the
rest:

```jsonc
"_meta": {
  "version": "v0.2",
  "captureMode": "trace",
  "traceBackend": "ebpf",
  "counts": {
    "processes": 100,
    "uniquePaths": 50,
    "uniqueDigests": 50,
    "uniqueComms": 3,
    "materials": 47,
    "intermediates": 2,
    "products": 1,
    "cacheArtifacts": 3
  }
}
```

### 3. Future-compatible shape

v0.3 (deferred to a future iteration) will drop the inlined `digests[]`
table entirely — digest references will resolve against material/product
attestations' merkle trees. The v0.2 schema is shaped for that without
reshape: digests are already their own top-level section, and no digest
*data* appears in per-process records (only ids).

### 4. Backwards compat

Every v0.1 attestation already in production keeps validating:

- `LegacyDecoder` (registry name `command-run-v0.1`) parses the v0.1
  predicate body.
- `Subjects()` synthesizes per-file subjects so policy-engine BFS
  matches by digest the same way it did against v0.1.
- `Attest()` refuses with `errLegacyDecodeOnly` so an accidental
  producer-mode invocation fails loudly. Only the v0.2 attestor
  produces new envelopes.

### What v0.2 does NOT yet include (deferred to follow-up commits)

| Feature | Why deferred |
|---|---|
| Column-packed events arrays (top-level `events[]` with delta-encoded timestamps + integer opcodes) | Schema supports adding without reshape; size win is already met by interning alone |
| Two-pass byte-offset section index (`_meta.sections` with exact ranges) | AI-traversal quality feature, not a size feature |
| `envDigests[]` interning | Same shape as `digests[]`; small win, follow-up |

## Trace attestor improvements (all versions)

Beyond the schema change, the trace attestor itself has gained
significant capability:

### eBPF tracer (V1.4 + V2)

- **Read-tap streaming SHA**: digests file content as the tracee reads
  it, race-free against the calling thread. Replaces the path-hash
  fallback that lost digests when fds closed before userspace could
  re-read. **Default-on in trace mode** (opt-out via
  `CILOCK_HASH_RACE_FREE=0`).
- **4-way file classification**: materials (read), intermediates
  (read + written), products (written, not read), cacheArtifacts
  (written to a known cache path) — populated from a single trace,
  no separate walk needed.
- **66 default cache patterns** covering Go, Python, Node, Rust,
  Java/Gradle, C/C++, Docker, Bazel, OS temp dirs. User-extensible
  via `--cache-add-pattern` / `--cache-allow-pattern`.
- **Process-tree visibility**: `raw_tracepoint/sched_process_fork`
  (BTF-aware, replaces the stale-on-5.x+ struct-args tracepoint) +
  clone-family kretprobes. Closes the deep-fork-chain gap where
  `gcc → collect2 → ld` linker output binaries went missing from
  the product set.
- **Syscall coverage** (kprobes + kretprobes where relevant):
  openat, openat2, read, pread64, write, pwrite64, close, execve,
  renameat (V2 — was missing), renameat2, unlinkat, fchmodat,
  socket, connect, bind, ptrace, mount, mprotect, prctl, setsid,
  setns, init_module, finit_module, clone, clone3, vfork, fork,
  dup2, dup3.
- **mmap-write synthesis**: `gcc`/`ld` write output via mmap, so
  `sys_write` never fires. V2 synthesizes a write event when
  `openat(O_WRONLY|O_CREAT|O_TRUNC|O_APPEND)` fires, ensuring
  products are still captured.
- **Relative-path resolution**: cc1/javac/Go-linker open files
  with relative paths under `AT_FDCWD`. V2 resolves them via
  `/proc/<pid>/cwd` at event-arrival time so the digest path is
  absolute regardless of tracee lifetime.

### Adversarial test coverage

Each test pins a specific weakness as a regression catch
(`tracing_weakness_test.go`):

- `TestWeakness_ForkChain_DeepWatchPropagation` — 4-deep
  fork-and-exec chain; asserts leaf openat captured with correct
  digest.
- `TestWeakness_DirectSyscall_Bypass` — inline-asm openat/read
  bypassing libc entirely. Proves the kprobe is at the kernel
  boundary, not at libc; an LD_PRELOAD-style userspace hook
  bypass cannot evade.
- `TestWeakness_WriteOnlyFd_NotHashedAsRead` — pins V1 fix that
  write-only fds aren't path-hashed as fake reads.
- `TestWeakness_PtraceAttempt_Captured` — pins SECURITY-event
  detection. A malicious tracee probing for debugger inhibition
  leaves the same ptrace fingerprint.

### Cross-language regression suite

`cross_lang_e2e_linux_test.go` drives REAL compiles in each language
under the eBPF tracer and asserts the 4-way classification:

| Language | Status |
|---|---|
| C++ (`g++` direct) | ✅ stable |
| Go (`go build` with module-local cache) | ✅ stable |
| C single-file (`cc` direct) | ⏭️ skipped — Phase 8 dispatcher race |
| C multi-file (`make`) | ⏭️ skipped — same race |
| Java | scaffolded with `t.Skip` on missing javac |
| Rust | scaffolded with `t.Skip` on missing cargo |
| Python (`pip install`) | scaffolded |
| Node (`npm install`) | scaffolded |

## Known limitations + Phase 8 work

The trace attestor today is reliable for compiled-language builds
that don't hit the deep dispatcher race documented in
`tracing_phase8_blockers_test.go`. Specifically:

- **~50% flake on deep fork chains** under sustained run (TestPhase8Blocker_ForkChainStability).
  Fix is the canonical-patterns rewrite — Tetragon-style hereditary
  fork insertion via `kprobe/wake_up_new_task` + `BPF_MAP_TYPE_TASK_STORAGE`
  for the watched bit.
- **0/100 children captured under hyper-fork load** (TestPhase8Blocker_HyperForkPool).
  Kretprobe slot pool (4096 default) exhausts. Same canonical-patterns
  rewrite fixes it.
- **mmap reads invisible**. Fixed via `fentry/security_file_open`
  (BPF-LSM, allowlists `bpf_d_path` for canonical absolute paths).
- **JVM classpath scanning** floods the ringbuf. Sharded consumer
  pool is the planned mitigation.

See `memory/ebpf-canonical-patterns.md` (in the Claude project memory)
and the V2 plan's Phase 8 section for the full canonical-patterns
migration ladder. Tests pinning each weakness live in
`tracing_phase8_blockers_test.go`, gated by `CILOCK_KNOWN_FAILING=1`.

## Files in this package

| File | Purpose |
|---|---|
| `commandrun.go` | v0.1 producer + CommandRun struct |
| `v2_marshal.go` | v0.2 wire-format emitter (this file's focus) |
| `legacy.go` | v0.1 verify-only decoder |
| `tracing_linux.go` | trace-mode entry point (eBPF / ptrace selector) |
| `tracing_ebpf_linux.go` | eBPF userspace dispatcher |
| `tracing_linux_test.go` | ptrace path tests |
| `tracing_ebpf_e2e_linux_test.go` | eBPF e2e tests |
| `tracing_weakness_test.go` | Phase 3 weakness-pinning tests |
| `tracing_phase8_blockers_test.go` | failing tests for Phase 8 canonical rewrite |
| `cross_lang_e2e_linux_test.go` | Phase 2 cross-language regression suite |
| `v2_marshal_test.go` | schema invariants (size, shape, dedup, legacy round-trip) |
| `ebpf/openat_consumer.go` | BPF program loader + decoder |
| `ebpf/bpf/openat_kprobe.bpf.c` | BPF source (kprobes, kretprobes, raw_tp, ringbuf) |
| `LEARNINGS.md` | working log of design decisions + cross-language findings |
