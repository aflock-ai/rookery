# Trace-based attestation: design + cross-language findings

Working log of what we've learned building cilock's eBPF read-tap +
capture-mode V2 + 4-way file classification. Updated as we test
against more languages, build systems, and edge cases.

## Architecture decisions

### Read-tap over path-hash

- The kernel copies file bytes to the tracee via `copy_to_user` once.
  A BPF kretprobe on `sys_read` can read those bytes from the user
  buffer via `bpf_probe_read_user` BEFORE the tracee thread resumes.
- This is **race-free against the calling thread** (it's still blocked
  in kernel context). It's NOT race-free against sibling threads
  sharing the address space — but for build workloads (compilers
  don't write to their own read buffers) this is acceptable.
- Full tamper-resistance against sibling threads would require
  hooking the inlined kernel copy primitives. On Linux 6.8 these are
  all `notrace` or inlined; not achievable.

### Capture-mode auto-detection

- Default is `auto`. Resolves to `trace` if any registered attestor
  intends to provide trace data (command-run with `--trace`),
  otherwise `walk`.
- Walk mode is the legacy v0.1 behavior — preserved bit-for-bit.
- Trace mode short-circuits the material/product attestor walks
  (which would do redundant disk I/O the trace already covered).
- Fail loudly: `--capture-mode=trace` without `--trace` errors
  explicitly. No silent downgrade.

### 4-way file classification

Files the tracee touched fall into one of four buckets:

| bucket | rule | example |
|---|---|---|
| **material** | read by tracee | `/usr/include/stdio.h`, source files |
| **intermediate** | written AND read by tracee | Go's `_pkg_.a`, C's `*.o` files |
| **product** | written, NOT read, NOT cache | the final binary in cwd |
| **cacheArtifact** | written, NOT read, matches cache pattern | `~/.cache/go-build/*`, `/tmp/*` |

The classification surfaces in the command-run summary's `totals`
block for AI agents to scan without loading per-attestation merkle
trees.

### Cache pattern sourcing (priority order)

1. **Hardcoded defaults** (`DefaultCachePatterns()`) — 66 globs
   covering Go, Python, Node, Rust, Java/Gradle, C/C++, container
   builds, IDE state, OS temp roots
2. **Runtime env-var discovery** (`SystemCachePathsFromEnv()`) —
   reads `XDG_CACHE_HOME`, `GOCACHE`, `GOMODCACHE`, `CARGO_HOME`,
   `PIP_CACHE_DIR`, `NPM_CONFIG_CACHE`, `YARN_CACHE_FOLDER`,
   `PNPM_HOME`, `CCACHE_DIR`, `GRADLE_USER_HOME`, etc. Catches
   operators who redirect caches via env vars.
3. **User-added patterns** (`--cache-add-pattern`, repeatable)
4. **User-allowed patterns** (`--cache-allow-pattern`, removes
   from the effective set)

Disable knobs:
- `--cache-disable-defaults` (sealed-environment builds)
- `--cache-disable-env-probe` (containerized builds where host
  env vars shouldn't influence classification)

## Performance findings (from stress tests on cilock build itself)

| metric | walk mode | trace mode (auto) |
|---|---|---|
| material attestor | 1.20 s | 11 μs (skip + finalize) |
| product attestor | 1.20 s | 0.14 s |
| ringbuf drops | n/a | 0 (256 MB ringbuf is enough) |
| digest mismatches | n/a | 0 / 200 sampled paths |
| wall vs raw `go build` | n/a | 1.47× overhead |
| wall vs ptrace mode | n/a | 2.17× faster |

The 256 MB ringbuf + zero-copy `bpf_ringbuf_reserve` path was
sufficient — no need for the SIGSTOP/SIGCONT backpressure watchdog
(left in as opt-in `CILOCK_HASH_BACKPRESSURE=1` for adversarial
producer workloads).

## Per-language findings

### C / make (status: working, simple)

Tested: trivial `hello.c` + Makefile with separate compile + link.

Observations:
- Build creates `hello.o` (intermediate — written then read by linker)
  and `hello` (product — written, never read).
- Make itself spawns sub-shells; we capture them via the watched
  pid tree.
- `gcc` opens system headers (`/usr/include/...`) as materials.
- Total scale: 6 processes, 119 unique paths, 50 materials.

Caveats:
- If the build output lives in a path matched by a default cache
  pattern (`/tmp/**`, `**/.cache/**`), it gets classified as cache
  rather than product. Operators should either build in cwd or use
  `--cache-allow-pattern` to reclaim specific output paths.
- Object files (`*.o`) are correctly classified as intermediates
  in a single-pass make. In a multi-stage build that builds the
  `.o` once and links many binaries, the `.o` would be a write-and-
  read across multiple processes — still intermediate.

### Java / javac + jar (status: blocked, JVM event volume)

First test attempt hung for 4+ minutes on `javac Hello.java && jar
cf hello.jar Hello.class`. The JVM's classpath scanning opens
thousands of class files in its rt.jar / jmods at startup; event
volume swamped the dispatcher. Need to retest with isolation +
possibly tune for high-frequency openat workloads.

Hypothesis: each JVM startup opens 5-10K class files. For each:
openat event (~4KB) + read-tap events (~16KB each). Easy to push
through 100 MB of ringbuf traffic.

Action items:
- Run with `--no-trace` to skip read-tap and just count opens —
  isolate which phase is slow.
- Try enabling `CILOCK_HASH_BACKPRESSURE=1` to prevent ringbuf overflow.
- Add JVM cache patterns to defaults (`~/.cache/jdk/`, etc.).

### Other languages (pending)

- Python (pip install / running scripts) — to test
- Node.js (npm install / runtime) — to test
- Rust (cargo build) — to test
- Ruby — to test
- PHP — to test
- Go — already covered in detail above

## Build systems (pending exploration)

- **Bazel**: hermetic builds with sandbox; the trace would see Bazel's
  worker processes, action graph execution, output_base writes
- **Complex Makefiles**: multi-target, parallel `-j` builds, recursive
  make
- **CMake + Ninja**: CMake generates Ninja files; Ninja drives the
  build. Two-stage process: configure + build.
- **Buck/Buck2**: similar to Bazel
- **Maven multi-module**: parent + child modules, dependency-driven
  classpath
- **Gradle multi-project**: daemon-based, incremental compilation,
  worker threads
- **Vite / Webpack / esbuild**: JS bundlers, lots of small reads + writes
- **Cargo workspaces**: multi-crate, shared target/ dir
- **dune** (OCaml), **mix** (Elixir), **sbt** (Scala), **stack** (Haskell)
- **`make -j N`** parallelism: how does our trace scale with multi-process
  compile workers?

## Open questions

1. **Source dir vs cache dir for Maven local repo**. `~/.m2/repository`
   is dependency *source* (inputs), not cache. We don't include it in
   default cache patterns. Same call needed for Cargo's
   `~/.cargo/registry/src/` — it's source, not just cache. The DEFAULTS
   correctly distinguish: `**/cargo/registry/cache/**` is cache,
   `**/cargo/registry/src/**` is borderline. May need policy guidance.

2. **fs-verity / IMA fallback**. Roadmap items but not implemented.
   When IMA is available on a host (with active policy), it provides
   kernel-trusted measurements that are stronger than read-tap. The
   `CaptureProbe` interface has a slot for `CaptureIMA` that's
   reserved but unused.

3. **Schema evolution**. Today the command-run/v0.1 attestation has
   processes[].openedfiles as `map[path]DigestSet`. For very large
   builds (~80K paths across ~4000 processes) this duplicates digests.
   A v0.2 schema could deduplicate via a top-level digestTable and
   per-process refs. Not blocked anything yet; defer until measured
   need.

4. **Per-event timestamps**. We capture timestamp on each BPF event
   but only retain the deduplicated path → digest map. For TOCTOU
   detection across a single build (same path read twice with
   different digests), we'd want a temporal event log. Schema impact
   makes this a v0.2 candidate.

## V1 limitations to document for users

- **Sibling-thread VM race**: documented, kernel-level fix not available
- **mmap'd files**: page faults don't fire our read kprobe. We see
  the openat but no content stream. Future: hook `filemap_map_pages`
  or use the path-hash fallback for mmap'd files.
- **`splice/sendfile/copy_file_range`**: zero-copy paths bypass our
  read kprobe. Acceptable for Go builds (uses regular reads) but
  matters for `tar` extraction, `rsync`, container layer copies.
- **Process-exit without close**: kernel auto-closes; our `sys_close`
  kprobe doesn't fire. End-of-trace sweep covers this.
- **Build cache files**: classified as cache, not products. Default
  for most use cases. Operators wanting them as products use
  `--cache-allow-pattern`.
