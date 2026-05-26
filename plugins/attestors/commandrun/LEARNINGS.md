# Trace-based attestation: design + cross-language findings

Working log of what we've learned building cilock's eBPF read-tap +
capture-mode V2 + 4-way file classification. Updated as we test
against more languages, build systems, and edge cases.

## TL;DR — current state

What's working:
- eBPF read-tap captures file content race-free against the calling
  thread on Linux 5.13+
- Zero ringbuf drops on a 28s parallel Go build with 256 MB ringbuf
- Zero digest mismatches on a 200-path random sample
- 1.47× overhead vs raw `go build`; 2.17× faster than ptrace
- 4-way classification (materials / intermediates / products /
  cacheArtifacts) populated from a single trace
- 66 default cache patterns covering Go, Python, Node, Rust,
  Java/Gradle, C/C++, Docker, Bazel, OS temp
- Env-var-driven cache discovery (XDG_CACHE_HOME, GOCACHE,
  CARGO_HOME, NPM_CONFIG_CACHE, ...)
- CLI: --capture-mode (auto/walk/trace), --cache-add-pattern,
  --cache-allow-pattern, --cache-disable-defaults,
  --cache-disable-env-probe
- Material attestor populated from trace via Finalize phase
- Backwards-compatible: walk mode reproduces v0.1 exactly

What's open:
- Process-tree visibility: deep linker chains (`gcc → collect2 → ld`,
  `cargo → rustc → ld`) don't fully propagate watched-ness; final
  output binaries sometimes missing from product set. See V1
  limitations section.
- JVM workloads (javac, java -jar): event volume from classpath
  scanning can stall the dispatcher on small ringbuf configurations
- mmap'd reads not captured (only opens)
- splice/sendfile/copy_file_range zero-copy paths not captured
- IMA / fs-verity integration: CaptureProbe slots exist but not yet
  wired
- Schema evolution (v0.2 with events array + digestTable + per-entry
  timestamps): documented in plan; deferred to a separate PR

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
sufficient for these workloads. The SIGSTOP/SIGCONT backpressure
watchdog was removed in the golden-path commit — it disrupted
deep fork chains (forks-in-flight completed with the wrong parent
state) and the right fix for ringbuf pressure on heavier workloads
is separate ringbufs for openat vs read-tap, not pausing the
tracee.

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
- Run with `--no-trace` to skip event capture entirely and just
  measure baseline build time — isolate which phase is slow.
- Add JVM cache patterns to defaults (`~/.cache/jdk/`, etc.).
- Long-term mitigation for JVM-class openat volume: separate
  ringbufs (task #115) so read-tap volume can't evict openat
  events.

### Other languages (pending)

- Python (pip install / running scripts) — to test
- Node.js (npm install / runtime) — to test
- Rust (cargo build) — to test
- Ruby — to test
- PHP — to test
- Go — already covered in detail above

## CI / release environments

How the trace + classification system interacts with common CI
runtimes and release tooling.

### GitHub Actions

- **eBPF availability**: hosted runners (Linux x64/arm64) ship
  kernel 6.x and support BPF programs with `CAP_BPF +
  CAP_PERFMON` granted via setcap. The cilock-action wrapper
  handles the setcap step. eBPF works on hosted Linux runners.
- **macOS/Windows runners**: no eBPF. Falls back to ptrace mode
  (Linux) or walk mode (macOS/Windows).
- **Self-hosted runners**: same as workstation; whatever kernel
  the host runs.
- **Memory**: hosted runners are 7 GB. Our 256 MB ringbuf is
  fine; the read-tap streaming hash data flow shouldn't exhaust
  it for typical CI builds.
- **CapBPF gotchas**:
  - The runner's `/sys/fs/cgroup` interactions sometimes trip
    BPF program load on older kernels. Our 5.13+ minimum
    covers all current hosted runners.
  - GH Actions sets `GITHUB_*` environment variables that should
    NOT be classified as cache — they're build state. Our
    cache patterns don't touch them.
- **Artifact upload integration**: cilock's product attestation
  could feed directly into the `actions/upload-artifact` step's
  attestation predicates. The path-set is already filtered to
  user-facing outputs.

### GitLab CI

- Similar story to GitHub Actions. Runners use Docker by default
  (which our `--cache-disable-env-probe` flag exists for —
  don't let the host's env vars leak into a containerized
  build's classification).
- `CI_PROJECT_DIR` / `CI_BUILDS_DIR` set the working dir. Our
  workingdir option honors `-d`.
- Shared runners often have `/cache/` mounted from S3 or similar
  — that path may not match our default patterns. Operators
  should add `--cache-add-pattern=/cache/**` per project.

### Bazel

- Hermetic by design: Bazel runs every action inside a sandbox
  (Linux: `linux-sandbox`, basically a private mount namespace
  + tmpfs overlays). Inside the sandbox, all paths look like
  `/tmp/bazel-out/...` or similar.
- Our trace sees the OUTSIDE view: the bazel-server process forks
  a sandboxed worker, the worker's syscalls happen against
  paths like `/tmp/bazel-sandbox/12345/external/...` — those
  resolve to absolute paths the kernel sees.
- **Cache pattern needed**: `**/bazel-out/**`, `**/bazel-bin/**`,
  `**/bazel-testlogs/**`, and `~/.cache/bazel/**`. Already in
  default patterns.
- Bazel's REMOTE cache (gRPC) doesn't write to disk locally —
  no file capture needed.
- Bazel + cilock + read-tap should "just work" for monorepo
  builds; the trace sees the full action graph naturally.

### Buck / Buck2

- Similar to Bazel but Meta-developed. Not yet in default
  patterns; add `**/.buck/**`, `**/buck-out/**` if testing.

### GoReleaser

- GoReleaser orchestrates `go build` × N (per GOOS/GOARCH),
  archives, signs, releases. Each `go build` step is what we'd
  trace; goreleaser itself is the parent.
- Best integration:
  ```bash
  cilock run --trace --capture-mode=trace \
    -- goreleaser release --clean
  ```
- The single attestation captures EVERY child `go build` plus
  the archive/upload steps. Products will include the final
  release binaries + the archive tarballs + checksums files.
- Caveat: goreleaser uploads to GitHub Releases via HTTP. Our
  trace sees the HTTP traffic as `connect()` + `write()` to a
  socket fd. The product set still cleanly excludes socket
  writes (we filter `socket:` and `pipe:` paths in
  recordEBPFWrite).

### CircleCI / Buildkite / Drone / Jenkins

- All Linux-runtime; same eBPF story as GitHub Actions self-hosted.
- Jenkins agents that run inside Docker need
  `--cache-disable-env-probe` to avoid the host's env vars
  influencing the container's cache classification.

### Nix builds

- Nix builds are heavily sandboxed (per-derivation chroot).
  The cilock process would need to wrap `nix-build` invocations
  at the top level; tracing inside the sandbox is restricted.
- Output paths are `/nix/store/<hash>-<name>/` — interesting
  category: products that are CONTENT-ADDRESSED by Nix itself.
  Could classify `/nix/store/**` as a special "nix-store"
  bucket distinct from products/cache.

### Containerized builds (BuildKit / docker buildx / kaniko)

- BuildKit runs each Dockerfile layer as a sandboxed exec.
- For attestation, the cilock invocation lives OUTSIDE the
  container build context. Tracing the `docker buildx build`
  command sees BuildKit's daemon activity but not the
  per-layer container internals (those are PID-namespaced).
- Provenance-style attestations live INSIDE BuildKit's own
  attestation mechanism (`provenance` plugin). Our trace would
  be complementary, not a replacement.

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

## Cross-language test results (preliminary)

Tested in colima Ubuntu 24.04 / kernel 6.8 against each language's
trivial build. Each row is one `cilock run --capture-mode=trace`
invocation. Counts come from the summary block.

| language | wall (ms) | processes | uniquePaths | materials | intermediates | products | cacheArtifacts | notes |
|---|---|---|---|---|---|---|---|---|
| Python (script) | 1448 | 1 | 47 | 32 | 0 | 0 | 0 | no build step; stdlib read only |
| Ruby (script) | 1477 | 1 | 293 | 137 | 0 | 0 | 0 | Ruby loads a LOT of stdlib at startup |
| Node (inline) | 1525 | 6 | 34 | 29 | 0 | 0 | 0 | V8 reads few files at startup |
| PHP (eval) | 1472 | 1 | 129 | 105 | 0 | 0 | 0 | |
| C single-file (make) | ~2000 | 5 | 124 | 50 | 2 | 0 | 1 | `hello` binary written via mmap; openat captured but missing in product set due to fork-tracepoint gap (see below) |
| C multi-file (make) | ~2500 | 9 | 123 | 40 | 4 | 0 | 1 | same gap — `prog` written by `ld` (collect2's child), not in watched set |
| Rust (cargo) | 1500 | 2 | 63 | 57 | 3 | 0 | 0 | cargo handled the build cache offline; the `target/debug/hello` binary not captured because of similar fork chain issue |
| Java (javac+jar) | (timeout 90s) | — | — | — | — | — | — | JVM event volume overwhelmed dispatcher; ringbuf drained but build hung. Needs investigation. |
| Go (cilock build, fully tested elsewhere) | 28100 | 4374 | 38162 | 26003 | 1371 | 1 | 455 | clean baseline; trace works end-to-end |

### Known issue: process tree visibility (V1 limitation)

For builds that spawn deep process trees (`gcc → collect2 → ld`,
`cargo → rustc → ld`, `javac → javac forked workers`), the final
linker / writer often isn't in the watched set when its openat
fires. Symptoms:

  - Final output binary missing from products
  - Build summary shows materials/intermediates correctly but
    products = 0 for compiled-language single-target builds

Root cause: the `sched_process_fork` tracepoint we added attaches
cleanly but doesn't always propagate watched-ness all the way down.
Possible issues:

  - Tracepoint args struct offsets need BTF-aware reading on some
    kernels (CO-RE relocation) — currently relying on hardcoded
    offsets that match Linux 6.8 but may shift
  - Some forks use `clone3` with flags that route through different
    paths in the scheduler — the tracepoint may not fire for all
    of them
  - Process exec'd via posix_spawn (a wrapper around vfork+exec)
    might not trigger sched_process_fork the same way

Workaround for V1: the synthesized-write-on-openat path captures
output paths when the OPENING process IS in the watched set
(intermediate compiled object files, all of which are produced by
compile workers that ARE captured). The FINAL link step often
misses because the linker is too deep in the process tree.

Follow-up actions:
  - Switch to `tp_btf/sched_process_fork` for BTF-aware reading
  - Add explicit `clone` / `clone3` kretprobes that grab the
    return value (= child pid) and add to watched_pids
  - Verify with `bpf_trace_printk` debugging which fork paths
    fire and which don't on our test workloads

### Pattern: simple scripts vs build pipelines

For pure script execution (Python, Ruby, Node, PHP one-liners):
the trace correctly captures stdlib reads as materials. No writes
because scripts produce stdout, not files. This is the EASY case
and works perfectly.

For builds with intermediate stages (C, Rust, Go):
- intermediates split is detected correctly when the compile
  worker IS in the watched set (we see .o written-and-read)
- products only show up reliably for tools whose top-level
  process writes the output directly (Go's `go build` writes the
  final binary in the linker subprocess, which IS captured;
  gcc's `collect2 → ld` writes outside the captured set)

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
