# Production Validation Checklist — trace attestation + Merkle verification

Status legend: `[ ]` not yet validated · `[~]` partial · `[x]` validated · `[!]` known limitation, documented

Each item lists:
1. **What** we're validating
2. **How** to verify (concrete command or workflow ref)
3. **Acceptance** criterion (the pass bar)

---

## 1. Functional correctness — what gets attested

### 1.1 Products and materials
- [x] **gh CLI (Go, single product)** — `bin/gh` attested as the sole product.
  How: `colek42/cli@nk/cilock-smoke` smoke; run 26425519632.
  Accept: product treeSize == 1; material treeSize > 10000.
- [x] **npm install (heavy products)** — 591 files attested across `node_modules/` + 1 overwrite (`package.json`).
  How: local `TestTraceOutputs_NpmInstall_ManyProducts`; GHA: `cilock-action/.github/workflows/smoke-npm-install.yml` run 26426541224 on rc64+rc13.
  Result: local=591, prod=591 (exact match). Material treeSize=1285. Attestation 1.05 MB; trace duration 4.75s.
  Accept: ✓ product treeSize in [50, 50000]; ✓ overwrite tagged; ✓ express digest matches sha256.
- [ ] **Cargo build (Rust)** — single binary product, multi-MB.
  How: new smoke `smoke-cargo.yml`, target ripgrep or cargo new + cargo build.
  Accept: product treeSize == 1 for release builds; clean materials.
- [ ] **Maven / Gradle (JVM)** — single JAR + transitive deps in `~/.m2`.
  How: extend PetClinic capstone with cilock-action wrap.
  Accept: JAR product + reads from local repo as materials.
- [ ] **C / autotools** — multi-product `make install` (binary + man pages + headers).
  How: smoke against GNU hello or a small autotools package.
  Accept: product set matches `find prefix/ -type f` post-install.

### 1.2 Pre-existence + overwrite semantics
- [x] **Clean checkout, new product** — Source: `trace-pathhash`.
  How: gh CLI smoke (fresh checkout, no `bin/gh` pre-existing).
- [x] **Overwrite of pre-existing file** — Source: `trace-pathhash-overwrite`.
  How: local `TestTraceOutputs_PreExistingOverwrittenEmittedWithSourceTag`.
- [x] **Pre-existing, untouched** — NOT emitted as product.
  How: local `TestTraceOutputs_PreExistingUntouchedNotEmittedAsProduct`.
- [ ] **Incremental rebuild on GHA** — re-run smoke on top of cached `bin/gh`.
  How: GHA smoke variant that caches `bin/gh` across runs via actions/cache, then re-runs.
  Accept: product still attested with overwrite tag; digest matches new binary.

### 1.3 Atomic-rename builds
- [x] **Go atomic-rename** — `/tmp/go-build.../exe/a.out → bin/gh`, write-tap miss + stat-fallback rescues.
  How: local `TestTraceOutputs_AtomicRenameProducesProduct_WriteTapMissed`; gh CLI smoke.
- [ ] **Cargo atomic-rename** — `target/.rustcXXXXXX → target/debug/<bin>`.
  How: Cargo smoke (above).
- [ ] **GCC -o atomic-rename** — `gcc -o foo foo.c` opens `foo.tmpXXXXX` then renames.
  How: smoke compiling a small C file via `gcc -o`.

### 1.4 Content-bypass syscalls
- [x] **mmap-write (Go linker)** — write-tap blind, stat-fallback rescues with `trace-pathhash`.
  How: gh CLI smoke — link subprocesses have 0 sys_write events.
  See [[go-link-mmap-write-gap]].
- [!] **copy_file_range / splice / sendfile / vmsplice** — surfaced via zero-copy hooks, content NOT digested.
  Accept: entry exists in attestation with `WrittenContentLimited: true`.
- [!] **Memory-mapped reads (filemap_fault)** — content gap documented.

---

## 2. Merkle tree integrity

### 2.1 Schema correctness (v0.3)
- [x] **product/v0.3 envelope** — has `merkleRoot`, `treeSize`, `hashAlgorithm: sha256`, `construction: RFC6962`.
  How: `jq '.predicate.attestations[]? | select(.type | test("product/v0\\.3"))' payload.json`.
- [x] **material/v0.3 envelope** — same shape.
- [ ] **subject[] contains the tree subjects** — `tree:products` and `tree:materials` as in-toto subjects with digests matching `merkleRoot`.
  Accept: `jq '.subject[] | select(.name | endswith("tree:products"))'` returns a subject whose digest equals the predicate's `merkleRoot`.

### 2.2 Merkle root reproducibility
- [ ] **Recompute Merkle root from leaf list** — given the off-envelope leaf list (path + digest pairs), recompute RFC6962 root and assert it equals the predicate's `merkleRoot`.
  How: new test `merkle_reproducibility_test.go` — feed known leaves into `attestation.NewMerkleTree`, compare root.
  Accept: bit-exact match. **This is the load-bearing check that the off-envelope leaves haven't been swapped.**
- [ ] **Same leaves → same root, deterministic** — order independence per RFC6962.
  How: feed leaves in two orders, assert same root.
- [ ] **Empty tree** — treeSize=0 → defined-empty-root behavior matches RFC6962.

### 2.3 Inclusion proofs
- [ ] **Single-leaf inclusion proof verifies** — given one product, produce inclusion proof, verify with `transparency-dev/merkle/proof.VerifyInclusion`.
  How: extend `verify.go` test.
- [ ] **Tampered leaf rejected** — modify one digest, inclusion proof must fail.

---

## 3. cilock verify integration

### 3.1 Round-trip envelope verification
- [x] **DSSE envelope parses** — gh CLI smoke produces a parseable envelope.
- [ ] **`cilock verify` against attestation + product file** — verifier reads attestation, fetches leaf list (Archivista or sidecar), recomputes product Merkle root, compares against attestation root.
  How: `cilock verify --attestation /tmp/gh-build-attestation.json --product bin/gh` in a smoke step.
  Accept: exit 0; "verified" line in output; digest matches.
- [ ] **`cilock verify` rejects tampered product** — overwrite `bin/gh` post-attestation, verify must fail.
  Accept: exit non-zero; error mentions digest mismatch.
- [ ] **`cilock verify` rejects truncated leaf list** — drop one leaf, recomputed root won't match.
  Accept: exit non-zero.
- [ ] **`cilock verify --policy ...`** — policy check against subjects + materials list.
  Accept: subject-based policy enforcement works.

### 3.2 Compat: in-toto / sigstore consumer
- [ ] **`cosign verify-attestation`** can read our DSSE envelope.
  How: smoke step that calls cosign on the produced bundle.
- [ ] **`slsa-verifier`** rejects when expected.

---

## 4. Workload coverage matrix

| Lang | Toolchain | Build pattern | Status | Smoke ref |
|---|---|---|---|---|
| Go | go 1.26 | `go build -o bin/<x>` | [x] | gh-cli smoke |
| Node | npm 10 | `npm install <pkg>` | [x] | npm-install smoke run 26426541224 (rc64+rc13) |
| Rust | cargo | `cargo build --release` | [ ] | TBD |
| Java | Maven | `mvn package` | [ ] | TBD |
| Java | Gradle | `gradle build` | [ ] | TBD |
| C | gcc + make | `make && make install` | [ ] | TBD |
| C++ | cmake + ninja | `cmake --build` | [ ] | TBD |
| Python | pip | `pip install -t ./out <pkg>` | [ ] | TBD |
| Ruby | bundler | `bundle install` | [ ] | TBD |

Run each on **ubuntu-22.04** and **ubuntu-24.04** to cover both hosted-runner kernels.

---

## 5. Failure modes (must-detect)

### 5.1 Drops & gaps
- [x] **Zero-drop fanotify burst** — `TestZeroDropGate` + capstone harshness.
- [x] **`--require-zero-drops` fails when drops > 0** — fail-closed gate.
- [ ] **Missing fanotify (no CAP_SYS_ADMIN)** — graceful BPF-only fallback with diagnostic surfaced.
  Accept: `diagnostics.fanotifyAvailable: false` + reason in summary.
- [ ] **Process tree gap** — child process whose writes don't reach the trace (the gh linker scenario in production).
  Accept: surface as diagnostic OR rescued by stat-fallback.

### 5.2 Tampering
- [ ] **Mid-build file swap** — adversarial test: external process overwrites a product mid-build.
  Accept: write-tap captures last write digest OR overwrite tag fires; verifier detects mismatch with stable artifact.
- [ ] **Read-then-unlink (TOCTOU laundering)** — file deleted between open and our hash attempt.
  How: existing `UnhashedOpens` mechanism + tests.
  Accept: entry in `unhashedOpens[]` with reason; verifier surfaces.

### 5.3 Identity / signing
- [x] **Sigstore keyless OIDC** — gh CLI smoke produces a Fulcio cert.
- [ ] **Fulcio cert chain validates** — assert cert SAN matches GHA workload identity (`https://github.com/colek42/cli/.github/workflows/cilock-smoke.yml`).
- [ ] **Transparency log inclusion** — Rekor entry present + verifiable.
- [ ] **Replay protection** — verifier rejects when bundled cert's notBefore is in the future or notAfter past.

---

## 6. Performance & resource bounds

- [x] **gh CLI build: <1m overhead** — measured ~7-8s additional vs no-trace.
- [ ] **npm install: <30s overhead** — re-measure once GHA npm smoke runs.
- [ ] **Linux kernel defconfig: <10% overhead** — capstone harness.
- [ ] **prePaths walk cost** — bounded; degrade gracefully past 1M entries (currently caps at 1M, returns partial set).
  Accept: walk completes in < (workdir-file-count * 0.5ms) on a typical SSD.
- [ ] **Attestation payload size** — bound at ~5MB for typical builds.
  How: `wc -c /tmp/<attestation>.json`.
  Accept: < 20MB at p99 across workload matrix.

---

## 7. Capture-mode coverage

- [x] **eBPF mode** — primary path; gh CLI smoke uses it.
- [ ] **ptrace fallback** — when eBPF unavailable (older kernel, missing caps).
  Accept: smoke succeeds with `tracingMode: ptrace` in diagnostics; lower fidelity acknowledged.
- [x] **trace+fanotify mode** — exercised in gh CLI smoke (auto-upgrade with CAP_SYS_ADMIN).
- [ ] **walk-only mode** — when no tracing available at all.
  Accept: products attested via post-exec walk; materials NOT attested; diagnostic surfaces the degradation.

---

## 8. Compatibility & ergonomics

- [ ] **cilock-action @v1 docs** — link from action.yml to docs page covering inputs, modes, products glob.
  Owner: [[v1.0.5 docs]] task #74.
- [ ] **Witness/cosign migration story** — document the import shim path.
- [ ] **Schema migration v0.2 → v0.3** — verifier handles both predicates.
- [ ] **Default products glob explained** — workingDir/** documented with override examples.
- [ ] **CI examples in cilock-action README** — Go, Node, Rust at minimum.

---

## 9. Release gates (must be green before promoting v1)

Before tagging `v1.1.0` final (no `-rcN`):

1. [ ] All sections 1.x rows in §1 are `[x]` or documented `[!]`.
2. [ ] §2.2 Merkle root reproducibility test lands and runs in CI on every PR.
3. [ ] §3.1 cilock verify round-trip works end-to-end in GHA on the gh CLI smoke.
4. [ ] At least 5 of the 9 workload-matrix langs in §4 are `[x]`.
5. [ ] §5.1 drop + §5.2 tampering tests are part of release-gate CI.
6. [ ] §6 perf bounds measured & documented in release notes.
7. [ ] §7 ptrace + walk-only fallback smokes pass.
8. [ ] §8 docs landed at cilock-docs site.

---

## 10. Today's status (2026-05-25)

- Local validation: **strong** — 4 unit tests + real npm install integration test covering products + overwrite detection.
- Production validation: **good** — two end-to-end workloads on rc64+rc13:
  - gh CLI Go build (run 26426462406): 1 product / 12410 materials
  - npm install express (run 26426541224): 591 products / 1285 materials, attestation 1.05 MB
  - Local synthesized count = prod actual count = 591 (exact match)
- Verifier round-trip: **not yet exercised** — §3.1 is the next concrete gap.
- Merkle root reproducibility: **not yet a test** — §2.2 is the priority for the next session.

Diagnostics surfaced from npm smoke that need follow-up:
- `partialReadFallbacks: 39`, `fallbackHashFailures: 71`, `hashFailureSilentDrops: 68`
  Likely transient files npm creates+deletes during install. Investigate before release-grade promotion.

Next concrete steps in priority order:

1. Land the Merkle root reproducibility test (§2.2) — small, high-leverage.
2. Wire `cilock verify` into the gh CLI smoke (§3.1) — proves the verifier round-trip.
3. Investigate npm install silent-drops (`hashFailureSilentDrops: 68`) — likely lock-journal race.
4. Add Rust + JVM smoke workflows (§4) — broadens language coverage.
5. Tampering adversarial test (§5.2) — single most important security check.
