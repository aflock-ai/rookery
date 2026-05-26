# Experiment: tap-the-reads for race-free hashing

Bandwidth + correctness measurements to derisk the proposed "tap
`vfs_read` and hash the bytes the kernel returned to the tracee"
design from the cilock-EBPF + IMA conversation.

Measured 2026-05-23 on colima VM (4 vCPU, 8 GB, kernel 6.8) via
bpftrace.

## What we'd hash

A `vfs_read` kprobe tap would stream bytes through the BPF ring buffer
to userspace, where we incrementally SHA-256 per `(pid, fd)` and
finalize on close. Numbers below show the bandwidth we'd push.

### Tiny workload (`go build hi.go`, ~4 s)

bpftrace on `vfs_read`, filtered to comm in {go, compile, asm, link, cgo}:

| metric                              | value          |
|-------------------------------------|----------------|
| file reads (S_IFREG fds)            | **4,598 reads / 89.3 MB** |
| pipe reads (S_IFIFO fds)            | 124 reads / 230 KB |
| socket / other reads                | 0 / 0 |
| total openats (for context)         | 4,872 |

**Almost everything is file reads.** Pipe + socket reads contribute
< 0.3% — filtering by fd type in the BPF program (skip non-S_IFREG)
saves nothing material.

Read size distribution: bimodal — many 1–8 KB reads (header/metadata
parses) and a big tail at 32–64 KB (full-block reads of `.a` and
source files). 18 KB average.

### Medium workload (`go build ./cmd/cilock`, ~50 s — full rookery monorepo)

| metric                              | value          |
|-------------------------------------|----------------|
| file reads                          | **156,509 reads / 2.66 GB** |
| pipe reads                          | 3,629 / 1.6 MB |
| total openats                       | many thousand |

**2.66 GB through ringbuf for a 50 s build = ~55 MB/s sustained.** That's
inside ringbuf's capability (consumer can drain at 100+ MB/s on a 4-core
host) but it doubles the memory bandwidth used by the build itself —
plausibly causing a measurable wall-clock slowdown beyond the BPF setup
cost we already see.

## Per-event overhead

At 18 KB average read, each event is small enough that the ringbuf
per-event cost is dominated by the data copy, not the metadata header.
At 156k reads / 50 s = ~3,100 events/sec — well below ringbuf saturation
(ringbuf comfortably handles 100k events/sec+).

The CPU cost on userspace is bounded by SHA-256 throughput, ~500 MB/s
per core. With 4 workers (current cilock hasher pool), we can hash at
2 GB/s aggregate. Plenty for 55 MB/s ingress.

## Correctness

Tap-the-reads gives byte-equivalent content to what the tracee saw —
the kernel `copy_to_user` step delivers the same bytes to both
destinations. If the file is rewritten mid-read, our hash reflects
the bytes the tracee actually got, not the post-rewrite content.

This is the fundamental win vs the current async-re-read approach,
which races: even fix-#2 (kretprobe + /proc/fd/) doesn't fix the case
where a third party rewrites the file's page cache while our hasher is
mid-read. The IMA cross-check measured 15/290 such mismatches on the
hi.go workload — small but nonzero.

## The real cost: memory bandwidth

For a CI build that's already memory-bound (compilers are), pushing
2.6 GB through ringbuf could cost 10–30% of wall-clock just from cache
pressure. We won't know without a head-to-head A/B.

## Mitigations worth implementing

In rough priority order — combine for best UX:

1. **`security.verity` xattr lookup first** (~30 lines). If the file has
   an fs-verity Merkle root in the xattr, use it directly — kernel
   already computed it once at "enable verity" time and verifies on
   every read. Zero ringbuf cost, zero race. Static deps (golang
   stdlib, signed shared libs) increasingly ship this way.

2. **Inode-keyed dedup**. The same `_pkg_.a` file gets read N times
   by N compile subprocesses; we should hash it once per `(dev, ino,
   mtime)`. Userspace map keeps the digest, returns it for any
   subsequent open of the same inode. Could cut bandwidth ~10x on a
   build that does lots of cross-module compilation.

3. **Size cap**. Files larger than some threshold (32 MB?) skip the
   read-tap and fall back to path-based hashing with a
   `oversized: true` flag in the attestation. Honest tradeoff.

4. **Static-tree exemption.** Paths matching `/usr/lib/**`,
   `/usr/bin/**`, container-image-root paths — never modified during
   builds. Hash via path (or fs-verity); skip tap.

5. **`vfs_read` filter on i_mode in the BPF program**. Already
   measured: gains < 1% on Go builds (no socket reads, negligible
   pipe reads). Skip — not worth the BPF code complexity.

## Recommended design

```
mode A: openat-only (current)            — fast, race-prone
mode B: openat + verity xattr probe      — fast, race-free for verity'd files only
mode C: openat + read-tap (new)          — race-free, +~25% wall-clock estimate
mode D: openat + read-tap + verity probe — race-free where verity exists,
                                            race-free elsewhere too, faster than C
```

cilock would default to mode A (back-compatible). `CILOCK_HASH_RACE_FREE=1`
opts into mode D. Container/CI deployments that care more about
attestation strictness than wall-clock pick D.

The page-cache walk approach (read all pages at fd close, dedup in
userspace) was considered but BPF page-cache xarray traversal is hard
to verify and gains nothing meaningful over the read-tap (same total
bandwidth, slightly fewer events).

## Open questions for prototyping

- Does ringbuf back-pressure correctly when hash workers fall behind?
  (Probably yes — `ringbuf.Reader` blocks the producer when full —
  but worth measuring.)
- Sleepable-LSM equivalent? `security_file_open` lets us read pages
  synchronously in a sleepable BPF program — might be cheaper than
  tapping every read.

## Coverage caveat: zero-copy paths

A `vfs_read` kprobe MISSES bytes that move through the kernel via
zero-copy syscalls — they never touch a userspace buffer:

- `splice(2)` — uses `do_splice_direct` directly
- `sendfile(2)` / `sendfile64(2)` — uses `do_sendfile`
- `copy_file_range(2)` — uses `vfs_copy_file_range`

Measured on the same workloads:

| tool                | vfs_read | copy_file_range | splice | sendfile |
|---------------------|---------:|----------------:|-------:|---------:|
| `cp /usr/bin/go`    |        7 |               2 |      0 |        0 |
| `dd if=... bs=64K`  |       11 |               0 |      0 |        0 |
| `go build hi.go`    |    6,375 |               2 |      0 |        0 |

Go barely uses any zero-copy paths (2 `copy_file_range`s out of 6k+
reads on the hi.go build). For Go-centric workloads, `vfs_read`-only
coverage is sufficient. For tools that rely on zero-copy (`tar` with
extraction, `rsync`, container image layer copies, NFS), we'd also
need kprobes on:

- `vfs_copy_file_range`
- `do_splice_direct`
- `do_sendfile`

All three deliver bytes the tracee or its peer "consumed" without
ever passing through `vfs_read`. Worth adding to V2 if container-
image-building workloads (`buildah`, `apko`) become common.
