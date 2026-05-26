# cilock-EBPF vs Linux IMA hash agreement

A short experimental cross-check from 2026-05-23 to validate cilock's
async eBPF hashes against the kernel's synchronous IMA measurements.

## Setup

Linux 6.8.0-100-generic (colima VM), IMA policy loaded at runtime:

```
dont_measure fsmagic=0x9fa0   # procfs
dont_measure fsmagic=0x62656572 # selinuxfs
dont_measure fsmagic=0x73636673 # securityfs
dont_measure fsmagic=0xf97cff8c # debugfs
dont_measure fsmagic=0x01021994 # tmpfs
dont_measure fsmagic=0x6e667364 # nsfs
dont_measure fsmagic=0xefa11    # bpf-fs
measure func=FILE_CHECK mask=MAY_READ gid=1000
```

Workload: `cilock run --trace -- go build hi.go` (the same workload
that produced the benchmark numbers).

## Results

After the trace produced 11,424 IMA measurements (mostly system noise
from the trace process and its descendants):

| outcome                                  | count |
|------------------------------------------|------:|
| cilock_EBPF hash == IMA hash             |   275 |
| cilock_EBPF hash != IMA hash             |    15 |
| cilock captured but IMA didn't measure   |   534 |
| IMA measured but cilock didn't capture   | 11189 |

275 files round-trip perfectly — eBPF + userspace SHA-256 produces
the same digest the kernel produced for the same file, byte-for-byte.

15 files mismatch. All 15 are Go build cache writes:
`/home/.../.cache/go-build/*-a` and `/tmp/go-build*/*_pkg_.a`. The
cilock-side hash for those is often `e3b0c44298fc1c14...` (SHA-256
of empty bytes), meaning the file was truncated when cilock opened
via the kretprobe-reported fd. The kernel hashed the file at-read-
time, inside the syscall, BEFORE returning — so IMA saw the post-
write content.

## What this proves

eBPF tracing produces correct hashes for stable files (input deps,
binaries, configs — anything not actively being written). For files
that the tracee or a sibling process is *mid-write*, our async
hashing pipeline races the writer no matter what we do in userspace:

- V1.2 fix (skip `O_WRONLY`) eliminates most races but not all
  (Go build cache reads its own writes through a different fd).
- V1.3 fix (`kretprobe` + `/proc/<pid>/fd/<fd>`) eliminates the
  path-reuse race but the page-cache flux race remains.

The only synchronous answer is to hash *inside* the syscall — either
fanotify `FAN_PRE_ACCESS` (userspace handler blocks the syscall) or
IMA (kernel hashes during read, exposes via xattr / measurement log).

## Cilock + IMA integration sketch

A future mode `CILOCK_TRACE_MODE=ebpf+ima` could:

1. Parse `/sys/kernel/security/ima/ascii_runtime_measurements` (or
   binary log via netlink for low-overhead streaming).
2. Build a `map[path]sha256` from IMA entries.
3. For each openat event from BPF: look up path in the map. If
   present, use the IMA hash (kernel-measured, race-free). Otherwise
   fall back to cilock-EBPF hashing.

Tradeoff: requires reading the IMA log (root or `CAP_DAC_READ_SEARCH`,
or specific xattr access via `getxattr(path, "security.ima")` if
the policy includes appraisal mode that writes the xattr).

Not a 2026 Q3 deliverable — recording as the architecturally-correct
path for race-free integrity attestation.
