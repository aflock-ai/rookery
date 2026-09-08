---
title: command-run
description: The cilock command-run attestor records the executed argv, exit code, captured stdout/stderr, and an optional Linux ptrace forensic record, signed into in-toto evidence.
sidebar_position: 2
examples_repo: 01-command-run
---

Records the command `cilock run` executed — argv, exit code, captured stdout/stderr, and (when `--trace` is enabled on Linux) a per-process ptrace record of opened files, network activity, file mutations, and security-sensitive syscalls.

## What it captures

Top-level `CommandRun` fields (json tags from the struct):

- `cmd` — the argv slice that was executed.
- `stdout` — the verbatim stdout the process wrote (captured into a `bytes.Buffer` and stored as a string).
- `stderr` — the verbatim stderr, same mechanism.
- `exitcode` — the child's exit status.
- `processes` — populated only when `--trace` is on; one `ProcessInfo` entry per traced PID.

Each `ProcessInfo` carries: `program`, `processid`, `parentpid`, `programdigest`, `comm`, `cmdline`, `exedigest`, `exedigestSource` (what `exedigest` measures: `mapped-image` is SHA-256 of `/proc/<pid>/exe` read through a single descriptor, claimed only when the backend can PROVE both that the measured file is the image this exec mapped and that the image stayed write-protected across the whole measurement - today only the ptrace backend, which holds the tracee stopped at the execve return; `path-hash` means the value is a copy of `programdigest`, the bytes at the caller-named path when the tracer opened it, which is not proof of what executed; empty means unlabelled, never "mapped image"; a policy comparing `exedigest` against an image allowlist must require `mapped-image`), `exedigestDowngradeReason` (why a backend that would otherwise report the mapped image reported a path hash: `not-kernel-bound` - the exec event carries no kernel identity to bind the measurement to, which is the case for the eBPF backend because its execve event comes from a syscall-entry kprobe fired before the kernel resolves or maps anything, so that backend always downgrades; `unprotected-measurement` - write protection could not be GUARANTEED for the whole measurement, so the bytes hashed need never have executed. This covers the process no longer mapping the image (ETXTBSY lapses once the last executing reference goes away), running on Linux 6.11 or 6.12 where an in-place write to a mapped image is not ETXTBSY-denied, and being unable to determine the kernel version at all - an unknown answer downgrades exactly as a negative one does, because a producer that cannot tell whether writes were possible is in the position of one that knows they were. Empty means no downgrade. It exists so a verifier can tell "the producer declined to claim what it could not prove" from "this producer never populated the field"), `environ`, `specbypassisvuln`, `exitcode` (per-process exit status; for signal-terminated processes uses the shell convention `128 + signal_number`; absent/zero means "still running when trace ended"), `openedfiles` (a `map[path]DigestSet` populated from `openat` syscalls and re-resolved at trace end), plus three nested structures:

- `network` (`NetworkActivity`): `sockets[]`, `connections[]` (each with `syscall`, `family`, `address`, `port`, `fd`, `timestamp`, and `hostname` for TLS SNI from ClientHello on port 443), `dnsLookups[]`.
- `fileOps` (`FileActivity`): `writes[]` (path resolved via `/proc/pid/fd/N`), `renames[]`, `deletes[]`, `permChanges[]` (mode bits + `setExec`).
- `syscallEvents[]` — notable syscalls: `memfd_create`, `ptrace`, `mount`, `clone` (with namespace flags), `dup2` (socket→stdio = reverse-shell pattern), `mprotect` (PROT_EXEC), `prctl` (PR_SET_NAME / PR_SET_DUMPABLE / PR_SET_NO_NEW_PRIVS), `setsid`, `setns`, `init_module`/`finit_module`.

## When to use

Always — it's the spine of every `cilock run`. The only knob is `--trace`, which turns the attestor from "I ran this command and here is its stdio" into a forensic record of what the process did at the syscall level.

## Flags

| Flag | Shorthand | Default | What it does |
|---|---|---|---|
| `--trace` | `-r` | `false` | Sets `SysProcAttr.Ptrace = true` on the child and enables the ptrace loop in `tracing_linux.go`. No-op as a syscall hook on non-Linux but causes `trace()` to error. |

There are no `--attestor-commandrun-*` flags — `commandrun.init()` registers with no `registry.Configurer` options.

## Output shape

```json
{
  "cmd": ["go", "build", "./..."],
  "stdout": "...verbatim bytes the child wrote to stdout...",
  "stderr": "...verbatim bytes the child wrote to stderr...",
  "exitcode": 0,
  "processes": [
    {
      "program": "/usr/local/go/bin/go",
      "processid": 12345,
      "parentpid": 12344,
      "programdigest": {"sha256": "..."},
      "comm": "go",
      "cmdline": "go build ./...",
      "exedigest": {"sha256": "..."},
      "exedigestSource": "mapped-image",
      "openedfiles": {"/path/to/go.mod": {"sha256": "..."}},
      "environ": "GOFLAGS=... GOPATH=...",
      "specbypassisvuln": false,
      "network": {
        "sockets": [{"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0, "fd": -1}],
        "connections": [{"syscall": "connect", "family": "AF_INET", "address": "140.82.112.3", "port": 443, "fd": 7, "timestamp": "2026-05-21T12:00:00Z", "hostname": "proxy.golang.org"}],
        "dnsLookups": [{"serverAddress": "1.1.1.1", "serverPort": 53}]
      },
      "fileOps": {
        "writes": [{"path": "/tmp/go-build/main", "bytes": 4096, "timestamp": "..."}]
      },
      "syscallEvents": [{"syscall": "memfd_create", "detail": "...", "timestamp": "..."}]
    }
  ]
}
```

## Gotchas

- **`stdout` / `stderr` are raw bytes, not digests.** The attestor stores `stdoutBuffer.String()` and `stderrBuffer.String()` verbatim into the predicate. Large or sensitive output goes into the signed envelope as-is.
- **`--trace` is Linux-only.** On macOS / Windows, `tracing_unsupported.go` returns `errors.New("tracing not supported on this platform")` from `trace()` and the attestation fails. Don't pass `--trace` off-Linux.
- **Tracing needs `ptrace(2)`.** Default Docker drops it; you need `--cap-add=SYS_PTRACE` (and to not be under a restrictive seccomp profile). Kubernetes pods need an equivalent `securityContext.capabilities.add: [SYS_PTRACE]`.
- **`openedfiles` is populated from `openat`** — and digested at open time, with a retry pass at trace end (`retryOpenedFiles`) for files that didn't exist yet. Files opened-but-never-read still appear.
- **TLS SNI extraction is best-effort.** The tracer peeks the first write on any fd that connected to port 443 and parses the ClientHello for the `server_name` extension. Only one peek per fd; non-printable hostnames are discarded.
- **DNS detection is a heuristic** — any `connect()` to port 53 is recorded as a DNS lookup. Non-DNS traffic to port 53 will be misclassified.

## CLI example

Builtin. cilock always runs this — there's no `--attestations command-run` toggle. With `--trace`, captures ptrace-level syscall info per child process.

```bash
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json \
  --trace \
  -- make build 
```

Validated. Always part of every cilock run. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/01-command-run](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/01-command-run).

## See also

- [Catalog row](../reference/attestor-catalog)
- [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks)
- Upstream: [witness/command-run.md](https://github.com/in-toto/witness/blob/main/docs/attestors/command-run.md)
