# cilock hang repro harness

Two halves that reproduce the CI attest hang fast:

- **colima half** (`run.sh` + `probe.sh` + `Makefile`): runs a cilock attest
  scenario in a privileged Linux container and dumps process **State** +
  kernel stack if it outlives the watchdog. `D` = uninterruptible
  (SIGKILL-immune), `S` = a network wait (the client lacks a deadline),
  `R` = busy loop.
- **GitHub-Actions half** (`.github/workflows/cilock-hang-repro.yml`,
  `workflow_dispatch`): runs the same probe on the self-hosted runner — the
  only place the ambient GitHub OIDC → platform Fulcio keyless path exists.

## What it found (2026-06-09)

`offline` → clean (<1s); `stall` → TSA call errors bounded; staging upload
client bounded 120s; OIDC fetch bounded 30s. The one **unbounded** network op
was the gRPC `CreateSigningCertificate` (default keyless path, `UseHTTP=false`):
the run context is signal-cancellable but not time-bounded, so a stalled Fulcio
gRPC endpoint parked `cilock run` forever and the retry loop never engaged. Fix:
per-call `context.WithTimeout` in `plugins/signers/fulcio/fulcio.go`.

## Loop

    make cilock          # rebuild linux binary from source
    make stall           # ~5s: prove the deadline bounds a black-hole endpoint
    make loop S=offline  # rebuild + run in one shot
