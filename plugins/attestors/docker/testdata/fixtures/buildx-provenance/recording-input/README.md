# buildx-provenance recording input

This is the source tree `record.sh` copies into `.record-work/` before driving a
real `docker buildx build` under cilock.

`Dockerfile` pins its base image **by digest**:

    FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

(`docker.io/library/alpine:3.20` as of the recording, 2026-05-29). Pinning by
digest makes the SLSA build material reproducible — the `materialdigest:` /
`materialuri:` subjects are derived from this exact digest, so they do not drift
between re-records as long as the pin is unchanged.

## liveClass: rerunnable (network needed to pull the base)

`record.sh` re-runs deterministically against this pinned digest: the
`buildx.build.provenance.materials` (the base image) and the `image.name` are
stable. Two volatile fields appear in the metadata JSON but are NOT consumed by
the docker attestor (it parses only `containerimage.digest`, `image.name`, and
`buildx.build.provenance`), so the attestor's PREDICATE is reproducible:

  - `buildx.build.ref` — a per-build BuildKit run id (parsed into BuildInfo.BuildRef but never emitted)
  - `containerimage.descriptor.annotations."org.opencontainers.image.created"` — build timestamp (not emitted)

Note `containerimage.digest` itself shifts per build because the SLSA provenance
attestation manifest embeds a timestamp, so the manifest-list digest changes.
That digest is frozen in the committed `metadata.json` (the replay source) and
in the committed recorded `attestation.json`, so the hermetic replay and the
recorded-evidence cross-check both stay byte-identical. A fresh `record.sh` run
will produce a new image digest and a matching `attestation.json` + `metadata.json`
pair — re-record both together.

Re-running requires network to PULL the pinned base image if it is not already
present in the local docker image store, and a `docker-container` buildx builder
(the legacy `docker` driver cannot emit `--provenance`).
