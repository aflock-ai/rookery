---
title: Store attestations in Archivista
sidebar_position: 2
---

# Store attestations in Archivista

[Archivista](https://github.com/in-toto/archivista) is the searchable evidence store CI/lock integrates with by default. This guide covers how to configure CI/lock to push signed attestations to it, and how to retrieve them later.

## When to use Archivista

Workflow artifacts (GitHub Actions / GitLab job artifacts) are fine for the first few weeks of adoption. Move to Archivista when you need:

- **Cross-team verification:** a release-gate workflow that fetches evidence about an artifact built last quarter, without rerunning CI.
- **Searchable history:** query by subject digest, predicate type, identity, or time window.
- **Long retention:** outlive your CI platform's artifact lifetime (typically 30–90 days).

## Two auth models

CI/lock supports two ways to authenticate to Archivista:

| Model | When to pick it |
|---|---|
| **Static API key** | Self-hosted Archivista with a long-lived service account; quick setup. |
| **OIDC (audience-bound)** | CI workflows with a short-lived OIDC token; no static credentials in the pipeline. |

The wire-level details below are taken from Cole's [`test-staging-cilock.yaml`](https://github.com/testifysec/dropbox-clone/blob/main/.github/workflows/test-staging-cilock.yaml) reference.

## Pattern 1: API key (raw CLI)

```bash
cilock run --step build \
  --enable-archivista \
  --archivista-server "$ARCHIVISTA_URL" \
  --archivista-headers "Authorization: $ARCHIVISTA_API_KEY" \
  --signer-file-key-path ./signing.key \
  --outfile attestation.json \
  -- go build ./cmd/myapp
```

The `--archivista-headers` flag accepts arbitrary HTTP headers in `Header: value` form, which is how the API key gets forwarded.

For TestifySec-hosted Archivista, the URL pattern follows `<platform-url>/archivista` (so `https://web.platform.testifysec.com/archivista`).

## Pattern 2: OIDC (cilock-action default)

When using `aflock-ai/cilock-action`, Archivista upload uses OIDC by default, no static API key in the workflow. The action requests a fresh OIDC token whose audience matches the Archivista server URL:

```yaml
- name: build
  uses: aflock-ai/cilock-action@v1.0.1
  with:
    step: build
    command: go build ./cmd/myapp
    attestations: environment git github sbom
    platform-url: ${{ env.PLATFORM_URL }}   # archivista URL derived from this
    # enable-archivista: true is the default
```

For the raw CLI inside a GitHub Actions step, fetch the OIDC token explicitly:

```yaml
- name: get oidc token
  id: oidc
  uses: actions/github-script@v7
  with:
    script: return await core.getIDToken("sigstore")
    result-encoding: string

- name: build
  run: |
    cilock run --step build \
      --enable-archivista \
      --archivista-server "$PLATFORM_URL/archivista" \
      --archivista-oidc \
      --archivista-audience "$PLATFORM_URL/archivista" \
      --signer-fulcio-token "${{ steps.oidc.outputs.result }}" \
      ...
      -- go build ./cmd/myapp
```

OIDC tokens are short-lived. **Fetch a fresh token before each step:** the dropbox-clone reference does this with a separate `actions/github-script@v7` step in front of every `cilock run`.

## Useful flags

| Flag | Purpose |
|---|---|
| `--enable-archivista` | Enable the Archivista sink. |
| `--archivista-server <url>` | Archivista server URL. Derived from `--platform-url` if omitted. |
| `--archivista-headers <h>` | Add an HTTP header (e.g. `Authorization: <token>`). Repeatable. |
| `--archivista-oidc` | Use OIDC auth instead of headers. |
| `--archivista-audience <aud>` | Audience claim for the OIDC token (typically the Archivista URL itself). |

All verified from `rookery/cilock/internal/options/run.go`.

## Verifying the upload

Each successful upload returns a **GitOID** that uniquely identifies the stored attestation. The `cilock-action` exposes it as a step output:

```yaml
- name: build
  id: build
  uses: aflock-ai/cilock-action@v1.0.1
  with:
    step: build
    command: go build ./cmd/myapp

- name: Print evidence GitOID
  run: echo "Stored at ${{ steps.build.outputs.git_oid }}"
```

For raw CLI: the `Stored in archivista as sha256:...` line appears in CI/lock's stderr at upload time.

## Querying stored evidence

Archivista exposes a GraphQL API, an HTTP API, and a CLI (`archivistactl`).

### Option A: archivistactl (upstream CLI)

The fastest way for ad-hoc queries. Source: [`in-toto/archivista/cmd/Readme.md`](https://github.com/in-toto/archivista/blob/main/cmd/Readme.md).

```bash
# Store
$ archivistactl store build.attestation.json
build.attestation.json stored with gitoid 4462a729...

# Search by subject digest (algorithm:value)
$ archivistactl search sha256:423da4cff198bbffbe3220ed9510d32ba96698e4b1f654552521d1f541abb6dc
Gitoid: 4462a729...
Collection name: build
Attestations: https://witness.dev/attestations/git/v0.1, .../environment/v0.1, ...

# Retrieve subjects for a stored attestation
$ archivistactl retrieve subjects 4462a729...

# Retrieve the full DSSE envelope
$ archivistactl retrieve envelope 4462a729...
```

`archivistactl` ships separately from CI/lock and is the canonical reader-side tool.

### Option B: GraphQL (programmatic)

The schema's top-level fields for evidence queries are `dsses(where: ...)` and `subjects(where: ...)`. The Go client's `SearchQuery` constant (used internally for digest-based lookups) is the reference shape:

```graphql
query($algo: String!, $digest: String!) {
  dsses(
    where: {
      hasStatementWith: {
        hasSubjectsWith: {
          hasSubjectDigestsWith: { value: $digest, algorithm: $algo }
        }
      }
    }
  ) {
    edges {
      node {
        gitoidSha256
        statement {
          attestationCollections {
            name
            attestations { type }
          }
        }
      }
    }
  }
}
```

Variables: `{"algo": "sha256", "digest": "1a2b3c..."}`. The same `hasSubjectDigestsWith` predicate works under `subjects(where: ...)` if you want subjects without the surrounding DSSE.

### Option C: HTTP endpoints (direct curl)

For tooling that doesn't want to depend on GraphQL:

```bash
# Upload (POST)
curl -X POST "$ARCHIVISTA_URL/v1/upload" \
  -H "Content-Type: application/json" \
  --data-binary "@attestation.json"
# → {"gitoid":"72d83847..."}

# Download (GET)
curl "$ARCHIVISTA_URL/v1/download/<gitoid>"
# → the raw DSSE envelope JSON

# Ad-hoc GraphQL POST
curl -X POST "$ARCHIVISTA_URL/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ subjects { edges { node { name subjectDigests { algorithm value } } } } }"}'
```

For the full schema, self-hosting setup, and the legacy ER diagram, see [`in-toto/archivista`](https://github.com/in-toto/archivista) and the upstream [`cmd/Readme.md`](https://github.com/in-toto/archivista/blob/main/cmd/Readme.md).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `archivista upload failed: 401` | OIDC token expired between fetch and use, or audience mismatch. Refresh the token before each step and confirm `--archivista-audience` matches the Archivista URL. |
| `archivista upload failed: 403` | API key doesn't have write permission for that Archivista instance. |
| Upload silently skipped | `--enable-archivista` not passed, or the platform-url default is set to a non-Archivista platform. |
| Successful run but no GitOID printed | Check stderr, successful uploads log `Stored in archivista as <gitoid>`. |
