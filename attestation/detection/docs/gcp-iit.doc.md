---
title: gcp-iit
description: The cilock gcp-iit attestor captures the GCE Instance Identity Token, verifies its signature against Google's JWKS, and signs the resulting GCE host identity into in-toto evidence.
sidebar_position: 18
examples_repo: 26-gcp-iit
---

Captures the GCP Instance Identity Token (a signed JWT from the GCE metadata server) and verifies its signature against Google's published JWKS, producing a tamper-evident proof of "this ran on GCE project/instance X."

## What it captures

The full verified [`jwt`](./jwt) attestor (token, header, claims, JWKS URL) plus the following GCE claims extracted from the `google` claim of the IIT:

- `project_id` — GCP project (string)
- `project_number` — numeric project ID (string)
- `zone` — GCE zone
- `instance_id` — GCE instance ID
- `instance_hostname` — `instance_name` from the IIT
- `instance_creation_timestamp`
- `instance_confidentiality`
- `licence_id` — list of GCE license IDs

When the token has no `google` claim (Workload Identity on GKE), the attestor instead reads the GCE metadata server directly and fills in `cluster_name`, `cluster_uid`, `cluster_location`, plus instance/project fields parsed from the JWT `email` claim.

Subjects emitted: `instanceid:`, `instancename:`, `projectid:`, `projectnumber:`, `clusteruid:`.

## When to use

Builds running on GCE VMs, GKE nodes, or Cloud Build workers. The IIT is the GCP analog of the AWS instance identity document — a strong "this ran in our project, this zone, this instance" signal signed by Google.

## Flags

None. Configuration is via environment variable:

| Env var | Default | What it does |
|---|---|---|
| `WITNESS_GCP_JWKS_URL` | `https://www.googleapis.com/oauth2/v3/certs` | Override the JWKS endpoint used to verify the IIT signature. |

The identity token is always fetched with audience `witness-node-attestor` against the `default` service account.

## Output shape

```json
{
  "jwt": { "token": "...", "claims": { ... }, "jwksUrl": "https://www.googleapis.com/oauth2/v3/certs" },
  "project_id": "my-project",
  "project_number": "123456789012",
  "zone": "projects/123/zones/us-central1-a",
  "instance_id": "8675309",
  "instance_hostname": "build-runner-01",
  "instance_creation_timestamp": "1700000000",
  "instance_confidentiality": "0",
  "licence_id": ["1234"],
  "cluster_name": "",
  "cluster_uid": "",
  "cluster_location": ""
}
```

## Gotchas

- **GCE-only.** The identity token is fetched from `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=witness-node-attestor&format=full` with the `Metadata-Flavor: Google` header. On any non-GCE host the request fails (no DNS, no IMDS) and `Attest` returns `unable to retrieve valid identity token`.
- **Signature verification is delegated to the `jwt` attestor.** The IIT is verified against Google's JWKS at `https://www.googleapis.com/oauth2/v3/certs` (or `WITNESS_GCP_JWKS_URL`). If verification fails, the attestor fails — unverified tokens are never recorded.
- **Workload Identity fallback.** GKE pods using Workload Identity get a token without the `google` claim. The attestor detects this, falls back to direct metadata server lookups (`/computeMetadata/v1/instance/...` and `/computeMetadata/v1/project/...`), and parses project ID/number out of the JWT `email` claim domain. Cluster fields are only populated on this path.
- Metadata responses are capped at 1 MB to bound memory if the endpoint is compromised.
- The hardcoded audience is `witness-node-attestor` — verifiers asserting an audience should expect that exact string.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/26-gcp-iit](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/26-gcp-iit). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog)
- [`aws`](./aws) — AWS analog (EC2 instance identity document)
- [`jwt`](./jwt) — the underlying token verification
- Upstream: [witness/gcp-iit.md](https://github.com/in-toto/witness/blob/main/docs/attestors/gcp-iit.md)
