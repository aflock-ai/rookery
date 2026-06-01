---
title: Steampipe
description: Query AWS, GCP, Azure, Kubernetes, GitHub, and other cloud or SaaS APIs as SQL with Steampipe under cilock — every row becomes a signed v0.1 Steampipe attestation chained to subject digests per identity axis.
sidebar_position: 17
examples_repo: 31-steampipe
---

[Steampipe](https://steampipe.io) is Turbot's SQL engine for cloud and SaaS APIs — query AWS, GCP, Azure, Kubernetes, GitHub, Okta, Slack, and dozens of other providers as if they were Postgres tables, then layer on compliance mods (`steampipe-mod-aws-compliance`, `steampipe-mod-aws-cis`, `steampipe-mod-kubernetes-compliance`) that ship FedRAMP / CIS / NIST / HIPAA benchmarks as SQL. Cilock wraps each query so the JSON rows become a **signed v0.1 Steampipe attestation** with per-row subject digests (`aws:account:<id>`, `github:repo:<owner/name>`, `k8s:uid:<uid>`, etc.) — evidence a Rego gate can match against `attestationsFrom`.

## Validated invocation

```bash
cilock run --step steampipe-query \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations steampipe,environment,git \
  --enable-archivista=false \
  -- sh -c 'steampipe query --output json "select arn, name from aws_iam_user limit 5" > steampipe.json'
```

Two Steampipe-specific quirks are baked into that command — both matter for clean attestations:

- **`--output json` is required.** The `steampipe` rookery attestor consumes the query's JSON product in `PostProductRunType`. The default `--output table` writes ANSI-formatted text that the attestor will skip (it filters on `application/json` MIME type or `.json` suffix). Pass `--output json` (or `--output csv` and reformat; `json` is the supported shape).
- **`sh -c '... > out.json'` is a single-shell-redirect.** Steampipe writes query output to stdout, not to a file. Wrapping the run in `sh -c` routes that stdout into `steampipe.json` so the `product/v0.3` attestor can hash it. `command-run/v0.1` records the full `sh -c` argv — that's a tool-output limitation (stdout-only), NOT the `cp` antipattern.

## What gets captured

Each cilock run emits an in-toto envelope whose predicate carries the following attestor types:

| Attestor type                                          | Captures                                                                |
| ------------------------------------------------------ | ----------------------------------------------------------------------- |
| `https://aflock.ai/attestations/command-run/v0.1`      | Real `sh -c 'steampipe query ...'` argv, env, exit code, stdout/stderr  |
| `https://aflock.ai/attestations/material/v0.3`         | Merkle tree of working-directory inputs (`.sql` files, mod definitions) |
| `https://aflock.ai/attestations/product/v0.3`          | Merkle tree of outputs, including `steampipe.json`                      |
| `https://aflock.ai/attestations/steampipe/v0.1`        | Parsed query rows, `resultHash` (SHA-256 of raw JSON), frontmatter (id, KSI, NIST, plugin, severity), per-row subjects |
| `https://aflock.ai/attestations/environment/v0.1`      | OS, arch, user, env vars (PII-filtered)                                 |
| `https://aflock.ai/attestations/git/v0.1`              | Commit SHA, branch, remotes                                             |

The `steampipe/v0.1` predicate's `results[].resultHash` matches the SHA-256 of the `steampipe.json` leaf in the `product/v0.3` tree. That is the chain that makes the rows verifiable — you can't swap in different JSON without invalidating the product tree. Per-row subjects (`aws:account:<id>`, `aws:arn:<arn>`, `aws:region:<region>` for the AWS plugin; `github:repo:<owner/name>`, `github:org:<login>` for GitHub; `k8s:uid:<uid>`, `k8s:namespace:<ns>` for Kubernetes; `okta:user:<id>`, `okta:org:<organization>` for Okta; `googleworkspace:customer:<id>`, `:user:<email>`, `:domain:<d>`, `:orgunit:<path>` for the Google Workspace plugins; `slack:team:<id>`, `slack:user:<id>`, `slack:channel:<id>` for Slack) are surfaced via `Subjects()` so policy graphs can join across tools.

## Why this shape

| Antipattern                                                       | This page                                                          |
| ----------------------------------------------------------------- | ------------------------------------------------------------------ |
| `cilock run ... -- bash -c "cp /tmp/steampipe.json out.json"`     | `cilock run ... -- sh -c 'steampipe query ... > steampipe.json'`   |
| `command-run` records `bash -c "cp ..."` — useless                | `command-run` records the real `steampipe query` argv inside `sh -c` |
| Product attestor digests the `cp` destination                     | Product attestor digests Steampipe's actual stdout-redirect target |
| Tool execution happens outside the attestation                    | Steampipe runs as cilock's grandchild via `sh -c`; spy still traces |

Steampipe writes its query results to **stdout**, not to a file the binary owns. That's an upstream limitation — `--output json` controls the format but there's no `--output-file` option. A single `sh -c '... > out.json'` is the minimum-glue redirect that gets the bytes into a file the `product/v0.3` Merkle tree can hash. `command-run/v0.1` records the full `["sh", "-c", "steampipe query --output json ... > steampipe.json"]` argv, so the recipe is auditable end-to-end — no shell logic, no string concatenation, no `cp` laundering.

## Validate it locally

```bash
# Generate a signing key (one-time).
openssl genpkey -algorithm ed25519 -out key.pem

# Install the Steampipe plugin for the cloud you want to query, and configure credentials.
steampipe plugin install aws
export AWS_PROFILE=your-profile   # or rely on instance role / SSO

# Run cilock + Steampipe against any cloud API.
cilock run --step steampipe-query \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations steampipe,environment,git \
  --enable-archivista=false \
  -- sh -c 'steampipe query --output json "select arn, name from aws_iam_user limit 5" > steampipe.json'

# Confirm the predicate carries the expected attestor types.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations | map(.type)'
```

Expected output:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/steampipe/v0.1"
]
```

```bash
# Confirm the real argv (including the steampipe query string) landed in command-run.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'
```

Expected output (literal argv — proof the `cp` antipattern is absent):

```json
[
  "sh",
  "-c",
  "steampipe query --output json \"select arn, name from aws_iam_user limit 5\" > steampipe.json"
]
```

```bash
# Inspect the per-query results: row count, result hash, frontmatter, subjects.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/steampipe/v0.1")
        | .attestation
        | {results: (.results | map({frontmatterId: .frontmatter.id,
                                     plugin: .frontmatter.plugin,
                                     rowCount, resultHash}))}'
```

Against `select arn, name from aws_iam_user limit 5` you should see a single `QueryResult` with `rowCount: 5` (or fewer, if the account has fewer IAM users), `plugin: "aws"`, and a `resultHash` matching `steampipe.json`'s digest in the `product/v0.3` tree.

## How a verifier consumes this

The `steampipe` attestor is a `postproduct` lifecycle attestor with predicate type `https://aflock.ai/attestations/steampipe/v0.1`. It consumes the JSON product in the PostProduct phase (same pattern as `asff` and `sarif`); it does not shell out to the `steampipe` binary. The predicate is a `Predicate` object with:

- `steampipeVersion` — version of the steampipe binary that produced the output (optional).
- `plugins` — list of Steampipe plugins involved (optional).
- `collectedAt` — UTC timestamp of when the attestor sealed the results.
- `results` — array of `QueryResult` entries, one per JSON product consumed.
- `identities` — optional map of identity-axis hints (e.g. account → role) the recipe driver injected.

Each `QueryResult` carries:

- `frontmatter` — `QueryFrontmatter` parsed from the `.sql` file's YAML comment block: `id`, `task`, `ksis` (FedRAMP 20x indicators), `nist` controls, `plugin`, `severity`. Injected via `WithFrontmatter`; ID falls back to `"anonymous"`.
- `sql` — literal SQL the recipe ran, injected via `WithSQL` (optional).
- `ranAt` — UTC timestamp.
- `duration` — recorded query duration string.
- `rowCount` — number of rows in the JSON output.
- `resultHash` — hex SHA-256 of the raw JSON body.
- `rows` — raw JSON bytes (omitted when truncated for envelope size).
- `error` — error string if the query failed.

Subjects emitted for graph linking (SHA-256 of the identifier string) are driven by `frontmatter.plugin` via the convention table in `conventions.go`:

- `aws`: `aws:account:<id>`, `aws:arn:<arn>`, `aws:region:<region>`
- `github`: `github:repo:<owner/name>`, `github:org:<login>`
- `okta`: `okta:user:<id>`, `okta:org:<organization>`
- `kubernetes`: `k8s:uid:<uid>`, `k8s:namespace:<namespace>`
- `googledirectory`: `googleworkspace:customer:<id>`, `:user:<primary_email>`, `:group:<email>`, `:domain:<domain_name>`, `:orgunit:<org_unit_path>`
- `googleworkspace`: `googleworkspace:customer:<id>`, `:user:<user_email>`, `:user:<actor_email>`
- `slack`: `slack:team:<team_id>`, `slack:user:<user_id>`, `slack:channel:<channel_id>` (posture recipes alias `id as user_id` / `id as channel_id` so the two axes don't collide on a bare `id`)

The source JSON file is recorded as a Material so verifiers can re-derive the captured bytes. Pair with `policyverify` to gate a deployment on rego rules evaluating the captured rows — for example, KSI / NIST mappings carried via the SQL frontmatter route the resulting envelope at the matching FedRAMP 20x indicator.

The attestor itself exposes no command-line flags. Configuration is via Go option functions called by the recipe driver:

| Option | Purpose |
|---|---|
| `WithQueryPackPath(path)` | Directory of `.sql` files (recipe driver use). |
| `WithMaxRowsPerQuery(n)` | Truncate row capture per query (default 500). |
| `WithFrontmatter(fm)` | Inject parsed YAML frontmatter from the `.sql` comment block. |
| `WithSQL(sql)` | Record the literal SQL on the result entry. |

### Output shape

```json
{
  "predicate": {
    "collectedAt": "2026-05-21T12:00:00Z",
    "results": [
      {
        "frontmatter": {
          "id": "iam-mfa-enforcement",
          "ksis": ["KSI-IAM-MFA"],
          "nist": ["IA-2(1)"],
          "plugin": "aws",
          "severity": "high"
        },
        "sql": "select user_name, account_id, arn, mfa_enabled from aws_iam_user;",
        "ranAt": "2026-05-21T12:00:00Z",
        "rowCount": 4,
        "resultHash": "9f3c...",
        "rows": [{ "user_name": "alice", "account_id": "123456789012", "mfa_enabled": true }]
      }
    ]
  }
}
```

## Notes

- **Mods for compliance benchmarks.** Beyond ad-hoc queries, Steampipe ships compliance mods that map to named regimes: [`steampipe-mod-aws-compliance`](https://hub.steampipe.io/mods/turbot/aws_compliance) (FedRAMP, NIST 800-53, HIPAA, PCI), [`steampipe-mod-aws-cis`](https://hub.steampipe.io/mods/turbot/aws_compliance) (CIS AWS Foundations v1.2 – v3.0), [`steampipe-mod-kubernetes-compliance`](https://hub.steampipe.io/mods/turbot/kubernetes_compliance), [`steampipe-mod-gcp-compliance`](https://hub.steampipe.io/mods/turbot/gcp_compliance), [`steampipe-mod-azure-compliance`](https://hub.steampipe.io/mods/turbot/azure_compliance), and several others in [Turbot's mod gallery](https://hub.steampipe.io/mods). Each mod is a Git repo of `.sql` queries + `benchmark.sp` definitions; you can run a whole benchmark (`steampipe check benchmark.cis_v300` — produces a posture report) or extract individual controls as queries.
- **Query vs check vs dashboard.** Steampipe has three execution modes. `steampipe query` runs ad-hoc SQL and emits rows. `steampipe check` runs a benchmark from a mod and emits per-control pass/fail (also exportable as JSON). `steampipe dashboard` serves an interactive web UI (not used under cilock; the attestor consumes JSON files, not a live server). The validated invocation uses `query` because it's the simplest path to a single signed JSON product.
- **Plugins drive subjects.** The `steampipe/v0.1` attestor only emits subjects for plugins in its convention table — `aws`, `github`, `okta`, `kubernetes`, `googledirectory`, `googleworkspace`, and `slack` today. Queries against other plugins (`gcp`, `azure`, `datadog`, …) still produce a signed attestation with rows and `resultHash`, but the per-row subject fan-out won't include identity axes the table doesn't know about. Extend `conventions.go` in rookery if you need new ones (and update this doc — the convention list lives in several places here).
- **Output formats.** Steampipe supports `--output json`, `--output csv`, `--output table`, `--output line`. Only `json` flows into the `steampipe` attestor — the others are filtered out (MIME type / `.json` suffix check). Stick to JSON for signed evidence; use CSV / table for human-readable runs.
- **Plugin + credentials prerequisite.** `steampipe plugin install aws` (or `gcp`, `azure`, `kubernetes`, `github`, `slack`, `okta`, …) must run before the query, and the plugin needs cloud credentials configured — `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` in env for AWS, `GOOGLE_APPLICATION_CREDENTIALS` for GCP, `KUBECONFIG` for Kubernetes, `GITHUB_TOKEN` for GitHub. The `environment` attestor will record the env vars present at run time (PII-filtered), but credentials themselves are not leaked into the envelope.
- **Frontmatter routing.** Real-world recipes drive Steampipe from `.sql` files with a YAML frontmatter block (`id`, `task`, `ksis`, `nist`, `plugin`, `severity`). The recipe driver parses the frontmatter and stamps it onto the attestor via `WithFrontmatter` / `WithSQL`; the resulting `steampipe/v0.1` predicate carries those fields, and a Rego gate can route on `frontmatter.ksis` (e.g. `KSI-IAM-MFA`) to match envelopes to FedRAMP 20x indicators. Ad-hoc `steampipe query` (no `.sql` file) gets `frontmatter.id = "anonymous"`.
- **In the collection by default (not a sidecar).** The `steampipe/v0.1` attestation rides INSIDE the run's collection, so a witness policy step can require `steampipe/v0.1` and gate its rows directly (e.g. `cilock verify -a attestation.json -s sha256:<product-leaf-digest>` — the product/v0.3 inline leaves bridge the file digest to the `tree:products` root, find the collection, and run the Rego over the in-collection rows). Emitting the attestation as its own standalone sidecar envelope is the **exception**, opt-in with `--attestor-steampipe-export` (or `WithExport(true)`) — use it only when a downstream consumer needs the query result as an independently-addressable attestation. When evaluating rows in Rego, the policyverify `input` is the marshaled attestor, so the rows are at `input.predicate.results[_].rows.rows[_]`.

## Gotchas

- This attestor does **not** shell out to the `steampipe` binary. The recipe runs `steampipe query --output json my-pack/check.sql > out.json` as a `commandrun` step; this attestor consumes the JSON product in the PostProduct phase (same pattern as `asff` and `sarif`).
- Two JSON shapes are accepted: a raw array `[{...}, ...]` and a wrapper `{"id": "...", "rows": [...]}`. Anything else is skipped.
- Products whose MIME type does not contain `json` and whose path does not end in `.json` are skipped. Each product is re-digested against the context's recorded digest; mismatches are silently skipped.
- Subjects only emit for plugins listed in the convention table (`aws`, `github`, `okta`, `kubernetes`, `googledirectory`, `googleworkspace`, `slack`). Other plugins produce no subjects unless the table is extended.
- AWS account IDs decoded as JSON `float64` are rendered as integer strings (`"123456789012"`, not `"1.23456789012e+11"`) before hashing.
- Returns an error if no products are present or none parse as valid Steampipe output.

## FAQ

### Does cilock support Steampipe?

Yes. Cilock invokes the upstream `steampipe` binary unchanged, redirects its JSON output into a file, and the built-in `steampipe` rookery attestor parses that JSON in the `PostProduct` phase. The predicate type is `https://aflock.ai/attestations/steampipe/v0.1` — distinct from `sarif/v0.1`, because Steampipe's row-oriented data shape doesn't fit SARIF's finding model. No Steampipe fork, no plugin install on the cilock side.

### Which clouds can Steampipe scan under cilock?

Anything Steampipe has a plugin for — AWS, GCP, Azure, Kubernetes, GitHub, GitLab, Slack, Okta, Datadog, Snowflake, Salesforce, Jira, plus 140+ other providers in [Steampipe's hub](https://hub.steampipe.io/plugins). The `steampipe` attestor's subject fan-out today covers AWS, GitHub, Okta, Kubernetes, the Google Workspace plugins (`googledirectory` / `googleworkspace`), and Slack identity axes; queries against other plugins still produce a signed envelope with rows and a `resultHash`, just without per-row subject digests until the rookery `conventions.go` table is extended.

### How is Steampipe different from Prowler?

Prowler is a fixed CLI that runs a baked-in catalog of AWS / Azure / GCP / Kubernetes security checks and emits OCSF or ASFF findings. Steampipe is a **SQL engine** — you write the query (or pull one from a mod). Prowler's findings have severity, status, and remediation guidance built in; Steampipe gives you raw rows and lets the policy layer decide what's pass / fail. Use Prowler when you want an off-the-shelf compliance scan; use Steampipe when you want to define your own controls in SQL or join across providers (e.g. "every GitHub repo whose CODEOWNERS lists an Okta-disabled user").

### Can I use custom SQL queries as compliance gates?

Yes — that's the primary cilock + Steampipe pattern. Author a `.sql` file with a YAML frontmatter block (`id: my-control`, `ksis: [KSI-IAM-MFA]`, `nist: [IA-2(1)]`, `plugin: aws`, `severity: high`), run it under cilock, and the `steampipe/v0.1` predicate carries both the rows and the frontmatter. A Rego policy on the verify side reads `attestation.frontmatter.ksis` to route the envelope and `attestation.results[].rows` to gate on row contents (e.g. "no row where `mfa_enabled = false`").

### What if the query returns no rows?

That's a valid attestation. `steampipe/v0.1` records `rowCount: 0`, `resultHash` over the empty `[]` JSON array, and emits no per-row subjects (because there are no rows to fan out). A Rego gate can treat "zero rows matched the bad-state query" as the pass condition — which is the natural shape for negative-finding controls (e.g. "select * from aws_iam_user where mfa_enabled = false" → zero rows means the control passes).

### Can I attest SaaS security posture (Slack, Google Workspace)?

Yes — this is the same pattern, pointed at a SaaS plugin instead of a cloud one. The `slack` plugin (`steampipe plugin install slack`, token in `~/.steampipe/config/slack.spc`) exposes `slack_user` (2FA enrollment via `has_2fa`, `is_admin` / `is_owner` / `is_restricted` flags) and `slack_conversation` (external sharing via `is_ext_shared` / `is_shared` / `is_org_shared`). A posture recipe captures those rows under cilock and a Rego policy gates them — e.g. "every active member has 2FA," "no externally-shared channels in the CUI boundary." Because the recipe reuses `id` for both tables, alias the primary key (`select id as user_id …` / `select id as channel_id …`) so the `slack:user:` and `slack:channel:` subject axes stay distinct. The Google Workspace plugins (`googledirectory` / `googleworkspace`) work the same way and converge with the dedicated `scubagoggles` attestor on `customer_id` / `domain_name` in the policy graph. Note steampipe captures 2FA *enrollment* (`has_2fa`) but not the factor type — fine, since enrollment is the gating signal.

## See also

- [Validated example: `31-steampipe`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/31-steampipe) — end-to-end reproduce scripts, including the Slack workspace-posture recipe (`slack/`: query pack + NIST 800-171 Rego gate)
- [Steampipe](https://steampipe.io) — upstream project (Turbot)
- [Steampipe Hub: mods](https://hub.steampipe.io/mods) — compliance benchmark catalogs (`aws_compliance`, `aws_cis`, `kubernetes_compliance`, …)
- [Steampipe Hub: plugins](https://hub.steampipe.io/plugins) — 140+ cloud / SaaS data sources
- [Steampipe docs](https://steampipe.io/docs)
- [Tools index](./index)
