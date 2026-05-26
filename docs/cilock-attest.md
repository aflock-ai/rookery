# `cilock attest` — recording attestations without wrapping a command

`cilock attest` is a thin wrapper over `cilock run` for **consultative
attestors** that snapshot at-rest state — things that don't need a
wrapped command's stdout/stderr/exit-code to produce evidence.

## When to reach for it

| Use `cilock attest` when…                          | Use `cilock run -- <cmd>` when…                  |
| -------------------------------------------------- | ------------------------------------------------ |
| You want a snapshot of an *external* fact          | You want a record of *running* a build or scan   |
| Examples: PR review state, EC2 identity, IAM creds | Examples: docker build, syft scan, semgrep, etc. |
| The attestor reads APIs / metadata endpoints       | The attestor wraps a wrapped command             |

Internally, `cilock attest` synthesizes the no-op argv `["true"]` and
calls the same code path as `cilock run`. Every flag (`-a`, `-k`, `-o`,
`-s`, `--attestor-*`, `--ignore-command-exit-code`) accepts the same
shape.

## Quickstart: `github-review`

Snapshot PR review state for a commit, sign it with your own key, and
get a bundle that policyverify can later gate on.

### 1. Generate or supply a signing keypair

```bash
openssl genpkey -algorithm ed25519 -out signer.key
openssl pkey -in signer.key -pubout -out signer.pub
```

### 2. Auth to GitHub

Pick one (highest precedence first):

```bash
# Local dev: gh CLI already logged in — nothing extra needed
gh auth status

# Or set an env var (also what GitHub Actions does automatically)
export GITHUB_TOKEN=ghp_yourtoken
```

### 3. Attest the HEAD commit's review state from a checkout

```bash
cd ~/proj/myrepo

cilock attest \
  -a github-review \
  -k signer.key \
  -o review-head.bundle.json \
  -s review-snapshot
```

cilock will:

1. Read `.git/HEAD` to get the commit SHA
2. Parse `git remote get-url origin` to get owner/repo
3. Call `GET /repos/OWNER/REPO/commits/SHA/pulls` to find PRs
4. For each PR, `GET /repos/OWNER/REPO/pulls/N/reviews`
5. Sign everything into `review-head.bundle.json`

### 4. Attest an arbitrary commit (no checkout needed)

```bash
cilock attest \
  -a github-review \
  --attestor-github-review-repo  aflock-ai/rookery \
  --attestor-github-review-sha   abc123def \
  -k signer.key \
  -o review-abc123.bundle.json \
  -s review-abc123
```

### 5. Attest a specific PR by number

```bash
cilock attest \
  -a github-review \
  --attestor-github-review-repo  aflock-ai/rookery \
  --attestor-github-review-pr    184 \
  -k signer.key \
  -o review-pr184.bundle.json \
  -s review-pr184
```

## Predicate shape

URI: `https://aflock.ai/attestations/github-review/v0.1`

```json
{
  "repo": "aflock-ai/rookery",
  "commit_sha": "abc123def",
  "fetched_at": "2026-05-25T23:23:29Z",
  "api_base_url": "https://api.github.com",
  "token_source": "github-token-env",
  "prs": [{
    "number": 184,
    "state": "merged",
    "head_sha": "...",
    "base_sha": "...",
    "url": "https://github.com/aflock-ai/rookery/pull/184",
    "reviews": [
      {
        "state": "APPROVED",
        "user_login": "reviewer1",
        "submitted_at": "2026-05-25T18:00:00Z",
        "commit_id": "..."
      }
    ]
  }]
}
```

The `token_source` field records which auth source produced the token
that fetched these reviews. Possible values: `flag`, `gh-token-env`,
`github-token-env`, `gh-auth-token`, `anonymous`. Verifiers can use
this to require a specific provenance — e.g., reject any bundle whose
review predicate was captured anonymously.

## Bundle subjects

The bundle's `subject[]` list exposes everything verifiers and
policyverify can pin on:

- `commitsha:<sha>` — the target commit
- `repo:<owner>/<name>` — the repo
- `pr:<owner>/<name>#<n>` — every associated PR
- `reviewer:<login>` — every distinct reviewer

A policy can require, e.g., "subject = commitsha:abc123 must carry one
`github-review/v0.1` predicate with `state == APPROVED` and
`user_login` ∈ {alice, bob}".

## Running inside GitHub Actions

`GITHUB_TOKEN` is auto-injected by the runner. Declare the right
permissions in your workflow:

```yaml
permissions:
  contents: read
  pull-requests: read   # ← required

jobs:
  attest-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install cilock
        run: |
          curl -L https://github.com/aflock-ai/rookery/releases/latest/download/cilock-linux-amd64 -o /usr/local/bin/cilock
          chmod +x /usr/local/bin/cilock
      - name: Attest PR review state
        env:
          # The runner sets GITHUB_TOKEN automatically — but if you set
          # `env:` here you must include this line or override it.
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          cilock attest \
            -a github-review \
            --attestor-github-review-sha ${{ github.sha }} \
            -k ${{ secrets.SIGNING_KEY_PATH }} \
            -o review-${{ github.sha }}.bundle.json \
            -s review-snapshot
```

If you get a `403 — GITHUB_TOKEN in this workflow lacks the
pull-requests: read scope`, the attestor's error message will tell you
the exact YAML to add.

## GitHub Enterprise Server

```bash
cilock attest \
  -a github-review \
  --attestor-github-review-api-url https://ghe.example.com/api/v3 \
  --attestor-github-review-token   $GHE_TOKEN \
  --attestor-github-review-repo    myorg/myrepo \
  -k signer.key \
  -o review.bundle.json \
  -s review
```

The token from the env-var chain (`GH_TOKEN`/`GITHUB_TOKEN`) is reused
when `--token` isn't passed — pointing at GHE doesn't change the auth
resolution order.

## Anonymous use (public repos only)

For quick experiments against public repos, no auth is required —
github-review falls through to anonymous and warns:

```
(github-review) no GitHub token resolved — falling back to anonymous
(60 req/hr; public repos only).
```

The `token_source` in the predicate will be `anonymous`. Verifiers
typically reject these for production use.

## Other consultative attestors that work with `cilock attest`

| Attestor      | Captures                                       |
| ------------- | ---------------------------------------------- |
| `aws-iid`     | EC2 instance identity document (when on EC2)   |
| `gcp-iit`     | GCP instance identity token (when on GCE)      |
| `aws-config`  | AWS Config compliance evaluation results       |
| `vault-cli`   | (with explicit query argv) HashiCorp Vault state |

All follow the same shape — no wrapped command, just snapshot + sign.

## Implementation notes

- The wrapped `command-run` attestor still records the no-op `true`
  exec. That's intentional: it stamps the moment of attestation in the
  bundle. If you don't want command-run, pass `-a <attestor>`
  selectively (this overrides the default attestor set).
- `cilock attest` accepts no positional arguments. If you find
  yourself wanting `cilock attest -- foo`, you actually want
  `cilock run -- foo` — the attestation is for the command you ran,
  not for state-at-rest.
