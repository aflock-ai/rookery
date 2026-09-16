# cilock

**Collect and verify attestations about your build environments.**

`cilock` wraps a command (or snapshots at-rest state), records in-toto / DSSE
attestations from a pluggable set of attestors, signs them, and verifies a chain
of evidence against a Witness policy. It is the batteries-included CLI built from
the [Rookery](../) attestation library and plugin set.

By default `cilock` targets the hosted TestifySec platform
(`https://platform.testifysec.com`) for keyless Fulcio signing, RFC 3161
timestamps, and Archivista attestation storage. You can also bring your own key,
timestamper, and storage, or run fully offline.

---

## Install

```bash
go install github.com/aflock-ai/rookery/cilock/cmd/cilock@latest
```

The default binary ships every attestor and a sensible signer set. To build a
slimmer binary with only the plugins you need, see the [`builder`](../builder/).
For a Judge-compatible distribution with compiled evidence defaults, see
[Build a custom CI/lock](../site/docs/guides/build-a-custom-cilock.md#compiled-evidence-defaults).

Check the version:

```bash
cilock version
```

---

## Quick start (local key, offline)

This sequence requires a source build with compact inventory support. Check
`cilock run --help-advanced` before using it. An installed release can predate
these defaults. It wraps a build, signs evidence with a local key, generates and
signs a starter policy, and verifies the built binary. All steps stay offline
with `--platform-url ""`. This is a human-run local demonstration, not a Pushgate
enrollment or authoritative policy-signing flow.

```bash
# 1. Generate a local signing key pair
openssl ecparam -genkey -name prime256v1 -noout -out cosign.key
openssl ec -in cosign.key -pubout -out cosign.pub

# 2. Wrap a build — produces an in-toto / DSSE attestation
cilock run \
  --step build \
  --workload manual \
  --attestations environment \
  --material-manifest \
  --signer-file-key-path cosign.key \
  --outfile build.att.json \
  --platform-url "" \
  -- go build -o app .

# 3. Generate a starter Witness policy from the evidence, then sign it
cilock policy from-bundles -k cosign.pub build.att.json > policy.json
cilock sign -k cosign.key -f policy.json -o policy.signed.json --platform-url ""

# 4. Verify the built artifact against the signed policy
cilock verify ./app \
  -p policy.signed.json \
  -k cosign.pub \
  -a build.att.json \
  --platform-url ""
# → "Verification succeeded" (exit 0)
```

`product` and `material` attestations are present by default, even with
`--attestations environment`. In compact builds, `--material-manifest` retains
the full input details needed to infer artifact links for the starter policy.
Keep the signed inventory companions beside `build.att.json` for local policy
generation and verification. The CLI discovers them there and verifies their
content against the signed collection's inventory references.

---

## Commands

Run `cilock <command> --help` for the full flag list. `cilock --help-advanced`
exposes the hidden signing-backend, attestor-tuning, cache, and env flags.

| Command | What it does |
|---|---|
| `run` | Run a command and record attestations about its execution. |
| `attest` | Record attestations without wrapping a command (sugar for `cilock run -- true`). |
| `verify` | Verify a Witness policy and exit 0 on success. |
| `sign` | Sign a file with a key source and emit a DSSE envelope. |
| `plan` | Show which attestors detection would fire for a command, without executing it. |
| `bundle` | Create and inspect attestation bundles (tar.gz of DSSE envelopes). |
| `policy` | Validate a policy, or generate a starter policy from signed bundles. |
| `attestors` | List available attestors or print an attestor's JSON schema. |
| `tools` | Introspect the in-binary detector registry (list / show / test-plan). |
| `pushgate` | Inspect whether an accepted Git push is queued, delivered, refused, or failed. |
| `keyid` | Inspect the canonical keyid derived from a public or private key. |
| `login` / `logout` / `whoami` | Manage the stored TestifySec platform session. |
| `version` | Print the cilock version. |
| `license` | Show license information. |
| `completion` | Generate a shell completion script (bash, zsh, fish, powershell). |

### Global flags

```
-l, --log-level string                Level of logging to output (debug, info, warn, error) (default "info")
    --debug-cpu-profile-file string   Path to store the CPU profile (enables profiling when non-empty)
    --debug-mem-profile-file string   Path to store the Memory profile (enables profiling when non-empty)
```

---

## `cilock pushgate status`

From a repository configured with a Pushgate Git remote, show the exact
delivery state for the current branch and commit:

```bash
cilock pushgate status
cilock pushgate status --wait
cilock pushgate status --wait --timeout 20m --json
```

CI/lock infers the current ref, `HEAD`, and remote. It discovers the trusted
Pushgate origin from the selected TestifySec platform and refuses to send the
repository credential when the remote origin does not match. `--wait` exits
successfully only after delivery; refusal, conflict, failed delivery, unknown
ledger state, and timeout return non-zero.

Use `--platform-url https://your-platform.example` to select a private
installation explicitly, including an agent-only environment with no human
login. Without that flag, status uses the selected login's platform, then the
hosted default. The selected platform's discovery response must still name the
configured remote's exact origin; this flag does not bypass that check.

---

## `cilock agent status`

`cilock agent status --json --platform-url <platform>` prints one JSON object
containing public identity and local eligibility only. The ordinary text output
is unchanged without `--json`. No credential or signing token is exported.

The fields `platform_url`, `principal_kind`, `tenant_id`, `agent_id`, and
`spiffe_id` identify the stored active slot, or the pending delivery when there
is no active slot. `active` means the local store records a redeemed identity;
`pending` means a separate delivery awaits redemption. `eligible` means an
active-slot credential is not locally expired, **not** that the platform will
accept it. An unredeemed active-slot credential can be locally eligible while
`active` is false and `spiffe_id` is empty. `status` distinguishes `not_enrolled`,
`pending`, `unredeemed`, `eligible`, and `expired`; `expires_at` is omitted when
the local ceiling is unknown, not unlimited. `source` is `local_store` and
`platform_checked` is false: revocation and repository scope remain platform
decisions. An absent identity still exits zero for compatibility; inspect the
fields. Expired active-slot credentials still exit nonzero after printing JSON.

## `cilock run`

```
cilock run [cmd] [flags] -- <command> [args...]
```

Key flags:

```
-a, --attestations strings          Attestations to record ('product' and 'material' are
                                    always recorded) (default [environment,git,platform])
-s, --step string                   Name of the step being run
-o, --outfile string                File to write signed data to
-k, --signer-file-key-path string   Path to the file containing the private key
-r, --trace                         Enable tracing for the command (Linux; eBPF, falls back to ptrace)
-d, --workingdir string             Directory from which commands will run
    --ignore-command-exit-code      Exit 0 from cilock even when the wrapped command exits non-zero;
                                    the exit code is recorded and signed in command-run/v0.2 either way
    --workload string               How attestors are picked: 'auto' (default — detects when you
                                    don't pass -a) or 'manual' (disables detection)
    --capture-mode string           Where material/product attestors get their digests
                                    (auto | walk | trace[:ebpf|:ptrace|:auto] | ima) (default "auto")
    --enable-archivista             Use Archivista to store or retrieve attestations
                                    (automatic for authenticated platform runs)
    --material-manifest             Retain complete material details locally in compact builds
    --upload-inventories            Permit retained inventory upload when Archivista is enabled
    --max-attestation-bytes bytes   Largest in-toto statement cilock will sign (default 4MiB)
```

**Attestation size limit:** `--max-attestation-bytes` (env
`CILOCK_MAX_ATTESTATION_BYTES`, default `4MiB`, `0` to disable) caps the in-toto
statement JSON — the bytes a consumer base64-decodes and parses. A statement over
the limit is refused *before* it is signed, written or uploaded, and the error
names the total, the limit, and the five largest attestors with a remedy for each.
Sizes take plain bytes (`4194304`) or a unit; `KiB`/`MiB`/`GiB` are 1024-based and
`KB`/`MB`/`GB` are 1000-based, so `4MB` is not silently rounded up to `4MiB`.

The number is set by what the platform can afford to read, not by what a signer can
produce: push evaluation downloads and JSON-parses every envelope matching the
commit three times, caching nothing above 512 KiB, at about **0.4 s per MB**
(measured 2026-09-15). One 45 MB envelope costs 18.6 s and two cost 32 s against a
**25 s** edge timeout — which is how a `go test -json` stream captured into
command-run turned into "the platform is unreachable" on push. A real `push-tests`
mint of the Judge repo measured 17,023 bytes on the same day, so the default leaves
roughly 240x headroom for ordinary evidence. The margin is much thinner on a
**legacy**-profile build, where material's per-file leaves stay inline: the same
repository measured a 4.95 MiB envelope (~3.7 MiB of statement, 17,152 leaves) before
compact inventories detached them — 88% of this limit. That is intended; raise the
limit deliberately if you need it.

`verify` has no such flag: the limit is a mint-time guardrail, and evidence signed
before it existed must stay verifiable. Companion envelopes (`--material-manifest`,
detached inventories) are exempt — they are keyed by tree root, never opened by a
commit-keyed evaluation, and carry their own ceilings.

**Attestor selection:** with `--workload auto` (the default), cilock auto-detects
attestors only when you do *not* pass `-a` — it inspects the workspace (go-build
for `go.mod`, git for `.git/`, etc.) and attaches what it finds. Passing `-a`
makes that your exact set with no detection. `--workload auto` forces detection
even alongside `-a`; `--workload manual` disables detection entirely.

**Exit-code policy:** cilock splits attestor errors into two classes so CI can
gate on the exit code:

- **Fatal (exit 1)** — signer failure, the wrapped command exited non-zero,
  `--trace` requested on an unsupported platform, an inaccessible output path or
  unparseable key, or any other attestor contract violation. Logged under
  `Errors:`.
- **Soft (exit 0)** — an attestor ran fine but had nothing to do (e.g. `sbom`
  with no products, `go-build` with no Go binaries). Logged under `Warnings:`.

A non-zero command exit fails cilock's exit status but not the evidence: the
envelope is still signed, written to `--outfile` and uploaded when Archivista is
enabled, with `command-run/v0.2` carrying the real exit code, so a policy rule
on `input.exitcode` can deny the run and print its remediation.
`--ignore-command-exit-code` makes cilock exit 0 in that case (for tools that
exit non-zero on findings); the recorded exit code is unchanged.

Examples (from `cilock run --help`):

```bash
# Wrap a build, sign with a local key, capture Go build provenance
cilock run --step build -k cosign.key --workload manual \
  -a environment,git,go-build -o build.att.json -- go build ./...

# Wrap any command, signing it with just the environment attestor
cilock run --step unit-test -k cosign.key --workload manual \
  -a environment -o test.att.json -- go test ./...
```

### Compact evidence defaults

Source builds use `config.DefaultEvidenceProfile="compact"` and
`config.DefaultProductInlineBytes="131072"`. These are compiled distribution
defaults, independent of login and the selected platform. Ordinary runs need no
profile arguments. There is no runtime profile flag. Build operators can select
`compact-chain`, `legacy`, or a different product budget through validated
`-ldflags -X` values in the
[custom-build guide](../site/docs/guides/build-a-custom-cilock.md#compiled-evidence-defaults).
This describes the source contract, not the version of an installed binary.

For artifact-chain producers, distribute a `compact-chain` build. It retains
material details and enables inventory upload by default when Archivista is
enabled. It uses the same product budget and detachment rules as `compact`.
Users and agents then run ordinary commands without a per-run inventory flag
list. The operator must also verify that the deployed verifier supports compact
inventories before requiring them in a policy.

- **Materials (`compact`):** a nonempty captured set keeps its v0.3 root commitment and an
  `inventory` reference with `state: "omitted"`. Per-file details are not retained
  by default. Omitted details do not mean an empty input set.
- **Products:** the complete serialized product predicate stays inline at or
  below the budget, provided the inline representation preserves every captured
  path. Duplicate-content paths require a detached inventory even below the
  budget. Larger predicates also use a complete signed local inventory companion,
  not a truncated list.
- **Empty sets:** confirmed empty captures keep the existing empty commitment
  encoding. They are distinct from omitted or unavailable details.

The default budget is 131072 bytes (128 KiB) for the inline product predicate,
not the collection or DSSE envelope. Other attestations, signatures, and encoding
add bytes. Capture and the before-command baseline remain unchanged. Compact
encoding does not establish lower scan CPU cost, isolation, or hermeticity.

### Retention and upload

In a `compact` build, `--material-manifest` retains complete material details as a
signed local inventory companion. It does not permit upload. Product inventories
that cannot stay inline are retained automatically.

With `--outfile build.att.json`, companions use names such as
`build.att.json-material-inventory.json` and
`build.att.json-product-inventory.json`. Without `--outfile`, a run that needs
companions creates a private persistent `evidence/run-*` directory under the
Cilock auth-state directory. The CLI prints that directory and stores the
collection as `attestation.json` beside its companions. On Unix, automatic
directories use mode `0700`, and evidence files use `0600`. On Windows, Cilock
creates and verifies protected current-user-only ACLs and rejects reparse points.
Compact builds refuse existing
evidence files instead of overwriting them. Headless inventory retention and
upload never prompt.

In a `compact` build, `--upload-inventories` explicitly permits bulk inventory
upload when Archivista upload is enabled. It does not enable material retention
or Archivista itself. Without this flag, detached inventories remain local even
when the normal collection automatically uploads during an authenticated platform run. Inline
product details travel with that collection. A local companion is not evidence
of remote availability. The run summary reports local paths and upload outcomes
separately from the signed inventory reference.

In a `compact-chain` build, the compiled profile enables retention and upload
consent separately. Explicit `--material-manifest=false` disables material
retention. `--upload-inventories=false` keeps detached inventories local. Neither
flag changes the other setting. Offline runs without an enabled store keep
retained inventories local instead of applying the compiled upload default.
An explicit upload request without an enabled store fails.

Legacy builds retain their previous material-manifest behavior, including
upload when Archivista is enabled.

The normative details are in the
[Cilock compact inventories architecture contract](../../../docs/architecture/cilock-compact-inventories.md).

---

## `cilock attest`

Records attestations against the current context without wrapping a child
command — for consultative attestors that snapshot at-rest state (e.g.
`github-review`, `aws`). Every flag accepted by `cilock run` works here, plus
`--subjects` to inject additional in-toto subjects.

```bash
# Snapshot PR review state for HEAD in the current repo
cilock attest -a github-review -k key.pem -o review.bundle.json -s review-head

# Snapshot a specific PR's review state from any working dir
cilock attest -a github-review \
  --attestor-github-review-repo aflock-ai/rookery \
  --attestor-github-review-pr 153 \
  -k key.pem -o review-pr153.bundle.json -s review-pr153
```

---

## Git commit signing

The same `cilock` binary can serve as Git's X.509 signing program. Configure it
once in the repository (or add `--global` if that is your intended default):

```bash
git config gpg.format x509
git config gpg.x509.program cilock
git config commit.gpgsign true
```

Or configure the current repository in one step (add `--global` for the
current user's global Git config):

```bash
cilock git configure
```

Normal use needs no platform flag. CI/lock defaults to
`https://platform.testifysec.com`, exchanges the stored session for a
short-lived Fulcio credential, creates an ephemeral signing key, and requires an
RFC 3161 timestamp from the platform TSA. A TSA failure aborts the commit rather
than emitting an untimestamped signature. Registered GitHub workflows use their
ambient workload OIDC identity instead of a stored session.

Enterprise and development installations can set `CILOCK_PLATFORM_URL` to the
appliance origin. Git author and committer fields are unchanged; the X.509
certificate records the authenticated platform principal. The same program
verifies the CMS signature, pinned Fulcio chain, and mandatory platform TSA:

```bash
git commit -S -m "feat: signed with CI/lock"
git tag -s v1.2.3 -m "v1.2.3"
git verify-commit HEAD
git verify-tag v1.2.3
```

---

## `cilock verify`

```
cilock verify [artifact-path] [flags]
```

Verifies a policy and exits 0 on success. The artifact may be given positionally
(a regular file maps to `--artifactfile`, a directory to `--directory-path`), or
the subject digest can be supplied directly with `--subjects`.

```
-p, --policy string         Path to the policy to verify
-k, --publickey string      Path to the policy signer's public key
-f, --artifactfile string   Path to the artifact subject to verify
    --directory-path string Path to the directory subject to verify
-a, --attestations strings  Attestation files to test against the policy
    --bundle <file>         Attestation bundle file(s) to load envelopes from (tar.gz from
                            `cilock bundle create`); additive with -a and Archivista lookups
    --enable-archivista     Use Archivista to store or retrieve attestations
    --platform-url string   Platform URL (derives archivista + TSA URLs). Pass "" for fully
                            offline verify (default "https://platform.testifysec.com")
    --offline               Fully offline verify — alias for --platform-url ""
    --format string         How to report the verdict: text (default) or json (machine-readable
                            verdict on stdout). `-o` is a deprecated alias for --format on this
                            command; everywhere else -o is an output path.
    --vsa-outfile string    Write the Verification Summary Attestation to this file
```

Examples (from `cilock verify --help`):

```bash
# Verify a binary against a signed policy (positional artifact)
cilock verify ./judge-api -p policy.json.signed --policy-ca-roots fulcio-root.pem

# Verify a policy against local attestation files
cilock verify -p policy.json -k policy-pub.pem -a build.att.json -a test.att.json

# Fully offline verify from a bundle (no platform lookup)
cilock verify -p policy.json -k policy-pub.pem --bundle evidence.tar.gz --platform-url ""
```

Existing material/product v0.3 evidence remains readable. The `material` and `product`
names and predicate URIs are unchanged:
`https://aflock.ai/attestations/material/v0.3` and
`https://aflock.ai/attestations/product/v0.3`. Existing legacy manifest fields
retain their original meaning. Generic library `material.New()` and
`product.New()` constructors still use legacy inline behavior.

A command-only policy can pass without optional inventories. That result does
not prove artifact inclusion or a complete artifact chain. Artifact-chain checks
require the complete input data and relevant product evidence. Omitted, missing,
or invalid required inventories fail explicitly, including during policy
generation. For those workflows, use a `compact-chain` distribution and make the
required companions available to the verifier. Remote verification cannot read
companions that exist only on the producer's disk.

The v0.3 Merkle root commits to a set of distinct file contents, not every path
or duplicate-content occurrence. The signed `inventory.digest` binds the exact
inventory manifest bytes, including all retained paths and metadata. A matching
content root alone is not a complete path inventory.

---

## `cilock sign`

```bash
cilock sign -k cosign.key -f policy.json -o policy.signed.json --offline
```

```
-k, --signer-file-key-path string   Path to the file containing the private key
-f, --infile string                 File to sign
-o, --outfile string                File to write signed data; defaults to stdout
    --platform-url string          Hosted platform URL; pass "" for local/offline signing
    --offline                       Alias for --platform-url "": no session lookup, no keyless
                                    exchange, no platform TSA; needs a local signer (-k or a
                                    --signer-kms-*/--signer-vault-*/--signer-spiffe-* provider)
-t, --datatype string               URI for the data type being signed
                                    (default "https://witness.testifysec.com/policy/v0.1")
    --max-attestation-bytes bytes   Largest input cilock will sign (default 4MiB)
```

`sign` frames nothing around its input, so `--max-attestation-bytes` is measured on
the bytes read from `--infile`. The check runs before a signer is loaded, so an
oversized file is refused even when no key is configured, and the output file is
never created or truncated.

---

## `cilock plan`

Runs detection against a hypothetical command and prints what *would* fire,
without executing anything.

```bash
# Show which attestors would fire for a build, without running it
cilock plan -- go build ./...

# Machine-readable plan for an agent to consume
cilock plan --format json -- docker build -t app .
```

`-v/--verbose` includes the full skip list. To actually run the planned set, copy
the names from the `fire:` list into `cilock run -a <names> -- <command>`.

---

## `cilock policy`

```bash
# Validate a policy's schema and structure (an unsigned policy is the normal input here)
cilock policy validate -p policy.json

# Also verify the policy signature, as JSON (`-o`/`--output` are deprecated aliases for --format)
cilock policy validate -p policy.json -k policy-pub.pem --format json

# Refuse a policy that was never signed
cilock policy validate -p policy.signed.json --require-signed

# Generate a starter policy template from signed bundles
cilock policy from-bundles -k signer.pub *.bundle.json > policy.json
```

`from-bundles` reads DSSE bundles produced by `cilock run -o ...`, derives each
signing keyid, and emits a policy with one step per bundle (step name = bundle
basename without the `.bundle.json` suffix), the discovered predicate types under
`step.attestations`, and the supplied public keys under `publickeys[]`. You must
pass the public key for every signing key with one or more `-k` flags.

---

## `cilock bundle`

Attestation bundles are tar.gz packages of DSSE envelopes — portable evidence
sets for `cilock verify --bundle`.

```bash
# Build a bundle by walking an Archivista subject graph
cilock bundle create -s sha256:<digest> -o evidence.tar.gz

# Print a bundle's manifest and per-envelope summary
cilock bundle inspect evidence.tar.gz
```

`create` flags include `--max-depth` (default 5) and `--max-envelopes`
(default 10000). `inspect --json` emits the manifest as JSON.

---

## `cilock attestors`

```bash
# List every attestor compiled into this binary (with predicate type + run type)
cilock attestors list

# Print the JSON schema of a specific attestor's predicate
cilock attestors schema <attestor-name>
```

The **canonical name** in the `NAME` column is what you pass to `--attestations`;
it is not always the directory name (`commandrun` registers as `command-run`,
etc.). `product`, `material`, and `command-run` are marked **(always run)**;
`git`, `environment`, and `platform` are marked **(default)**. See the
[attestor catalog](../docs/attestor-catalog.md) for the full list and predicate
types.

---

## `cilock tools`

Introspects the in-binary detector registry — purely informational, no signer or
outfile needed.

```bash
# List every detector cilock can auto-fire (table)
cilock tools list

# Filter to one lexicon category, machine-readable
cilock tools list --category vulnerability-scan --format json

# Full catalog detail for one tool/attestor
cilock tools show sarif
cilock tools show sarif --section policy-gotcha
cilock tools show sarif --format json

# Emit a per-detector test plan (markdown or JSON)
cilock tools test-plan --format json
```

Lexicon categories are documented in [`docs/lexicon-v1.md`](../docs/lexicon-v1.md).

---

## `cilock keyid`

Prints the deterministic identifier cilock uses to refer to a signing key in
attestations and policies — i.e. the value for a policy's
`functionaries[].publickeyid` field. The keyid is `hex(sha256(PEM(public-key)))`
over the PKIX-encoded public key.

```bash
cilock keyid show signer.pub
cilock keyid show signer.key signer.pub other.pem
cilock keyid show --format=json signer.key | jq .
```

For a private key, the public half is extracted before hashing. Output is one
`<keyid>  <path>` line per input (sha256sum shape) unless `--format=json`.

---

## Platform login

For agent-produced evidence, use `cilock enroll agent`, not a stored human
session. The agent can start enrollment, but the human must approve it in the
browser. Read `cilock agent status` before producing evidence. Never fall back
to human-session signing when enrollment is missing, expired, or refused.

The login commands below manage human sessions or registered workflow identity.
Humans sign authoritative policies and perform authenticated policy publication
from a human signing context. Agents prepare policy drafts and sign attestations
as their enrolled agent principals. The human separately reviews and approves
the exact Pushgate repository assignment. Product `policy bind` is not Pushgate
activation.

```bash
# Interactive browser login to the default TestifySec platform
cilock login

# CI/headless: provide a JWT directly (or '-' to read from stdin)
cilock login --platform-url https://platform.example.com --token "$TESTIFYSEC_TOKEN"

# Show / clear the stored session
cilock whoami
cilock logout
```

Identity is resolved by precedence: explicit `--token`, then ambient CI OIDC
(GitHub Actions, auto-detected on the default platform), then interactive browser
login. `--interactive` forces the browser; `--workflow-identity` forces ambient
OIDC.

---

## Shell completion

```bash
# bash (current session)
source <(cilock completion bash)

# zsh (persisted; requires `autoload -U compinit; compinit` in ~/.zshrc)
cilock completion zsh > "${fpath[1]}/_cilock"

# fish
cilock completion fish | source
```

`cilock completion powershell` is also available.

---

## License

Apache License 2.0. Copyright 2025 The Aflock Authors. Run `cilock license` for
the full text. Source: <https://github.com/aflock-ai/rookery>.
