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

Check the version:

```bash
cilock version
```

---

## Quick start (local key, offline)

This sequence wraps a build, signs with a local key, generates a starter policy
from the resulting evidence, signs the policy, and verifies the built binary —
all without contacting the platform (`--platform-url ""`).

```bash
# 1. Generate a local signing key pair
openssl ecparam -genkey -name prime256v1 -noout -out cosign.key
openssl ec -in cosign.key -pubout -out cosign.pub

# 2. Wrap a build — produces an in-toto / DSSE attestation
cilock run \
  --step build \
  --workload manual \
  --attestations environment \
  --signer-file-key-path cosign.key \
  --outfile build.att.json \
  --platform-url "" \
  -- go build -o app .

# 3. Generate a starter Witness policy from the evidence, then sign it
cilock policy from-bundles -k cosign.pub build.att.json > policy.json
cilock sign -k cosign.key -f policy.json -o policy.signed.json

# 4. Verify the built artifact against the signed policy
cilock verify ./app \
  -p policy.signed.json \
  -k cosign.pub \
  -a build.att.json \
  --platform-url ""
# → "Verification succeeded" (exit 0)
```

`product` and `material` attestations are always recorded, so even with
`--attestations environment` the collection still binds the build's inputs and
outputs.

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
| `prove` | Emit signed inclusion proofs for files in a v0.3 product/material tree. |
| `prove-chain` | Build a multi-step chain-of-custody sidecar binding consumed materials to an upstream step's signed Merkle root. |
| `attestors` | List available attestors or print an attestor's JSON schema. |
| `tools` | Introspect the in-binary detector registry (list / show / test-plan). |
| `keyid` | Inspect the canonical keyid derived from a public or private key. |
| `login` / `logout` / `whoami` | Manage the stored TestifySec platform session. |
| `version` | Print the cilock version. |
| `license` | Show license information. |
| `completion` | Generate a shell completion script (bash, zsh, fish, powershell). |

### Global flags

```
-c, --config string                   Path to the witness config file (default ".witness.yaml")
-l, --log-level string                Level of logging to output (debug, info, warn, error) (default "info")
    --debug-cpu-profile-file string   Path to store the CPU profile (enables profiling when non-empty)
    --debug-mem-profile-file string   Path to store the Memory profile (enables profiling when non-empty)
```

---

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
    --workload string               How attestors are picked: 'auto' (default — detects when you
                                    don't pass -a) or 'manual' (disables detection)
    --capture-mode string           Where material/product attestors get their digests
                                    (auto | walk | trace[:ebpf|:ptrace|:auto] | ima) (default "auto")
    --enable-archivista             Use Archivista to store or retrieve attestations
```

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

Examples (from `cilock run --help`):

```bash
# Wrap a build, sign with a local key, capture Go build provenance
cilock run --step build -k cosign.key --workload manual \
  -a environment,git,go-build -o build.att.json -- go build ./...

# Wrap any command, signing it with just the environment attestor
cilock run --step unit-test -k cosign.key --workload manual \
  -a environment -o test.att.json -- go test ./...
```

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

---

## `cilock sign`

```bash
cilock sign -k cosign.key -f policy.json -o policy.signed.json
```

```
-k, --signer-file-key-path string   Path to the file containing the private key
-f, --infile string                 File to sign
-o, --outfile string                File to write signed data; defaults to stdout
-t, --datatype string               URI for the data type being signed
                                    (default "https://witness.testifysec.com/policy/v0.1")
```

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
# Validate a policy's schema and structure
cilock policy validate -p policy.json

# Also verify the policy signature, as JSON
cilock policy validate -p policy.json -k policy-pub.pem -o json

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

## `cilock prove` / `cilock prove-chain`

`prove` emits one signed inclusion-proof DSSE envelope per `--file`, each binding
`(path, fileDigest, treeRoot, leafIndex, auditPath)` against a v0.3
product/material tree carried in a sidecar:

```bash
cilock prove --file path/in/tree --signer-file-key-path cosign.key \
  -o proof.json --tree-sidecar <sidecar>
```

`prove-chain` builds an unsigned `rookery.chain-proof.sidecar/v0.1` document that
binds consumed materials to an upstream step's signed Merkle root:

```bash
cilock prove-chain \
  --source-envelope upstream.bundle.json \
  --source-sidecar upstream.sidecar.json \
  --source-step source \
  --consumed path/to/material=sha256:<hex> \
  -o chain.sidecar.json
```

Each `--consumed` material must already appear in the upstream sidecar's leaf set;
the command refuses to fabricate proofs for materials not in the upstream tree.

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
