# Secret Scan Attestor

The secretscan attestor is a post-product attestor that scans attestations and products for secrets and other sensitive information. It helps prevent accidental secret leakage by detecting secrets and securely storing their cryptographic digests instead of the actual values.

## How It Works

The attestor uses [Gitleaks](https://github.com/zricethezav/gitleaks) to scan for secrets in:

1. Products generated during the attestation process
2. Attestations from other attestors that ran earlier in the pipeline
3. Environment variable values that match sensitive patterns:
   - Scans for actual values of sensitive environment variables that might have leaked into files or attestations
   - Checks both for direct values and encoded values of environment variables
   - Supports partial matching of sensitive environment variable values
   - Respects the user-defined sensitive environment variable configuration from the attestation context
4. Multi-layer encoded secrets:
   - Detects secrets hidden in base64, hex, or URL-encoded content
   - Can decode multiple layers of encoding (e.g., double base64-encoded secrets)
   - Tracks the encoding path for audit and forensic purposes

When secrets are found, they are recorded in a structured format with the actual secret replaced by a DigestSet containing cryptographic hashes of the secret using all configured hash algorithms from the attestation context.

### Workflow Diagram

The following sequence diagram illustrates how the secretscan attestor works:

```mermaid
sequenceDiagram
    participant User
    participant Aflock
    participant SecretScan
    participant Detector
    participant Scanner
    participant EnvScanner
    participant Decoder
    
    User->>Aflock: Run with secretscan attestor
    Aflock->>SecretScan: Initialize attestor
    SecretScan->>SecretScan: Load configuration
    Note over SecretScan: Configure allowlists, file limits, etc.
    
    Aflock->>SecretScan: Run attestation
    
    SecretScan->>Detector: Initialize with patterns
    Note over Detector: Gitleaks pattern matching
    
    par Scan Products
        SecretScan->>Scanner: Scan product files
        Scanner->>Detector: Match patterns
        Scanner->>Decoder: Check for encoded content
        Decoder-->>Scanner: Return decoded secrets
        Scanner-->>SecretScan: Return findings
    and Scan Attestations
        SecretScan->>Scanner: Scan attestation data
        Scanner->>Detector: Match patterns
        Scanner->>Decoder: Check for encoded content
        Decoder-->>Scanner: Return decoded secrets
        Scanner-->>SecretScan: Return findings
    and Scan Environment Variables
        SecretScan->>EnvScanner: Get all sensitive env vars
        Note over EnvScanner: Gets current env variable values
        EnvScanner->>Detector: Search for plain sensitive values
        loop For each encoding layer
            EnvScanner->>Decoder: Identify encoded content
            Decoder-->>EnvScanner: Return decoded content
            EnvScanner->>Detector: Search for sensitive values in decoded content
            EnvScanner->>Decoder: Recursively check for more encoding layers
            Note over Decoder: Up to max-decode-layers deep
        end
        EnvScanner-->>SecretScan: Return findings with encoding paths
    end
    
    SecretScan->>SecretScan: Process all findings
    Note over SecretScan: Create DigestSet for each secret
    
    alt Fail on Detection (--secretscan-fail-on-detection=true)
        SecretScan->>Aflock: Return error with secret count
        Aflock->>User: Exit with non-zero code
    else Continue (default behavior)
        SecretScan->>Aflock: Return attestation with findings
        Aflock-->>User: Return attestation results
    end
```

This diagram shows the major components and data flow of the secretscan attestor process.

The attestor enhances Gitleaks' default rule set with custom rules based on the environment variables considered sensitive. By default, it uses the `DefaultSensitiveEnvList` from the environment package, which includes both explicit variable names (like `AWS_SECRET_ACCESS_KEY`) and glob patterns (like `*TOKEN*`, `*SECRET*`, `*PASSWORD*`). Keys added with `--env-add-sensitive-key` are sensitive too, and keys named by `--env-allow-sensitive-key` are not. A value is matched only when it has at least 8 characters, and never for a location or identity (`PWD`, `OLDPWD`, `HOME`, `TMPDIR`, `TMP`, `TEMP`, `SHELL`, `USER`, `LOGNAME`, `SSH_AUTH_SOCK`, `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_AUTHOR_DATE`, any key ending in `PATH`), whichever pattern catches it. `--env-capture-allowlist` only decides what the environment attestor records.

**Important:** The environment variable scanning specifically looks for the **values** of sensitive environment variables that might have leaked into files, attestations, or other content. This differs from traditional secret scanning, which typically looks for patterns that match known secret formats. By examining actual environment variable values, the attestor can detect real secrets that have leaked from your environment, whether in plain text form or through various encoding methods.

The scanning process examines:
1. **All product files** - Source code, config files, build artifacts, etc.
2. **Attestation data** - JSON representations of attestor results
3. **Command outputs** - Stdout/stderr from command run attestors
4. **Decoded content** - Content after decoding base64, hex, or URL encoding

For each location, it searches for the actual values of sensitive environment variables that are currently set during attestation. For example, if you have `AWS_SECRET_ACCESS_KEY=1234abcd` set in your environment, the attestor will look for the string `1234abcd` anywhere in the scanned content.

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `fail-on-detection` | `false` | If true, the attestation process will fail if secrets are detected. It governs FINDINGS only: a file the scan could not read fails the run regardless, because an empty findings list over unread files is not a clean result |
| `max-file-size-mb` | `10` | Maximum file size in MB to scan (prevents resource exhaustion) |
| `config-path` | `""` | Path to custom Gitleaks configuration file in TOML format |
| `allowlist-regex` | `""` | Regex pattern for content to ignore (can be specified multiple times) |
| `allowlist-stopword` | `""` | Specific string to ignore (can be specified multiple times) |
| `max-decode-layers` | `3` | Maximum number of encoding layers to decode (prevents resource exhaustion) |
| `scope` | `products` | Which files to scan: `products` (the files earlier attestors recorded), `tree` (every file under the working directory, `.git` excluded), or `diff:<base-ref>` (products plus every file changed since the merge-base of `<base-ref>` and HEAD, including untracked files) |
| `scan-attestations` | `true` | Scan the JSON of attestors that ran earlier in the step (this is where command-run stdout/stderr and the material inventory live). Set `false` to scan files only |
| `include-glob` | `""` | Only scan paths matching this glob, relative to the working directory (product keys recorded as absolute paths are made relative before matching). One pattern; use brace alternation for several (`{src,cmd}/**`) |
| `exclude-glob` | `""` | Never scan paths matching this glob; exclude wins over include. One pattern; use brace alternation for several (`{**/,}{vendor,node_modules}/**`) |

> **Important Note on Allowlists**: When `config-path` is provided, the `allowlist-regex` and `allowlist-stopword` options are ignored. All allowlisting must be defined within the Gitleaks TOML configuration file. The `max-file-size-mb` setting still applies and will override any value in the TOML configuration.

## Scan Scope

By default the attestor scans every recorded product and every prior attestation, and records nothing about that choice. The four scope options narrow or widen it, and whenever any of them is set the predicate gains a `scope` object saying exactly what was covered:

```json
{
  "findings": [],
  "scope": {
    "files": "diff",
    "baseRef": "origin/main",
    "baseCommit": "7f3e1a85b8ea1c084c92d924d90a5fd872df43dc",
    "attestations": false,
    "excludeGlob": "{**/,}{vendor,node_modules}/**",
    "filesScanned": 3
  }
}
```

- `scope=diff:<base-ref>` is the push-gate shape. It answers "did this push introduce a secret": **every commit newly reachable from `HEAD`**, not just the difference between the two end trees — add a secret and delete it in the next commit and the endpoint diff is clean while the push still carries it. Every blob each newly reachable commit introduces (relative to all of its parents, not just the first, and recursively so nested files are not missed) is read and attributed to the commit that introduced it. Ancestry is read from the commit objects themselves — their parent lines, never their dates, and never `git rev-list`: `.git/info/grafts` rewrites what git reports for a commit's parents and `--no-replace-objects` does not disable it, so a graft could otherwise hide a secret-bearing commit from the scan while the pushed history still carried it. A grafted or shallow repository is refused outright — no attestation rather than one that quietly covers less. On top of that, every tracked file that changed in any way that leaves a file to read — added, modified, and type-changed, such as a symlink replaced by a regular file — plus untracked files that are not ignored, relative to the merge-base of `<base-ref>` and `HEAD`. Only deletions are left out, because there is nothing to read. **What the COMMIT contains is read from the git object store, not from disk** — every changed blob, unconditionally, in one `git cat-file --batch`. Committing a secret and then restoring, deleting or overwriting the file does not remove it from the scan, and neither does `git update-index --assume-unchanged` / `--skip-worktree`: git's own verdict on whether a path is dirty is not consulted, because it is exactly what an attacker would change. Git object replacement (`refs/replace/*`) is disabled on every git command the attestor runs, so a replace ref pointing at a clean substitute cannot stand in for the object a push would actually carry. When the committed bytes turn out to be identical to the file on disk the content is reported once, under `file:<path>`; when they differ, the committed bytes get their own subject and findings under `commit:<sha>:<path>`, naming the commit that introduced them. Uncommitted work is scanned on top, since it is about to become a commit, and the INDEX is read as its own source: staging a secret and then restoring the working copy leaves bytes that neither the commit nor the file on disk has, and those are recorded under `index:<path>`. Product metadata never decides what gets read — a file another attestor labelled binary is still read, and binary-ness is decided from its bytes. A file already recorded as a product is scanned once, as a product. The base is resolved with `git`, and a base that cannot be resolved (unknown ref, not a repository) fails the run rather than scanning nothing.
- `scope=tree` reads every regular file under the working directory except anything under `.git`; a symlinked working directory is resolved first, and a root that cannot be walked fails the run rather than reporting an empty, clean tree. This is the explicit whole-tree scan; it can be slow on a large checkout, which is what the globs are for.
- `scan-attestations=false` leaves prior attestations alone. Pair it with `scope=diff:...` for the cheapest meaningful gate; leave it on when the wrapped command's stdout/stderr must be covered.
- Working-tree files that are not products are recorded as subjects under `file:<path>` with the digest of the bytes read, and their findings use the same `file:<path>` location.
- **Every subject is the digest of the bytes this attestor read** — `product:<path>` included. A signed claim binds to what was observed, not to another attestor's record. When the bytes are what the product attestor recorded, which is the normal case, the subject is identical to what it always was and correlation between the two attestations is unchanged. When they differ, the scanned digest is published and the disagreement is listed in `scope.productDigestMismatches` with the path, the recorded digest and the scanned one; that alone is enough to make a default scan emit a `scope` object, because a file that changed between the product snapshot and the scan is something a policy may want to deny on.
- **cilock's own untracked output is not scanned** (`own_output.go`). Two kinds of file, each identified by what it is and never by its name. (1) The file this cilock process writes its stdout or stderr to (same device and inode, never followed through a symlink), in any scope, a recorded product included. (2) A file holding a signed DSSE envelope over an attestation collection (another run's `--outfile`, or its saved stdout), ONLY when a `diff` scope's working-tree walk discovered it: never a recorded product, which is what the step publishes, and never under a `tree` scope. For an envelope file, the text outside the envelope lines is scanned first, and any finding there means the whole file is scanned. Either is skipped only when git positively says the path is untracked: its real path (no symlinked component) is in neither the index nor `HEAD`, is not at or under a submodule gitlink, and is owned by the working directory's own repository; outside a git work tree, with an unborn `HEAD`, or on any git error, it is scanned. Committed and staged blobs are read from the object store and never pass through this filter, so a skipped file is one no commit in the push carries, and staging it makes it scanned again. The skip is logged; the file is neither a subject nor a digest disagreement. Without it, `cilock run ... 2> log` inside the repository always reported its own log as a product that changed between recording and scanning, and a diff scope reported the commit hashes inside an earlier step's saved evidence as secrets.

Example, gating a push on the changed files only:

```sh
cilock run -a git -a secretscan \
  --attestor-secretscan-scope=diff:origin/main \
  --attestor-secretscan-scan-attestations=false \
  --attestor-secretscan-fail-on-detection \
  -k key.pem -s secrets -- true
```

## Execution Order and Coverage

The secretscan attestor runs as a `PostProductRunType` attestor, which means it runs after all material, execute, and product attestors have completed.

**Important Notes on Coverage:**

1. **Attestation Coverage:** The attestor only scans attestations that have completed before it starts. This means:
   - It covers all pre-material, material, execute, and product attestors
   - It does NOT scan other post-product attestors that run concurrently with it
   - This limitation prevents race conditions and ensures reliable operation

2. **Product Coverage:** The attestor scans all products, regardless of which attestor created them.

3. **Binary Files:** By default, binary files and directories are automatically skipped to prevent false positives.

4. **Encoded Content:** The attestor will recursively decode content up to `max-decode-layers` deep to find hidden secrets, supporting:
   - Base64 encoding
   - Hex encoding
   - URL encoding
   - Multiple layers of the same or different encoding types

## Secret Representation

Secrets are represented as a DigestSet that contains multiple cryptographic hashes of the secret:

1. The set of hash algorithms is determined by the attestation context configuration
2. By default, this includes at minimum a SHA-256 hash
3. Each hash is stored as a hex-encoded string in the DigestSet map
4. This approach ensures the actual secret is never stored or transmitted

## Advanced Features

### Multi-layer Encoding Detection

The secretscan attestor can detect secrets that have been encoded multiple times:

1. **Encoding Detection**: Automatically identifies base64, hex, and URL-encoded content
2. **Recursive Decoding**: Recursively decodes content up to the configured maximum layers
3. **Encoding Path Tracking**: Records the sequence of encodings used to hide the secret
4. **Environment Variable Pattern Matching**: Detects encoded environment variable values

When an encoded secret is found, the attestor adds an `encodingPath` field to the finding that lists all the encoding layers detected, which is valuable for:

- Forensic analysis to understand how the secret was hidden
- Determining if the encoding was deliberate obfuscation
- Helping remediate the source of the secret leak

### Environment Variable Protection

The attestor provides enhanced environment variable protection:

1. **Direct Environment Variable Detection**: Scans for sensitive environment variable values directly exposed in:
   - All product files (source code, config files, build artifacts, etc.)
   - Attestation data from earlier attestors (e.g., command run outputs, git info)
   - Decoded content from encoded data
2. **Encoded Environment Variable Detection**: Detects environment variable values hidden through encoding
3. **Partial Value Matching**: Can detect partial matches of sensitive values (useful for truncated secrets). A partial match must carry at least half of the value and at least 8 characters of it; see [Partial Match Support](#partial-match-support) below
4. **Custom Match Redaction**: Securely redacts sensitive values in match context displays
5. **Pattern Matching**: Supports both exact matches and pattern-based matching for variable names
6. **Value-based Detection**: Focuses on the actual values of variables rather than just their names
7. **DigestSet Creation**: Securely stores cryptographic hashes of values instead of the values themselves
8. **Extensive Coverage**: Uses a comprehensive list of sensitive environment variables:
   - Common cloud provider credentials (AWS, Azure, GCP)
   - API keys and tokens for popular services
   - Generic patterns like `*TOKEN*`, `*SECRET*`, `*PASSWORD*`
   - User-defined sensitive environment variables

**How Environment Variable Scanning Works:**

1. The attestor gets all environment variables currently set in the execution environment
2. It identifies which variables are sensitive using the configured sensitive variable list
3. For each sensitive environment variable, it:
   - Searches for its value in all product files
   - Searches for its value in all attestation data
   - Searches for its value in any decoded content from encoded data
4. It also examines command run attestor outputs (stdout/stderr) for sensitive values
5. All found sensitive values are recorded as findings with secure digests

**Encoded Environment Variable Detection:**

The attestor has a powerful capability to detect sensitive environment variable values even when they've been encoded:

1. **Multi-layer Encoding Detection:**
   - When scanning files and attestations, the attestor looks for encoded content (base64, hex, URL-encoded)
   - It recursively decodes this content up to the configured `max-decode-layers` (default: 3)
   - For each layer of decoded content, it searches for sensitive environment variable values

2. **Encoding Path Tracking:**
   - When an encoded secret is found, the attestor records the exact "encoding path" 
   - For example, if a secret was base64-encoded and then hex-encoded, the path would be `["hex", "base64"]`
   - This helps identify how secrets were obfuscated

3. **Partial Match Support:**
   - The attestor can detect partial matches of encoded environment variable values
   - This catches cases where only a leading portion of a secret was encoded, such as `echo ${TOKEN:0:24} | base64`
   - A partial match is reported only when the decoded content carries **at least half of the value, and at least 8 characters of it**. Decoded content is mostly not text (every sha256 in a material inventory, every `h1:` line in `go.sum`, every lockfile integrity hash decodes to 32 bytes of noise), so a shorter prefix turns up by chance in any large tree, and which environment value it "matched" depends on the caller's environment. The half rule also keeps a prefix that every secret of a kind shares (the HS256 JWT header, PEM armor, `ghp_`, `AKIA`) from matching a different secret of the same kind
   - Findings from partial matches carry the `-partial` rule-id suffix and digest the matched prefix, not the whole value

4. **Context Awareness:**
   - Special handling for common patterns like newlines often introduced by `echo` commands
   - Recognition of encoding artifacts and padding characters

## Examples

### Basic Usage

```sh
aflock run -a secretscan -k key.pem -s step-name
```

### Fail on Secret Detection

To make CI/CD pipelines fail when secrets are detected:

```sh
aflock run -a secretscan --secretscan-fail-on-detection=true -k key.pem -s step-name
```

When `--secretscan-fail-on-detection=true` is specified, the command will exit with a non-zero exit code if any secrets are found. This is useful in CI/CD pipelines to prevent accidental deployment of code containing sensitive information.

### Using Built-in Allowlist

```sh
aflock run -a secretscan \
  --secretscan-fail-on-detection=true \
  --secretscan-allowlist-regex="TEST_[A-Z0-9]+" \
  --secretscan-allowlist-stopword="EXAMPLE_API_KEY" \
  -k key.pem -s step-name
```

### Using Custom Gitleaks Configuration

```sh
aflock run -a secretscan \
  --secretscan-config-path="/path/to/custom-gitleaks.toml" \
  -k key.pem -s step-name
```

### Configuring Encoding Detection

```sh
aflock run -a secretscan \
  --secretscan-max-decode-layers=5 \
  -k key.pem -s step-name
```

For a reference to the Gitleaks TOML configuration format, see the [Gitleaks documentation](https://github.com/zricethezav/gitleaks/blob/master/README.md).

## Real-World Examples

### Detecting Plain Secrets

When a file contains a plaintext secret:

```
API_KEY=1234567890abcdef
```

The attestor will detect it and create a finding like:

```json
{
  "ruleId": "generic-api-key",
  "description": "API Key detected",
  "location": "product:/path/to/file.txt",
  "startLine": 10,
  "secret": {
    "SHA-256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  },
  "match": "API_KEY=123[REDACTED]",
  "entropy": 5.6
}
```

### Detecting Environment Variables

For environment variables:

```
GITHUB_TOKEN=ghp_012345678901234567890123456789
```

The attestor creates a specific finding:

```json
{
  "ruleId": "witness-env-value-GITHUB-TOKEN",
  "description": "Sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "product:/path/to/file.txt",
  "startLine": 10,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "HUB_TOKEN=[SENSITIVE-VALUE]"
}
```

### Detecting Encoded Environment Variables

Suppose you have `GITHUB_TOKEN=ghp_012345678901234567890123456789` set in your environment, and a file contains:

```
# This is output from a build script
Encoded token: Z2hwXzAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==
```

The attestor will:
1. Detect the base64-encoded content
2. Decode it to `ghp_012345678901234567890123456789`
3. Recognize this as the value of the sensitive `GITHUB_TOKEN` environment variable
4. Create a finding:

```json
{
  "ruleId": "witness-encoded-env-value-GITHUB-TOKEN",
  "description": "Encoded sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "product:/path/to/file.txt",
  "startLine": 2,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "Encoded token: [REDACTED]",
  "encodingPath": ["base64"],
  "locationApproximate": true
}
```

For multi-layer encoded environment variables like a double base64-encoded GitHub token:

```
# This is deeply hidden 
WjJod1h6QXhNak0wTlRZM09Ea3dNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPUT09
```

The attestor will recursively decode and detect it:

```json
{
  "ruleId": "witness-encoded-env-value-GITHUB-TOKEN",
  "description": "Encoded sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "product:/path/to/file.txt", 
  "startLine": 2,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "# This is deeply hidden [REDACTED]",
  "encodingPath": ["base64", "base64"],
  "locationApproximate": true
}
```

### Detecting Encoded Secrets

When a file contains a base64-encoded GitHub token:

```
Z2hwXzAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==
```

The attestor will detect and decode it:

```json
{
  "ruleId": "generic-api-key",
  "description": "Detected a Generic API Key",
  "location": "product:/path/to/file.txt",
  "startLine": 10,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "GITHUB_T...23456789",
  "entropy": 3.6889665,
  "encodingPath": [
    "base64"
  ],
  "locationApproximate": true
}
```

### Detecting Multi-layer Encoded Secrets

For a double base64-encoded GitHub token:

```
WjJod1h6QXhNak0wTlRZM09Ea3dNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPUT09
```

The attestor will recursively decode and detect it:

```json
{
  "ruleId": "witness-encoded-env-value-GITHUB-TOKEN",
  "description": "Encoded sensitive environment variable value detected: GITHUB_TOKEN",
  "location": "attestation:command-run",
  "startLine": 1,
  "secret": {
    "SHA-256": "5d0b11a2c18800ccab20d01a60a9e58c535cc7da7f4cf582ace05aca9c8757dd"
  },
  "match": "HUB_TOKEN=[REDACTED]",
  "encodingPath": [
    "base64",
    "base64"
  ],
  "locationApproximate": true
}
```

## Implementation Details

The secretscan attestor includes these key features:

1. Secret detection based on Gitleaks' pattern matching
2. Secure cryptographic hashing of secrets with DigestSet
3. Multi-layer encoding detection and decoding
4. Environment variable value detection
5. Configurable file size limits and decoding depth
6. Allowlisting capability for expected patterns
7. Location-based identification of where secrets were found

## Finding Format

The attestor produces findings with the following fields:

| Field | Description |
|-------|-------------|
| `ruleId` | Identifier of the rule that triggered the finding |
| `description` | Human-readable description of the secret type |
| `location` | Where the secret was found (product path or attestation name) |
| `startLine` | Line number where the secret was found (if available) |
| `secret` | DigestSet containing cryptographic hashes of the secret |
| `match` | Redacted context around the detected secret |
| `entropy` | Entropy score of the secret (if calculated) |
| `encodingPath` | Array listing all encoding layers detected (if encoded) |
| `locationApproximate` | Boolean flag indicating if the location is approximate |

The `location` field clearly identifies where the secret was found:
- `product:/path/to/file.txt` - For secrets found in products
- `attestation:attestor-name` - For secrets found in attestations
- `file:path/to/file.txt` - For secrets found in working-tree files read under a `diff` or `tree` scope that are not products
- `commit:<sha>:path/to/file.txt` - For secrets found in bytes a newly reachable COMMIT introduced at a path, read from the git object store under a `diff` scope. `<sha>` is the commit that introduced them, which may be an intermediate commit whose content never reaches `HEAD` at all
- `index:path/to/file.txt` - For secrets found in the content STAGED for a path, read from the git object store under a `diff` scope when the staged bytes are neither what the commit holds nor what is on disk

## Internal Architecture

The secretscan attestor is organized into several logical components:

1. **Detector**: Integration with Gitleaks for pattern matching
2. **Scanner**: Core scanning logic for files and content
3. **EnvScan**: Specialized scanning for environment variable values
4. **Encoding**: Multi-layer encoding detection and decoding
5. **Allowlist**: Configuration and management of allowlisted content
6. **Findings**: Secure handling and reporting of detected secrets
7. **Config**: Configuration management and validation

This modular design ensures maintainability, testability, and extensibility as new secret detection capabilities are added.