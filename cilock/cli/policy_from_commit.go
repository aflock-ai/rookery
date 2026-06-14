// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/spf13/cobra"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// commitFetcher is the slice of the Archivista client `from-commit` needs: find
// the DSSE gitoids whose statement subjects include a digest (the commit), and
// download each as an envelope. It is an interface so tests can substitute an
// in-memory fetcher without standing up a real Archivista (mirrors push's
// dsseUploader seam).
type commitFetcher interface {
	// SearchGitoidsBySubjects returns gitoids whose statement subjects intersect
	// the given digest values (the git attestor records the commit as a subject
	// digest whose VALUE is the raw commit sha — that value is the join key).
	SearchGitoidsBySubjects(ctx context.Context, subjectDigests, excludeGitoids []string) ([]string, error)
	// Download fetches one DSSE envelope by its gitoid.
	Download(ctx context.Context, gitoid string) (dsse.Envelope, error)
}

// newCommitFetcher is a seam over the real Archivista client construction so
// tests can substitute an in-memory fetcher. It builds the same client
// `cilock policy push` / `cilock run --enable-archivista` use (Bearer auth).
var newCommitFetcher = func(archivistaURL, bearer string) commitFetcher {
	headers := http.Header{}
	if bearer != "" {
		headers.Set("Authorization", "Bearer "+bearer)
	}
	return archivista.New(archivistaURL, archivista.WithHeaders(headers))
}

// fullCommitSHA matches a full-length git object id (sha1: 40 hex, sha256: 64
// hex). A short ref or a non-hex string is resolved against the local repo
// before querying — the git attestor records the FULL commit hash as the
// subject, so a short sha would never match the platform's evidence.
var fullCommitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)

// PolicyFromCommitCmd is `cilock policy from-commit <commit>`. Where
// from-bundles reads LOCAL DSSE files, from-commit authors a policy from the CI
// attestations the platform already holds: in real CI, `cilock run
// --enable-archivista` uploads collections to Archivista keyed by SUBJECTS (the
// git attestor records the commit as a subject), so the developer never has the
// bundle files locally. from-commit points at the commit instead.
//
// It resolves the commit, queries Archivista for every DSSE whose subjects
// include that commit, downloads each, and feeds them through the SAME
// policy-derivation core as from-bundles (summarizeEnvelopeBytes +
// buildStarterPolicy) — so it inherits the verifiable-policy logic (TSA
// authorities, signer-email cert constraints, functionary-per-step).
//
// Without --product/--tag it just authors (write -o or stdout) so the discrete
// sign → push → bind flow still works. With --product AND --tag it runs the
// one-shot: derive → sign (keyless, same as `cilock sign`) → push (createDsse →
// createPolicyDefinition-if-missing → createPolicyRelease) → bind
// (createPolicyBinding).
func PolicyFromCommitCmd() *cobra.Command {
	var o policyFromCommitOpts

	cmd := &cobra.Command{
		Use:   "from-commit <commit-sha>",
		Short: "Author a Witness policy from a commit's CI attestations in Archivista",
		Long: `from-commit authors a starter Witness policy from the CI attestations the
platform already holds for a commit — no local bundle files needed.

In real CI, ` + "`cilock run --enable-archivista`" + ` runs in the pipeline and uploads
attestation collections to the platform's Archivista, keyed by SUBJECTS (the git
attestor records the commit as a subject). The developer who wants to gate on
that evidence never has the ` + "`cilock run -o`" + ` bundle files locally — they only
have the commit. from-commit resolves the commit, finds every DSSE whose
subjects include it, groups them by their witness collection name (the --step
value), and derives a policy.

It shares from-bundles' derivation core, so the generated policy:
  - lists one step per CI collection found for the commit
  - populates functionaries from each collection's signers (raw-keyid OR Fulcio
    keyless cert, with the leaf's SAN email pinned as a certConstraint)
  - recovers timestamp-authority trust anchors from the RFC3161 tokens so a
    short-lived keyless leaf verifies (the #5741 verifiable-policy fix)
  - wires cross-step provenance edges where one step's materials are another's
    products
  - defaults expires to 1 year (override with --expires)

Two modes:
  - author only (default): write the policy to -o/stdout; then run the discrete
    flow: cilock sign → cilock policy push → cilock policy bind.
  - one-shot (--product AND --tag): derive → sign (keyless) → push → bind in one
    command. --definition names the PolicyDefinition (default: the product name).

Auth: the Archivista query needs a logged-in session; createPolicyDefinition /
createPolicyRelease / createPolicyBinding need policy:write. If the platform
rejects a call for a missing scope, run ` + "`cilock login`" + ` again.`,
		Example: `  # Author a policy from a commit's CI evidence, write it for review
  cilock policy from-commit 1a2b3c4d... -o policy.json

  # One-shot: derive, sign keyless, publish a release tagged v1, bind to a product
  cilock policy from-commit 1a2b3c4d... --product my-service --tag v1

  # One-shot with an explicit definition name
  cilock policy from-commit HEAD --product my-service --tag v1 --definition supply-chain`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.commit = args[0]
			return runPolicyFromCommit(cmd, o)
		},
	}

	addFromCommitFlags(cmd, &o)
	return cmd
}

// addFromCommitFlags registers the from-commit flags, binding each into o.
func addFromCommitFlags(cmd *cobra.Command, o *policyFromCommitOpts) {
	f := cmd.Flags()
	f.StringVar(&o.platformURL, "platform-url", "", "TestifySec platform URL (default: the logged-in platform)")
	f.StringVar(&o.archivistaURL, "archivista-server", "", "Archivista server URL (default: ${platform-url}/archivista)")
	f.StringVarP(&o.output, "output", "o", "-", "Write the authored policy here. '-' (default) is stdout. Ignored in one-shot mode.")
	f.DurationVar(&o.expiresIn, "expires", defaultPolicyExpiry, "How far in the future the policy's `expires` field is set (default 1 year). Set short and re-issue after review.")
	f.StringVar(&o.stepPrefix, "step-prefix", "", "Optional prefix prepended to every generated step name (e.g. 'release-').")
	f.StringVarP(&o.product, "product", "p", "", "Product id or exact name. With --tag, runs the one-shot sign→push→bind flow against this product.")
	f.StringVarP(&o.tag, "tag", "t", "", "Release tag for the one-shot flow (requires --product).")
	f.StringVarP(&o.definition, "definition", "d", "", "PolicyDefinition name for the one-shot flow (default: the product name).")
	f.StringVar(&o.description, "description", "", "Description used only when the one-shot flow creates a new PolicyDefinition.")
}

// policyFromCommitOpts groups the resolved flag values for `policy from-commit`.
type policyFromCommitOpts struct {
	commit        string
	platformURL   string
	archivistaURL string
	output        string
	expiresIn     time.Duration
	stepPrefix    string
	product       string
	tag           string
	definition    string
	description   string
}

// oneShot reports whether the command should run the full sign→push→bind flow.
// It requires both --product and --tag; --product alone (used to scope the query
// in a future enhancement) does not trigger publishing.
func (o policyFromCommitOpts) oneShot() bool {
	return o.product != "" && o.tag != ""
}

func runPolicyFromCommit(cmd *cobra.Command, o policyFromCommitOpts) error {
	out := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()
	ctx := cmdContext(cmd)

	// A bare --product or bare --tag is almost certainly a half-typed one-shot;
	// fail loudly rather than silently authoring-only and dropping the publish.
	if (o.product == "") != (o.tag == "") {
		return fmt.Errorf("--product and --tag must be used together for the one-shot publish flow (got --product=%q --tag=%q)", o.product, o.tag)
	}

	sess, err := resolvePolicySession(o.platformURL)
	if err != nil {
		return err
	}

	// Resolve the commit to a full object id (the join key). The git attestor
	// records the FULL hash as the subject value, so a short ref must be expanded
	// against the local repo before querying.
	commit, err := resolveCommitSHA(o.commit)
	if err != nil {
		return err
	}

	archivistaURL := o.archivistaURL
	if archivistaURL == "" {
		archivistaURL = resolveArchivistaURL(sess.platformURL)
	}

	// Fetch + derive the policy from the commit's CI attestations.
	pol, stepCount, err := derivePolicyFromCommit(ctx, stderr, o, commit, archivistaURL, sess.cred.Token)
	if err != nil {
		return err
	}
	// Status/progress goes to STDERR, never stdout: in author-only mode the
	// policy JSON is written to stdout (default --output -), so a status line on
	// stdout would corrupt `cilock policy from-commit HEAD > policy.json`. stdout
	// stays reserved for the policy artifact alone (mirrors from-bundles).
	_, _ = fmt.Fprintf(stderr, "Authored a policy with %d step(s) from commit %s\n", stepCount, shortID(commit))

	if !o.oneShot() {
		return writeAuthoredPolicy(out, pol, o.output)
	}
	return runFromCommitOneShot(cmd, o, sess, pol)
}

// derivePolicyFromCommit queries Archivista for every DSSE whose subjects
// include the commit, downloads each, summarizes it through the shared core, and
// builds the policy via buildStarterPolicy. The returned step count is the
// number of distinct collections found (drives the no-evidence error).
func derivePolicyFromCommit(ctx context.Context, stderr io.Writer, o policyFromCommitOpts, commit, archivistaURL, bearer string) (*policy.Policy, int, error) {
	fetcher := newCommitFetcher(archivistaURL, bearer)

	// The git attestor's commit subject digest VALUE is the raw commit sha
	// (sha1=<commit> for sha1 repos). SearchGitoidsBySubjects filters subject
	// digests by valueIn, so the commit sha IS the search term. Tenant scoping
	// is enforced server-side; the session bearer carries the viewer.
	gitoids, err := fetcher.SearchGitoidsBySubjects(ctx, []string{commit}, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("query archivista for commit %s: %w", shortID(commit), err)
	}
	if len(gitoids) == 0 {
		return nil, 0, fmt.Errorf("no attestations found for commit %s on the platform.\n"+
			"CI must have run `cilock run --enable-archivista` for this commit so the\n"+
			"git attestor records it as a subject the platform can index. Confirm the\n"+
			"pipeline ran for this exact commit, and that you're logged in to the tenant\n"+
			"that owns the evidence:\n\n  cilock whoami", shortID(commit))
	}

	// Stable order so the generated policy is deterministic across runs.
	sort.Strings(gitoids)

	summaries := make([]bundleSummary, 0, len(gitoids))
	for _, gitoid := range gitoids {
		env, derr := fetcher.Download(ctx, gitoid)
		if derr != nil {
			return nil, 0, fmt.Errorf("download attestation %s: %w", shortID(gitoid), derr)
		}
		// Re-marshal the downloaded envelope to JSON bytes so the shared
		// file-source parser (summarizeEnvelopeBytes) handles it identically to
		// an on-disk bundle. The Envelope.Payload []byte marshals back to the
		// base64 string the parser expects.
		raw, merr := json.Marshal(env)
		if merr != nil {
			return nil, 0, fmt.Errorf("re-encode attestation %s: %w", shortID(gitoid), merr)
		}
		// nameHint = gitoid: only a filename fallback if the predicate has no
		// `name`. Collection envelopes from `cilock run -s <step>` always record
		// the name, so the step name comes from the recorded collection name.
		s, serr := summarizeEnvelopeBytes(stderr, raw, gitoid, o.stepPrefix, nil)
		if serr != nil {
			return nil, 0, fmt.Errorf("summarize attestation %s: %w", shortID(gitoid), serr)
		}
		summaries = append(summaries, s)
	}

	pol, err := buildStarterPolicy(stderr, summaries, map[string][]byte{}, o.expiresIn)
	if err != nil {
		return nil, 0, err
	}
	return pol, len(pol.Steps) + len(pol.ExternalAttestations), nil
}

// writeAuthoredPolicy marshals the policy to JSON and writes it to outputPath
// ('-' for stdout). Mirrors from-bundles' output handling.
func writeAuthoredPolicy(stdout io.Writer, pol *policy.Policy, outputPath string) error {
	encoded, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	if outputPath == "" || outputPath == "-" {
		_, err := stdout.Write(append(encoded, '\n'))
		return err
	}
	return os.WriteFile(outputPath, append(encoded, '\n'), 0o600)
}

// runFromCommitOneShot writes the derived policy to a temp file, signs it
// keyless through the SAME `cilock sign` code path, then publishes + binds it by
// invoking the existing push and bind flows — so the one-shot is byte-for-byte
// the discrete sign → push → bind sequence, just chained.
func runFromCommitOneShot(cmd *cobra.Command, o policyFromCommitOpts, sess *policySession, pol *policy.Policy) error {
	out := cmd.OutOrStdout()

	definition := o.definition
	if definition == "" {
		definition = o.product // default the definition name to the product
	}

	tmpDir, err := os.MkdirTemp("", "cilock-from-commit-*")
	if err != nil {
		return fmt.Errorf("create temp dir for one-shot publish: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	policyPath := filepath.Join(tmpDir, "policy.json")
	if err := writeAuthoredPolicy(io.Discard, pol, policyPath); err != nil {
		return fmt.Errorf("write derived policy: %w", err)
	}
	signedPath := filepath.Join(tmpDir, "policy.signed.json")

	// (1) Sign — keyless, identical to `cilock sign`. Reuse SignCmd so the exact
	// platform-default resolution (session → short-lived Fulcio token + TSA)
	// applies. Errors here mean the user isn't logged in / can't reach Fulcio.
	_, _ = fmt.Fprintf(out, "Signing the authored policy (keyless) ...\n")
	if err := runSignViaCmd(cmd, sess.platformURL, policyPath, signedPath); err != nil {
		return fmt.Errorf("sign authored policy: %w", err)
	}

	// (2) Push — upload signed DSSE, ensure definition, create release.
	if err := runPolicyPush(cmd, policyPushOpts{
		file:          signedPath,
		definition:    definition,
		tag:           o.tag,
		description:   o.description,
		platformURL:   o.platformURL,
		archivistaURL: o.archivistaURL,
	}); err != nil {
		return err
	}

	// (3) Bind — bind the just-published release tag to the product.
	return runPolicyBind(cmd, policyBindOpts{
		definition:  definition,
		tag:         o.tag,
		product:     o.product,
		platformURL: o.platformURL,
	})
}

// runSignViaCmd signs inPath → outPath keyless by executing a fresh SignCmd with
// the same flags `cilock sign --platform-url X -f in -o out` would set. Going
// through the real cobra command guarantees the one-shot signs exactly as the
// discrete `cilock sign` step does (platform-default resolution, keyless Fulcio
// exchange, platform TSA). It is a var so tests can stub the signing step.
var runSignViaCmd = func(parent *cobra.Command, platformURL, inPath, outPath string) error {
	sc := SignCmd()
	args := []string{"-f", inPath, "-o", outPath}
	if platformURL != "" {
		args = append(args, "--platform-url", platformURL)
	}
	sc.SetArgs(args)
	sc.SetOut(parent.OutOrStdout())
	sc.SetErr(parent.ErrOrStderr())
	return sc.ExecuteContext(cmdContext(parent))
}

// resolveCommitSHA expands the user's commit argument to the full object id the
// git attestor records as a subject. A full 40/64-hex id is used verbatim.
// Anything else (short sha, "HEAD", a branch/tag name) is resolved against the
// local git repo. When there is no local repo to resolve against, a short ref is
// rejected with a clear message (it would never match the platform evidence).
func resolveCommitSHA(arg string) (string, error) {
	if fullCommitSHA.MatchString(arg) {
		return arg, nil
	}
	repo, err := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", fmt.Errorf("%q is not a full commit sha and there is no local git repo to resolve it "+
			"against (pass the full commit hash, or run from inside the repository): %w", arg, err)
	}
	hash, err := repo.ResolveRevision(plumbing.Revision(arg))
	if err != nil {
		return "", fmt.Errorf("resolve commit %q against the local repo: %w", arg, err)
	}
	return hash.String(), nil
}
