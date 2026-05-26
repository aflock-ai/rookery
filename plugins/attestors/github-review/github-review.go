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

// Package github_review attests the GitHub pull request review state for
// a specific commit by talking to the GitHub REST API directly.
//
// Auth resolution, highest precedence first:
//
//  1. --attestor-github-review-token <PAT>     (explicit flag)
//  2. $GH_TOKEN                                (gh CLI convention)
//  3. $GITHUB_TOKEN                            (auto-set in GitHub Actions)
//  4. `gh auth token` shellout                 (local-dev convenience, optional)
//  5. anonymous                                (public repos only; 60 req/hr/IP)
//
// The attestor is consultative — it captures at-rest state from GitHub
// regardless of whether the wrapped command does anything. It's designed
// for use with `cilock attest` (no wrapped command) but also works
// inside a regular `cilock run`.
//
// Threat model:
//   - The resolved token determines what reviews are visible. A bundle's
//     review predicate is "everything the GitHub API showed to this
//     token at this time."
//   - We trust GitHub's API. There is no signature on the reviews; the
//     attestor's own DSSE envelope is what makes the snapshot tamper-
//     evident, scoped to the moment of capture (FetchedAt timestamp).
//   - On GitHub Enterprise Server, set --attestor-github-review-api-url
//     to your instance's REST base URL (e.g. https://ghe.example.com/api/v3).
package github_review

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name              = "github-review"
	Type              = "https://aflock.ai/attestations/github-review/v0.1"
	RunType           = attestation.PreMaterialRunType
	defaultAPIBaseURL = "https://api.github.com"
	defaultPerPage    = 100
	httpTimeout       = 30 * time.Second
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

// Attestor captures GitHub PR review state for a target commit.
//
// Configuration sources, in order of precedence:
//  1. Explicit flags (--attestor-github-review-repo / --sha / --pr / --token / --api-url)
//  2. Auto-detection from the AttestationContext's working dir:
//     - repo:  `git remote get-url origin` parsed for github.com paths
//     - sha:   `git rev-parse HEAD`
type Attestor struct {
	// Config (lower-case = unexported, set via flags)
	repoFlag   string
	shaFlag    string
	prFlag     string
	tokenFlag  string
	apiURLFlag string

	hashes []cryptoutil.DigestValue

	// Predicate payload (these get DSSE-signed).
	Repo        string `json:"repo"`
	CommitSHA   string `json:"commit_sha"`
	FetchedAt   string `json:"fetched_at"`
	APIBaseURL  string `json:"api_base_url"`
	TokenSource string `json:"token_source"` // flag | gh-token-env | github-token-env | gh-auth-token | anonymous
	PRs         []PR   `json:"prs"`
}

// PR is one pull request associated with the target commit, with the
// full set of reviews visible to the caller at the time of attestation.
type PR struct {
	Number  int      `json:"number"`
	State   string   `json:"state"` // open | closed | merged
	HeadSHA string   `json:"head_sha"`
	BaseSHA string   `json:"base_sha"`
	URL     string   `json:"url"`
	Reviews []Review `json:"reviews"`
}

// Review is one review entry from GitHub's reviews API.
type Review struct {
	State       string `json:"state"` // APPROVED | CHANGES_REQUESTED | COMMENTED | DISMISSED | PENDING
	UserLogin   string `json:"user_login"`
	SubmittedAt string `json:"submitted_at"`
	CommitID    string `json:"commit_id"`
}

type Option func(*Attestor)

// WithRepo overrides repo detection. Format: "owner/repo".
func WithRepo(repo string) Option { return func(a *Attestor) { a.repoFlag = repo } }

// WithSHA overrides commit SHA detection.
func WithSHA(sha string) Option { return func(a *Attestor) { a.shaFlag = sha } }

// WithPR pins to a specific PR number, bypassing commit→PR resolution.
func WithPR(pr string) Option { return func(a *Attestor) { a.prFlag = pr } }

// WithToken supplies an explicit GitHub token (highest precedence).
func WithToken(t string) Option { return func(a *Attestor) { a.tokenFlag = t } }

// WithAPIBaseURL sets a non-default API root (e.g. for GitHub Enterprise).
func WithAPIBaseURL(u string) Option { return func(a *Attestor) { a.apiURLFlag = u } }

func New(opts ...Option) *Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	},
		registry.StringConfigOption(
			"repo",
			"GitHub repository in owner/name form. If empty, parsed from `git remote get-url origin` in the working dir.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithRepo(val)(att)
				return att, nil
			},
		),
		registry.StringConfigOption(
			"sha",
			"Commit SHA to look up reviews for. If empty, taken from `git rev-parse HEAD` in the working dir.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithSHA(val)(att)
				return att, nil
			},
		),
		registry.StringConfigOption(
			"pr",
			"PR number to attest directly. Bypasses the commit→PR lookup; useful when the SHA may belong to multiple PRs or hasn't merged yet.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithPR(val)(att)
				return att, nil
			},
		),
		registry.StringConfigOption(
			"token",
			"GitHub Personal Access Token (PAT). If empty: GH_TOKEN → GITHUB_TOKEN → `gh auth token` → anonymous. Anonymous works only on public repos and is heavily rate-limited.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithToken(val)(att)
				return att, nil
			},
		),
		registry.StringConfigOption(
			"api-url",
			"GitHub REST API base URL. Defaults to https://api.github.com. For GitHub Enterprise Server set e.g. https://ghe.example.com/api/v3.",
			defaultAPIBaseURL,
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithAPIBaseURL(val)(att)
				return att, nil
			},
		),
	)
	detection.Register(Name, detectorYAML)
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(&a) }

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.hashes = ctx.Hashes()
	a.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	cwd := ctx.WorkingDir()

	// Resolve repo.
	if a.repoFlag != "" {
		a.Repo = a.repoFlag
	} else {
		repo, err := detectRepoFromGit(cwd)
		if err != nil {
			return fmt.Errorf("github-review: %w (set --attestor-github-review-repo to override)", err)
		}
		a.Repo = repo
	}

	// Resolve API base + token. Token source is recorded in the
	// predicate so verifiers can see whether reviews were captured
	// under a specific identity or anonymously.
	apiBase := a.apiURLFlag
	if apiBase == "" {
		apiBase = defaultAPIBaseURL
	}
	a.APIBaseURL = apiBase
	token, source := resolveToken(ctx.Context(), a.tokenFlag)
	a.TokenSource = source
	switch {
	case source == sourceAnonymous && os.Getenv("GITHUB_ACTIONS") == "true":
		// In GH Actions, GITHUB_TOKEN is auto-injected by the runner unless
		// the workflow explicitly nullifies it. Reaching anonymous here is
		// almost always a workflow misconfiguration — warn loudly with
		// remediation steps.
		log.Warnf("(github-review) running in GitHub Actions but no token resolved. " +
			"GITHUB_TOKEN should be auto-set by the runner — verify the step doesn't override it " +
			"via `env: { GITHUB_TOKEN: '' }` and that the workflow's `permissions:` block " +
			"includes `pull-requests: read`. Continuing anonymously: private repos and any " +
			"rate-limited endpoint will fail.")
	case source == sourceAnonymous:
		log.Warnf("(github-review) no GitHub token resolved — falling back to anonymous (60 req/hr; public repos only). " +
			"Set GH_TOKEN, GITHUB_TOKEN, or pass --attestor-github-review-token to authenticate.")
	default:
		log.Debugf("(github-review) using token from %s", source)
	}

	client := newGHClient(apiBase, token)

	// Two modes: by PR number, or by commit SHA → PRs lookup.
	if a.prFlag != "" {
		pr, err := client.fetchPR(ctx.Context(), a.Repo, a.prFlag)
		if err != nil {
			return fmt.Errorf("github-review: fetch PR %s: %w", a.prFlag, err)
		}
		a.PRs = []PR{*pr}
		if a.shaFlag != "" {
			a.CommitSHA = a.shaFlag
		} else {
			a.CommitSHA = pr.HeadSHA
		}
		return nil
	}

	// SHA mode.
	if a.shaFlag != "" {
		a.CommitSHA = a.shaFlag
	} else {
		sha, err := detectHEADSHA(cwd)
		if err != nil {
			return fmt.Errorf("github-review: %w (set --attestor-github-review-sha to override)", err)
		}
		a.CommitSHA = sha
	}

	prs, err := client.fetchPRsForCommit(ctx.Context(), a.Repo, a.CommitSHA)
	if err != nil {
		return fmt.Errorf("github-review: list PRs for %s: %w", a.CommitSHA, err)
	}
	a.PRs = prs
	return nil
}

// Subjects exposes the commit SHA, every associated PR (as "pr:<repo>#<n>"),
// and every distinct reviewer login as bundle subjects. Verifiers can pin
// policy on any of these.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	out := make(map[string]cryptoutil.DigestSet)
	add := func(key, value string) {
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(value), a.hashes)
		if err == nil {
			out[key] = ds
		}
	}

	if a.CommitSHA != "" {
		add(fmt.Sprintf("commitsha:%s", a.CommitSHA), a.CommitSHA)
	}
	if a.Repo != "" {
		add(fmt.Sprintf("repo:%s", a.Repo), a.Repo)
	}
	for _, pr := range a.PRs {
		add(fmt.Sprintf("pr:%s#%d", a.Repo, pr.Number), fmt.Sprintf("%d", pr.Number))
		for _, r := range pr.Reviews {
			add(fmt.Sprintf("reviewer:%s", r.UserLogin), r.UserLogin)
		}
	}
	return out
}

// ---- token resolution ----

// These identify which auth source produced the token at attestation
// time; the values are example provenance labels stamped into the
// predicate so verifiers can see where the token came from — they
// contain no token material. gosec G101 and the repo's
// forbidden-patterns check both flag the literal+identifier combo,
// hence the explicit "example label" annotations below.
const (
	sourceFlag         = "flag"
	sourceGHTokenEnv   = "gh-token-env"     //nolint:gosec // example label, not a secret
	sourceGHubTokenEnv = "github-token-env" //nolint:gosec // example label, not a secret
	sourceGHAuthToken  = "gh-auth-token"    //nolint:gosec // example label, not a secret
	sourceAnonymous    = "anonymous"
)

// resolveToken walks the five auth sources in precedence order and
// returns the first hit, plus an identifier for the predicate.
//
// The context is honored on the `gh auth token` fallback so a slow /
// hung gh binary can't stall an attestation indefinitely.
func resolveToken(ctx context.Context, explicit string) (string, string) {
	if explicit != "" {
		return explicit, sourceFlag
	}
	if t := strings.TrimSpace(os.Getenv("GH_TOKEN")); t != "" {
		return t, sourceGHTokenEnv
	}
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t, sourceGHubTokenEnv
	}
	if t := tryGHAuthToken(ctx); t != "" {
		return t, sourceGHAuthToken
	}
	return "", sourceAnonymous
}

// tryGHAuthToken asks the local gh CLI for its stored OAuth token. It
// fails silently if gh isn't installed or hasn't been logged in; the
// caller falls through to anonymous in that case.
func tryGHAuthToken(ctx context.Context) string {
	// 3s ceiling on the shellout — auth lookup should be near-instant.
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "gh", "auth", "token").Output() //nolint:gosec // fixed argv
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---- HTTP client ----

type ghClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newGHClient(baseURL, token string) *ghClient {
	return &ghClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: httpTimeout},
	}
}

// get issues a single GET against the GitHub REST API. The caller is
// responsible for pagination — see getPaginated for endpoints that
// return arrays.
func (c *ghClient) get(ctx context.Context, path string) (body []byte, linkHeader string, err error) {
	full := c.baseURL + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "cilock-github-review/0.1")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", full, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", full, err)
	}

	if resp.StatusCode >= 400 {
		return nil, "", buildHTTPError(resp, body, full)
	}

	return body, resp.Header.Get("Link"), nil
}

// githubErrorBody is the standard shape of an error response from
// GitHub's REST API. The Message field is what we surface to the user;
// "Resource not accessible by integration" is the signature for the
// GH Actions GITHUB_TOKEN-lacks-scope failure mode.
type githubErrorBody struct {
	Message string `json:"message"`
	DocURL  string `json:"documentation_url"`
}

// buildHTTPError turns a non-2xx GitHub response into an error with
// actionable guidance — including specific workflow-YAML snippets when
// running inside a GitHub Actions runner.
func buildHTTPError(resp *http.Response, body []byte, urlStr string) error {
	snippet := string(body)
	if len(snippet) > 256 {
		snippet = snippet[:256] + "..."
	}
	var gerr githubErrorBody
	_ = json.Unmarshal(body, &gerr) // best-effort; non-JSON bodies leave fields empty
	inActions := os.Getenv("GITHUB_ACTIONS") == "true"

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		if inActions {
			return fmt.Errorf(`GET %s: 401 unauthorized inside GitHub Actions.

The GITHUB_TOKEN this workflow received is invalid or expired. Common causes:
  - The step's `+"`env:`"+` block overrode GITHUB_TOKEN with an empty/wrong value.
  - You're running cilock under a token from a different identity that lacks repo access.
  - This is a fork PR: cross-repo workflows receive a read-only token with reduced scope.

GitHub said: %q`, urlStr, gerr.Message)
		}
		return fmt.Errorf(`GET %s: 401 unauthorized.

Token resolution chain: --attestor-github-review-token → $GH_TOKEN → $GITHUB_TOKEN → `+"`gh auth token`"+`.
Check that the token still exists, hasn't expired, and was generated for the correct GitHub host.
GitHub said: %q`, urlStr, gerr.Message)

	case http.StatusForbidden:
		// Rate limit is the cheapest case to detect.
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return fmt.Errorf("GET %s: 403 rate-limited (reset at unix %s). %s",
				urlStr, resp.Header.Get("X-RateLimit-Reset"),
				rateLimitHint(inActions, gerr.Message))
		}
		// "Resource not accessible by integration" is the GH Actions
		// signature for "GITHUB_TOKEN exists but doesn't have the
		// permission you need." Match that specifically.
		if inActions && strings.Contains(strings.ToLower(gerr.Message), "not accessible by integration") {
			return fmt.Errorf(`GET %s: 403 — GITHUB_TOKEN in this workflow lacks the pull-requests: read scope.

Add this to your workflow YAML (at the workflow root, or on the job running cilock):

    permissions:
      contents: read
      pull-requests: read   # ← required for github-review

If you've already declared permissions: at the workflow root, make sure pull-requests: read
is in the list — declaring permissions: switches off all defaults, you must enumerate what
you need.

Reference: https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token

GitHub said: %q`, urlStr, gerr.Message)
		}
		if inActions {
			return fmt.Errorf(`GET %s: 403 forbidden inside GitHub Actions.

Most common cause: the workflow's GITHUB_TOKEN doesn't have the required scope. Add to your workflow YAML:

    permissions:
      pull-requests: read

Other possibilities: the org has restricted GITHUB_TOKEN scope at the repo level, or this is a
fork-PR workflow run (cross-repo runs get a read-only token).

GitHub said: %q`, urlStr, gerr.Message)
		}
		return fmt.Errorf(`GET %s: 403 forbidden.

Your PAT may lack the required scope. For github-review you need at minimum:
  - 'repo' scope on a classic PAT (full repo access), OR
  - 'public_repo' for public repositories only, OR
  - a fine-grained PAT with "Pull requests: Read" permission on the target repo.

GitHub said: %q`, urlStr, gerr.Message)

	case http.StatusNotFound:
		return fmt.Errorf(`GET %s: 404 not found.

Check that the repo (owner/name), commit SHA, and PR number are correct.
For private repos: confirm the resolved token has access to this repo.
GitHub said: %q`, urlStr, gerr.Message)

	default:
		return fmt.Errorf("GET %s: HTTP %d (response: %s)", urlStr, resp.StatusCode, snippet)
	}
}

// rateLimitHint adapts the rate-limit error message to the runtime
// environment — anonymous-in-Actions is a different remediation from
// anonymous-on-laptop.
func rateLimitHint(inActions bool, gerrMsg string) string {
	if inActions {
		return fmt.Sprintf(`Inside GitHub Actions: this run hit the rate limit despite having a token. That usually means GITHUB_TOKEN didn't propagate to this step — check your `+"`env:`"+` and `+"`permissions:`"+` blocks. GitHub said: %q`, gerrMsg)
	}
	return fmt.Sprintf(`Pass a token via --attestor-github-review-token, GH_TOKEN, or GITHUB_TOKEN env to raise the limit from 60/hr (anonymous) to 5000/hr (authenticated). GitHub said: %q`, gerrMsg)
}

// getPaginated concatenates JSON arrays across all Link-header pages.
// GitHub uses RFC 5988 Link headers for pagination.
func (c *ghClient) getPaginated(ctx context.Context, path string) ([]json.RawMessage, error) {
	// Honor existing query params; append per_page if not present.
	parsed, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	q := parsed.Query()
	if q.Get("per_page") == "" {
		q.Set("per_page", fmt.Sprintf("%d", defaultPerPage))
	}
	parsed.RawQuery = q.Encode()

	var all []json.RawMessage
	next := parsed.String()
	for next != "" {
		body, linkHeader, err := c.get(ctx, next)
		if err != nil {
			return nil, err
		}
		var page []json.RawMessage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode page as JSON array: %w", err)
		}
		all = append(all, page...)
		next = parseNextLink(linkHeader, c.baseURL)
	}
	return all, nil
}

// parseNextLink extracts the rel="next" URL from an RFC 5988 Link
// header, then trims the base URL so we can pass a relative path back
// into get(). Returns "" when there's no next page.
func parseNextLink(header, baseURL string) string {
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		l := strings.Index(part, "<")
		r := strings.Index(part, ">")
		if l < 0 || r <= l {
			continue
		}
		full := part[l+1 : r]
		trimmed := strings.TrimRight(baseURL, "/")
		return strings.TrimPrefix(full, trimmed)
	}
	return ""
}

// ---- domain fetchers (same signatures as the original) ----

func (c *ghClient) fetchPRsForCommit(ctx context.Context, repo, sha string) ([]PR, error) {
	raws, err := c.getPaginated(ctx, fmt.Sprintf("repos/%s/commits/%s/pulls", repo, sha))
	if err != nil {
		return nil, err
	}
	out := make([]PR, 0, len(raws))
	for _, raw := range raws {
		var p ghPull
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("decode PR entry: %w", err)
		}
		reviews, err := c.fetchReviews(ctx, repo, fmt.Sprintf("%d", p.Number))
		if err != nil {
			return nil, err
		}
		out = append(out, PR{
			Number:  p.Number,
			State:   p.mergedOrState(),
			HeadSHA: p.Head.SHA,
			BaseSHA: p.Base.SHA,
			URL:     p.HTMLURL,
			Reviews: reviews,
		})
	}
	return out, nil
}

func (c *ghClient) fetchPR(ctx context.Context, repo, prNum string) (*PR, error) {
	body, _, err := c.get(ctx, fmt.Sprintf("repos/%s/pulls/%s", repo, prNum))
	if err != nil {
		return nil, err
	}
	var p ghPull
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode PR JSON: %w", err)
	}
	reviews, err := c.fetchReviews(ctx, repo, prNum)
	if err != nil {
		return nil, err
	}
	return &PR{
		Number:  p.Number,
		State:   p.mergedOrState(),
		HeadSHA: p.Head.SHA,
		BaseSHA: p.Base.SHA,
		URL:     p.HTMLURL,
		Reviews: reviews,
	}, nil
}

func (c *ghClient) fetchReviews(ctx context.Context, repo, prNum string) ([]Review, error) {
	raws, err := c.getPaginated(ctx, fmt.Sprintf("repos/%s/pulls/%s/reviews", repo, prNum))
	if err != nil {
		return nil, err
	}
	out := make([]Review, 0, len(raws))
	for _, raw := range raws {
		var r ghReview
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode review entry: %w", err)
		}
		out = append(out, Review{
			State:       r.State,
			UserLogin:   r.User.Login,
			SubmittedAt: r.SubmittedAt,
			CommitID:    r.CommitID,
		})
	}
	return out, nil
}

// ---- GitHub API DTOs ----

type ghPull struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	Merged  bool   `json:"merged"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		SHA string `json:"sha"`
	} `json:"base"`
}

func (p ghPull) mergedOrState() string {
	if p.Merged {
		return "merged"
	}
	return p.State
}

type ghReview struct {
	State string `json:"state"`
	User  struct {
		Login string `json:"login"`
	} `json:"user"`
	SubmittedAt string `json:"submitted_at"`
	CommitID    string `json:"commit_id"`
}

// ---- local git helpers (no network) ----

// detectRepoFromGit reads the origin remote URL from a git checkout and
// returns the owner/name path. Supports both https and ssh URL forms.
func detectRepoFromGit(cwd string) (string, error) {
	out, err := runGit(cwd, "remote", "get-url", "origin")
	if err != nil {
		return "", fmt.Errorf("git remote get-url: %w", err)
	}
	return parseRepoFromURL(strings.TrimSpace(out))
}

func parseRepoFromURL(remote string) (string, error) {
	s := strings.TrimSpace(remote)
	s = strings.TrimSuffix(s, ".git")
	if i := strings.Index(s, "github.com"); i >= 0 {
		s = s[i+len("github.com"):]
		s = strings.TrimLeft(s, ":/")
		if strings.Count(s, "/") < 1 {
			return "", fmt.Errorf("could not parse owner/repo from %q", remote)
		}
		parts := strings.SplitN(s, "/", 3)
		if len(parts) < 2 {
			return "", fmt.Errorf("could not parse owner/repo from %q", remote)
		}
		return parts[0] + "/" + parts[1], nil
	}
	return "", fmt.Errorf("not a github.com remote: %q", remote)
}

func detectHEADSHA(cwd string) (string, error) {
	out, err := runGit(cwd, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// runGit shells out to local git. The args are hard-coded in this file
// ("remote get-url", "rev-parse HEAD"), never user-supplied — hence
// the gosec suppression.
func runGit(cwd string, args ...string) (string, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // args sourced internally
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
