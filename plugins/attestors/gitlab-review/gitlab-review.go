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

// Package gitlab_review attests the GitLab merge request review state of a
// commit: the merge request(s) that brought it in, their diff versions,
// every approval with the exact sha it binds to, the approval rules and
// settings the tier offers, the pipelines and statuses for the reviewed head,
// and unresolved discussions. Design: docs/design/gitlab-api-attestors.md
// (monorepo), sections 2, 3 and 8.
//
// Rules the code keeps (and the tests pin):
//
//   - An approval counts only for the exact sha it approved (Cole,
//     2026-09-29). GitLab records no sha per approval; gitlabreview.BoundHead
//     derives it from the diff versions and the predicate records it per
//     approval. GitLab's `approved` flag and per-rule `approved` are recorded,
//     never evaluated.
//   - The tier is detected once and recorded. A tier-gated read the detected
//     tier lacks is recorded as `unavailable` with its reason. A failed read of
//     anything the tier has (401, 403, 5xx, transport, malformed) fails the
//     attestor: nothing is recorded.
//   - Ids, never names: subjects are keyed by instance-qualified project,
//     merge request and user ids. Names are recorded for display only.
//   - Every list is paginated to exhaustion; a cap never feeds a count.
//   - The token comes from a flag or one named environment variable, never
//     CI_JOB_TOKEN (its 404 on a paid route would read as a missing tier) and
//     never anonymous. Only named fields are recorded, never a raw body.
package gitlab_review

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/gitlabreview"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "gitlab-review"
	Type    = "https://aflock.ai/attestations/gitlab-review/v0.1"
	RunType = attestation.PreMaterialRunType

	// DefaultTokenEnv is the variable the read_api token is read from when
	// --attestor-gitlab-review-token-env names none.
	DefaultTokenEnv = "GITLAB_REVIEW_TOKEN"

	// DefaultClockSkewMillis is the clock guard used unless the operator
	// declares one. approved_at (web node) and a version's created_at (the
	// Sidekiq node that ran the refresh) come from different clocks on a
	// multi-node GitLab, gitlab.com included; with the Sidekiq clock behind, a
	// parent-sha approval can be stamped after the head's version and bind to
	// the head. An approval within the guard of any version binds to nothing.
	// 0 is for an install with one clock, and is recorded as clock_skew_ms.
	DefaultClockSkewMillis int64 = 60_000
)

var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
)

// Attestor is the gitlab-review predicate.
type Attestor struct {
	apiURLFlag, tokenEnvFlag, projectFlag, shaFlag, mrFlag string
	tierFlag                                               string
	skewMillis                                             int64
	getenv                                                 func(string) string
	hashes                                                 []cryptoutil.DigestValue

	Instance       Instance       `json:"instance"`
	Tier           Tier           `json:"tier"`
	ProjectID      int64          `json:"project_id"`
	CommitSHA      string         `json:"commit_sha"`
	FetchedAt      string         `json:"fetched_at"`
	TokenSource    string         `json:"token_source"`
	ClockSkewMs    int64          `json:"clock_skew_ms"`
	MergeRequests  []MergeRequest `json:"merge_requests"`
	instanceHostID string
}

// Instance is GET /version plus the API base the attestor read.
type Instance struct {
	APIURL string `json:"api_url"`
	// Host is the API origin's host[:port], the value a policy pins: the job
	// chooses CI_API_V4_URL, so an unpinned instance is whatever server the
	// job pointed the attestor at.
	Host       string `json:"host"`
	Version    string `json:"version"`
	Revision   string `json:"revision"`
	Enterprise bool   `json:"enterprise"`
}

// Tier is the detected plan and how it was detected.
type Tier struct {
	Plan       string `json:"plan"` // free | premium | ultimate
	DetectedBy string `json:"detected_by"`
}

// Unavailable says why a tier-gated field is absent.
type Unavailable struct {
	Tier    string `json:"tier"`
	Feature string `json:"feature"`
	Request string `json:"request"`
	Status  int    `json:"status"`           // 0: not attempted
	Reason  string `json:"reason,omitempty"` // set when not attempted
}

// MergeRequest is one merge request that brought commit_sha in.
type MergeRequest struct {
	ID              int64     `json:"id"`
	IID             int64     `json:"iid"`
	ProjectID       int64     `json:"project_id"`
	SourceProjectID int64     `json:"source_project_id"`
	TargetProjectID int64     `json:"target_project_id"`
	State           string    `json:"state"`
	SourceBranch    string    `json:"source_branch"`
	TargetBranch    string    `json:"target_branch"`
	AuthorID        int64     `json:"author_id"`
	HeadSHA         string    `json:"head_sha"`
	BaseSHA         string    `json:"base_sha"`
	MergeCommitSHA  string    `json:"merge_commit_sha,omitempty"`
	SquashCommitSHA string    `json:"squash_commit_sha,omitempty"`
	MergedAt        string    `json:"merged_at,omitempty"`
	MergeUser       *User     `json:"merge_user,omitempty"`
	Relation        string    `json:"relation"` // merge_commit | squash_commit | head
	Versions        []Version `json:"versions"`
	// Retargets are the MR's target-branch changes, from its system notes.
	// An approval given at or before the last reset boundary (a retarget, or a
	// version that repeats the previous head) binds to nothing.
	Retargets       []Retarget       `json:"retargets"`
	Approvals       []Approval       `json:"approvals"`
	ApprovedFlag    ApprovedFlag     `json:"approved_flag"`
	ApprovalState   *ApprovalState   `json:"approval_state,omitempty"`
	ApprovalSetting *ApprovalSetting `json:"approval_settings,omitempty"`
	Unavailable     []Unavailable    `json:"unavailable,omitempty"`
	Pipelines       []Pipeline       `json:"pipelines"`
	CommitStatuses  []CommitStatus   `json:"commit_statuses"`
	Discussions     Discussions      `json:"discussions"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type Version struct {
	ID            int64  `json:"id"`
	HeadCommitSHA string `json:"head_commit_sha"`
	BaseCommitSHA string `json:"base_commit_sha"`
	CreatedAt     string `json:"created_at"`
	State         string `json:"state"`
	PatchIDSHA    string `json:"patch_id_sha,omitempty"`
}

// Approval is one approval with the exact sha it binds to (null when the
// timeline cannot bind it; an unbound approval counts for nothing).
type Approval struct {
	UserID       int64   `json:"user_id"`
	Username     string  `json:"username"`
	ApprovedAt   string  `json:"approved_at"`
	BoundHeadSHA *string `json:"bound_head_sha"`
	Binding      string  `json:"binding"` // timeline | unbound | before_retarget
}

// Retarget is one "changed target branch from `X` to `Y`" system note.
type Retarget struct {
	From   string `json:"from"`
	To     string `json:"to"`
	At     string `json:"at"`
	NoteID int64  `json:"note_id"`
}

// ApprovedFlag is GitLab's `approved`, recorded with its edition semantics
// and never evaluated (on EE it is true with zero approvals when no rule
// applies; seen on gitlab.com Ultimate, design doc section 1.4).
type ApprovedFlag struct {
	Value             bool   `json:"value"`
	EditionSemantics  string `json:"edition_semantics"` // ce-any-approval | ee-rules-satisfied
	NeverEvaluatedDoc string `json:"note"`
}

type ApprovalState struct {
	ApprovalRulesOverwritten bool   `json:"approval_rules_overwritten"`
	Rules                    []Rule `json:"rules"`
}

type Rule struct {
	ID                  int64   `json:"id"`
	Name                string  `json:"name"`
	RuleType            string  `json:"rule_type"`
	ReportType          string  `json:"report_type,omitempty"`
	ApprovalsRequired   int     `json:"approvals_required"`
	Approved            bool    `json:"approved"`
	ApprovedByIDs       []int64 `json:"approved_by_ids"`
	EligibleApproverIDs []int64 `json:"eligible_approver_ids"`
	Overridden          bool    `json:"overridden"`
}

type ApprovalSetting struct {
	ResetApprovalsOnPush                      bool `json:"reset_approvals_on_push"`
	SelectiveCodeOwnerRemovals                bool `json:"selective_code_owner_removals"`
	MergeRequestsAuthorApproval               bool `json:"merge_requests_author_approval"`
	MergeRequestsDisableCommittersApproval    bool `json:"merge_requests_disable_committers_approval"`
	DisableOverridingApproversPerMergeRequest bool `json:"disable_overriding_approvers_per_merge_request"`
	RequireReauthenticationToApprove          bool `json:"require_reauthentication_to_approve"`
}

type Pipeline struct {
	ID        int64  `json:"id"`
	IID       int64  `json:"iid"`
	ProjectID int64  `json:"project_id"`
	SHA       string `json:"sha"`
	Ref       string `json:"ref"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

type CommitStatus struct {
	ID int64 `json:"id"`
	// ProjectID is the project the status was read from (the target, or a
	// fork MR's source project). GitLab's statuses API does not return it.
	ProjectID    int64  `json:"project_id"`
	SHA          string `json:"sha"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	AllowFailure bool   `json:"allow_failure"`
}

type Discussions struct {
	Resolvable int                `json:"resolvable"`
	Resolved   int                `json:"resolved"`
	Unresolved []UnresolvedThread `json:"unresolved"`
}

type UnresolvedThread struct {
	DiscussionID string `json:"discussion_id"`
	NoteID       int64  `json:"note_id"`
}

// GitLab field names the response shapes name more than once.
const (
	keySHA        = "sha"
	keyApprovedBy = "approved_by"
	keyProjectID  = "project_id"
	keyName       = "name"
)

func (*ApprovalSetting) shape() shape {
	return shape{keys: []string{"reset_approvals_on_push", "selective_code_owner_removals", "merge_requests_author_approval",
		"merge_requests_disable_committers_approval", "disable_overriding_approvers_per_merge_request",
		"require_reauthentication_to_approve"}}
}

func (*Version) shape() shape {
	return shape{keys: []string{"id", "head_commit_sha", "base_commit_sha", "created_at"}}
}

func (*Pipeline) shape() shape { return shape{keys: []string{"id", keyProjectID, keySHA, "status"}} }

func (*CommitStatus) shape() shape {
	return shape{keys: []string{"id", keySHA, keyName, "status", "allow_failure"}}
}

// Probe responses establish the tier even though the services themselves
// are not recorded. Validate the documented identity and service fields.
type apiExternalStatusCheck struct {
	ID          int64  `json:"id"`
	ProjectID   int64  `json:"project_id"`
	Name        string `json:"name"`
	ExternalURL string `json:"external_url"`
}

func (*apiExternalStatusCheck) shape() shape {
	return shape{keys: []string{"id", keyProjectID, keyName, "external_url"},
		check: func(m map[string]json.RawMessage) error {
			if err := positiveID(m["id"]); err != nil {
				return err
			}
			return positiveID(m[keyProjectID])
		}}
}

type Option func(*Attestor)

func WithAPIURL(u string) Option         { return func(a *Attestor) { a.apiURLFlag = u } }
func WithTokenEnv(n string) Option       { return func(a *Attestor) { a.tokenEnvFlag = n } }
func WithProject(p string) Option        { return func(a *Attestor) { a.projectFlag = p } }
func WithSHA(s string) Option            { return func(a *Attestor) { a.shaFlag = s } }
func WithMR(iid string) Option           { return func(a *Attestor) { a.mrFlag = iid } }
func WithClockSkewMillis(n int64) Option { return func(a *Attestor) { a.skewMillis = n } }

// WithTier declares the GitLab plan (free, premium, ultimate) instead of
// detecting it by probe.
func WithTier(plan string) Option { return func(a *Attestor) { a.tierFlag = plan } }

// withEnv injects the environment (tests).
func withEnv(getenv func(string) string) Option { return func(a *Attestor) { a.getenv = getenv } }

// parseClockSkew reads --attestor-gitlab-review-clock-skew-ms: a whole,
// non-negative number of milliseconds. A negative guard would disable it.
func parseClockSkew(v string) (int64, error) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("gitlab-review: clock-skew-ms %q must be a whole number of milliseconds >= 0", v)
	}
	return n, nil
}

func New(opts ...Option) *Attestor {
	a := &Attestor{getenv: os.Getenv, skewMillis: DefaultClockSkewMillis}
	for _, o := range opts {
		o(a)
	}
	return a
}

// setString adapts a field setter to a registry string option. Each option is
// registered with its name spelled out at the registry call, where the web
// configuration test (and a reader) can find it.
func setString(set func(*Attestor, string)) func(attestation.Attestor, string) (attestation.Attestor, error) {
	return func(a attestation.Attestor, v string) (attestation.Attestor, error) {
		att, ok := a.(*Attestor)
		if !ok {
			return a, fmt.Errorf("invalid attestor type: %T", a)
		}
		set(att, v)
		return att, nil
	}
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		registry.StringConfigOption("api-url", "GitLab REST v4 base URL with canonical /api/v4 path. Defaults to $CI_API_V4_URL; there is no default host.", "",
			setString(func(a *Attestor, v string) { a.apiURLFlag = v })),
		registry.StringConfigOption("token-env", "Environment variable holding a read_api token (Maintainer for the approval settings). Default "+DefaultTokenEnv+". CI_JOB_TOKEN is refused.", "",
			setString(func(a *Attestor, v string) { a.tokenEnvFlag = v })),
		registry.StringConfigOption("project", "Project id. Defaults to $CI_PROJECT_ID.", "", setString(func(a *Attestor, v string) { a.projectFlag = v })),
		registry.StringConfigOption("sha", "Commit to attest. Defaults to $CI_COMMIT_SHA, then `git rev-parse HEAD`.", "", setString(func(a *Attestor, v string) { a.shaFlag = v })),
		registry.StringConfigOption("mr", "Merge request iid to attest directly, instead of the MRs that brought the commit in.", "",
			setString(func(a *Attestor, v string) { a.mrFlag = v })),
		registry.StringConfigOption("clock-skew-ms",
			"Clock guard in milliseconds: an approval this close to any diff version binds to no sha. Default 60000 (multi-node GitLab, gitlab.com). 0 only for an install with one clock; the value is recorded.",
			"", func(at attestation.Attestor, v string) (attestation.Attestor, error) {
				a, ok := at.(*Attestor)
				if !ok {
					return at, fmt.Errorf("invalid attestor type: %T", at)
				}
				if v == "" {
					return a, nil
				}
				n, err := parseClockSkew(v)
				a.skewMillis = n
				return a, err
			}),
		registry.StringConfigOption("tier", "Declare the GitLab plan (free, premium, ultimate) instead of detecting it by probe; recorded as detected_by operator. Reads above it are not attempted and are recorded unavailable.", "",
			setString(func(a *Attestor, v string) { a.tierFlag = v })),
	)
	detection.Register(Name, detectorYAML)
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(&a) }

// Attest reads the review state. Any failure to observe returns an error and
// records nothing (an empty merge_requests list would satisfy "every MR was
// reviewed" vacuously).
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.hashes = ctx.Hashes()
	a.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	a.ClockSkewMs = a.skewMillis
	if a.skewMillis < 0 {
		return fmt.Errorf("gitlab-review: clock guard %d ms is negative; it would disable the guard", a.skewMillis)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := a.resolveTarget(ctx.WorkingDir()); err != nil {
		return err
	}
	if err := a.readInstance(c); err != nil {
		return err
	}
	if err := a.detectTier(c); err != nil {
		return err
	}
	mrs, err := a.candidateMRs(c)
	if err != nil {
		return err
	}
	for _, m := range mrs {
		mr, err := a.readMR(c, m)
		if err != nil {
			return err
		}
		a.MergeRequests = append(a.MergeRequests, mr)
	}
	return nil
}

func (a *Attestor) client() (*client, error) {
	base := a.apiURLFlag
	if base == "" {
		base = a.getenv("CI_API_V4_URL")
	}
	if base == "" {
		return nil, fmt.Errorf("gitlab-review: no API base: set --attestor-gitlab-review-api-url or run in a GitLab CI job ($CI_API_V4_URL)")
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, fmt.Errorf("gitlab-review: the API base is not a URL")
	}
	if err := validateAPIBase(u); err != nil {
		return nil, err
	}
	envName := a.tokenEnvFlag
	if envName == "" {
		envName = DefaultTokenEnv
	}
	if envName == "CI_JOB_TOKEN" {
		return nil, fmt.Errorf("gitlab-review: CI_JOB_TOKEN cannot read approvals, versions or discussions; give a read_api token in $%s", DefaultTokenEnv)
	}
	tok := strings.TrimSpace(a.getenv(envName))
	if tok == "" {
		return nil, fmt.Errorf("gitlab-review: $%s is empty; it must hold a read_api token (Maintainer to read approval settings)", envName)
	}
	a.TokenSource = "env:" + envName
	a.Instance.APIURL = u.String()
	a.Instance.Host = u.Host
	a.instanceHostID = u.Host
	return &client{base: u.String(), token: tok}, nil
}

func validateAPIBase(u *url.URL) error {
	// The base is recorded in the signed predicate (instance.api_url): it
	// carries no credentials, and a refusal does not repeat them.
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("gitlab-review: the API base must not carry credentials, a query or a fragment (host %q); give the token in $%s", u.Host, DefaultTokenEnv)
	}
	if u.Hostname() == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return fmt.Errorf("gitlab-review: API base %q must be https (or http to loopback)", u.String())
	}
	// Pin the API root as well as its host: raw repository files on the same
	// host are attacker-controlled and can imitate every response we record.
	// Loopback fixture servers may mount the API directly at their root.
	if u.RawPath != "" || (u.Path != "/api/v4" && !(isLoopback(u.Hostname()) && u.Path == "")) {
		return fmt.Errorf("gitlab-review: API base must use the canonical /api/v4 root (host %q)", u.Host)
	}
	return nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func (a *Attestor) resolveTarget(cwd string) error {
	p := a.projectFlag
	if p == "" {
		p = a.getenv("CI_PROJECT_ID")
	}
	id, err := strconv.ParseInt(p, 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("gitlab-review: project id %q is not a number: set --attestor-gitlab-review-project or $CI_PROJECT_ID", p)
	}
	a.ProjectID = id
	sha := a.shaFlag
	if sha == "" {
		sha = a.getenv("CI_COMMIT_SHA")
	}
	if sha == "" {
		out, gerr := exec.Command("git", "-C", cwd, "rev-parse", "HEAD").Output() //nolint:gosec // fixed argv
		if gerr != nil {
			return fmt.Errorf("gitlab-review: no commit to attest: %w", gerr)
		}
		sha = strings.TrimSpace(string(out))
	}
	a.CommitSHA = sha
	return nil
}

func (a *Attestor) readInstance(c *client) error {
	var v apiVersion
	if st, err := c.get("/version", &v); err != nil || st != 200 {
		return c.fail("/version", st, err)
	}
	a.Instance.Version, a.Instance.Revision, a.Instance.Enterprise = v.Version, v.Revision, v.Enterprise
	return nil
}

type apiVersion struct {
	Version, Revision string
	Enterprise        bool
}

func (*apiVersion) shape() shape { return shape{keys: []string{"version", "revision", "enterprise"}} }

// detectTier is design doc section 2.7 rule 1, by probe: CE is free; on EE a
// Premium route (project approval settings) answering 200 means Premium or
// better, and an Ultimate route (external status checks) answering 200 means
// Ultimate. A 404 is the tier lacking the feature; anything else is loud.
func (a *Attestor) detectTier(c *client) error {
	if a.tierFlag != "" {
		if _, ok := planRank[a.tierFlag]; !ok {
			return fmt.Errorf("gitlab-review: tier %q is not free, premium or ultimate", a.tierFlag)
		}
		if !a.Instance.Enterprise && a.tierFlag != planFree {
			return fmt.Errorf("gitlab-review: tier %q declared, but GET /version says this is Community Edition", a.tierFlag)
		}
		a.Tier = Tier{Plan: a.tierFlag, DetectedBy: "operator"}
		return nil
	}
	if !a.Instance.Enterprise {
		a.Tier = Tier{Plan: planFree, DetectedBy: "GET /version enterprise=false"}
		return nil
	}
	premium := fmt.Sprintf("/projects/%d/approvals", a.ProjectID)
	var settings ApprovalSetting
	st, err := c.get(premium, &settings)
	switch {
	case err != nil:
		return c.fail(premium, st, err)
	case st == 404:
		a.Tier = Tier{Plan: planFree, DetectedBy: "GET " + premium + " 404"}
		return nil
	case st != 200:
		return c.fail(premium, st, nil)
	}
	ultimate := fmt.Sprintf("/projects/%d/external_status_checks", a.ProjectID)
	var services []apiExternalStatusCheck
	st, err = c.get(ultimate, &services)
	switch {
	case err != nil:
		return c.fail(ultimate, st, err)
	case st == 200:
		a.Tier = Tier{Plan: planUltimate, DetectedBy: "GET " + ultimate + " 200"}
	case st == 404:
		a.Tier = Tier{Plan: planPremium, DetectedBy: "GET " + ultimate + " 404"}
	default:
		return c.fail(ultimate, st, nil)
	}
	return nil
}

// The plan names GitLab's docs and --tier use.
const (
	planFree     = "free"
	planPremium  = "premium"
	planUltimate = "ultimate"
)

var planRank = map[string]int{planFree: 0, planPremium: 1, planUltimate: 2}

// tiered reads a tier-gated route: the model's `collect`
// (formal/cilock-ci CilockCi/Tier.lean). A 404 is `unavailable` only when
// the feature needs a plan above the detected one; otherwise it is loud.
func (a *Attestor) tiered(c *client, needs, feature, path string, out any) (*Unavailable, error) {
	if a.Tier.DetectedBy == "operator" && planRank[needs] > planRank[a.Tier.Plan] {
		return &Unavailable{Tier: a.Tier.Plan, Feature: feature, Request: "GET " + path,
			Reason: "not read: needs " + needs + ", the operator declared " + a.Tier.Plan}, nil
	}
	st, err := c.get(path, out)
	switch {
	case err != nil:
		return nil, c.fail(path, st, err)
	case st == 200:
		return nil, nil
	case st == 404 && planRank[needs] > planRank[a.Tier.Plan]:
		return &Unavailable{Tier: a.Tier.Plan, Feature: feature, Request: "GET " + path, Status: st}, nil
	default:
		return nil, c.fail(path, st, nil)
	}
}

type apiMR struct {
	ID              int64   `json:"id"`
	IID             int64   `json:"iid"`
	ProjectID       int64   `json:"project_id"`
	SourceProjectID int64   `json:"source_project_id"`
	TargetProjectID int64   `json:"target_project_id"`
	State           string  `json:"state"`
	SourceBranch    string  `json:"source_branch"`
	TargetBranch    string  `json:"target_branch"`
	SHA             string  `json:"sha"`
	MergeCommitSHA  *string `json:"merge_commit_sha"`
	SquashCommitSHA *string `json:"squash_commit_sha"`
	MergedAt        *string `json:"merged_at"`
	Author          struct {
		ID int64 `json:"id"`
	} `json:"author"`
	MergeUser *User `json:"merge_user"`
	DiffRefs  struct {
		BaseSHA string `json:"base_sha"`
	} `json:"diff_refs"`
}

// The author must name a real user: author_id feeds the rule that excludes
// the author's own approval. merge_user is null until the MR merges.
func (*apiMR) shape() shape {
	return shape{keys: []string{"id", "iid", "project_id", "source_project_id", "target_project_id", "state", keySHA,
		"source_branch", "target_branch"},
		check: func(m map[string]json.RawMessage) error {
			if err := userRef(m, "author", false); err != nil {
				return err
			}
			if _, ok := m["merge_user"]; !ok {
				return nil
			}
			return userRef(m, "merge_user", true)
		}}
}

func (a *Attestor) candidateMRs(c *client) ([]apiMR, error) {
	var found []apiMR
	if a.mrFlag != "" {
		var m apiMR
		p := fmt.Sprintf("/projects/%d/merge_requests/%s", a.ProjectID, url.PathEscape(a.mrFlag))
		if st, err := c.get(p, &m); err != nil || st != 200 {
			return nil, c.fail(p, st, err)
		}
		return []apiMR{m}, nil
	}
	p := fmt.Sprintf("/projects/%d/repository/commits/%s/merge_requests", a.ProjectID, url.PathEscape(a.CommitSHA))
	var list []apiMR
	if err := c.getAll(p, &list); err != nil {
		return nil, err
	}
	for _, m := range list {
		if relation(m, a.CommitSHA) != "" {
			found = append(found, m)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("gitlab-review: no merge request brought %s in (as its head, merge commit or squash commit); nothing to attest", a.CommitSHA)
	}
	return found, nil
}

func relation(m apiMR, t string) string {
	switch {
	case m.MergeCommitSHA != nil && *m.MergeCommitSHA == t:
		return "merge_commit"
	case m.SquashCommitSHA != nil && *m.SquashCommitSHA == t:
		return "squash_commit"
	case m.SHA == t:
		return "head"
	}
	return ""
}

func (a *Attestor) readMR(c *client, cand apiMR) (MergeRequest, error) {
	base := fmt.Sprintf("/projects/%d/merge_requests/%d", a.ProjectID, cand.IID)
	var m apiMR
	if st, err := c.get(base, &m); err != nil || st != 200 {
		return MergeRequest{}, c.fail(base, st, err)
	}
	out := mrHeader(m, a.CommitSHA)
	if out.BaseSHA == "" {
		return MergeRequest{}, fmt.Errorf("gitlab-review: GET %s: malformed body: field \"diff_refs.base_sha\" is missing", base)
	}
	if out.Relation == "" {
		return MergeRequest{}, fmt.Errorf("gitlab-review: merge request !%d no longer relates to %s", m.IID, a.CommitSHA)
	}

	var versions []Version
	if err := c.getAll(base+"/versions", &versions); err != nil {
		return MergeRequest{}, err
	}
	out.Versions = versions
	bvs, err := timeline(versions)
	if err != nil {
		return MergeRequest{}, err
	}
	retargets, resetAt, haveReset, err := readResets(c, base, bvs)
	if err != nil {
		return MergeRequest{}, err
	}
	out.Retargets = retargets

	ap, err := readApprovals(c, base)
	if err != nil {
		return MergeRequest{}, err
	}
	out.ApprovedFlag = a.approvedFlag(ap)
	if out.Approvals, err = a.bindApprovals(m.IID, ap, bvs, haveReset, resetAt); err != nil {
		return MergeRequest{}, err
	}
	if err := a.readApprovalState(c, base, &out); err != nil {
		return MergeRequest{}, err
	}
	if err := a.readApprovalSetting(c, &out); err != nil {
		return MergeRequest{}, err
	}

	if err := a.readCI(c, &out); err != nil {
		return MergeRequest{}, err
	}
	if out.Discussions, err = readDiscussions(c, base); err != nil {
		return MergeRequest{}, err
	}
	if err := a.unchanged(c, base, m, len(versions), ap, out); err != nil {
		return MergeRequest{}, err
	}
	return out, nil
}

// approvedFlag records GitLab's approved flag, which means different things
// on CE and EE and is never evaluated.
func (a *Attestor) approvedFlag(ap apiApprovals) ApprovedFlag {
	f := ApprovedFlag{Value: ap.Approved, EditionSemantics: "ce-any-approval",
		NeverEvaluatedDoc: "recorded, never evaluated; count bound approvals"}
	if a.Instance.Enterprise {
		f.EditionSemantics = "ee-rules-satisfied"
	}
	return f
}

// readCI records the pipelines and commit statuses on the MR's head, in the
// target project and, for a fork MR, in the source project where the head's
// own pipelines run. An unreadable fork is loud, never an empty inventory.
func (a *Attestor) readCI(c *client, out *MergeRequest) error {
	projects := []int64{a.ProjectID}
	if out.SourceProjectID != 0 && out.SourceProjectID != a.ProjectID {
		projects = append(projects, out.SourceProjectID)
	}
	out.Pipelines, out.CommitStatuses = []Pipeline{}, []CommitStatus{}
	for _, p := range projects {
		var pipelines []Pipeline
		if err := c.getAll(fmt.Sprintf("/projects/%d/pipelines?sha=%s", p, url.QueryEscape(out.HeadSHA)), &pipelines); err != nil {
			return err
		}
		var statuses []CommitStatus
		if err := c.getAll(fmt.Sprintf("/projects/%d/repository/commits/%s/statuses?all=true", p, url.PathEscape(out.HeadSHA)), &statuses); err != nil {
			return err
		}
		for i := range statuses {
			statuses[i].ProjectID = p
		}
		out.Pipelines = append(out.Pipelines, pipelines...)
		out.CommitStatuses = append(out.CommitStatuses, statuses...)
	}
	return nil
}

// mrHeader copies the merge request's own fields; Relation is "" when the MR
// no longer brings the attested commit in.
func mrHeader(m apiMR, commit string) MergeRequest {
	out := MergeRequest{ID: m.ID, IID: m.IID, ProjectID: m.ProjectID, SourceProjectID: m.SourceProjectID,
		TargetProjectID: m.TargetProjectID, State: m.State, SourceBranch: m.SourceBranch, TargetBranch: m.TargetBranch,
		AuthorID: m.Author.ID, HeadSHA: m.SHA, BaseSHA: m.DiffRefs.BaseSHA, MergeUser: m.MergeUser,
		Relation: relation(m, commit)}
	if m.MergeCommitSHA != nil {
		out.MergeCommitSHA = *m.MergeCommitSHA
	}
	if m.SquashCommitSHA != nil {
		out.SquashCommitSHA = *m.SquashCommitSHA
	}
	if m.MergedAt != nil {
		out.MergedAt = *m.MergedAt
	}
	return out
}

// timeline is the diff versions as the binding model's (head, created-at ms).
func timeline(versions []Version) ([]gitlabreview.Version, error) {
	var bvs []gitlabreview.Version
	for _, v := range versions {
		t, err := millis(v.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("gitlab-review: version %d created_at %q: %w", v.ID, v.CreatedAt, err)
		}
		bvs = append(bvs, gitlabreview.Version{Head: v.HeadCommitSHA, CreatedAt: t})
	}
	return bvs, nil
}

// bindApprovals binds each approval to the head it was given on, or marks it
// before_retarget or unbound.
func (a *Attestor) bindApprovals(iid int64, ap apiApprovals, bvs []gitlabreview.Version, haveReset bool, resetAt int64) ([]Approval, error) {
	approvals := []Approval{}
	for _, x := range ap.ApprovedBy {
		if x.User.ID <= 0 {
			return nil, fmt.Errorf("gitlab-review: an approval on !%d at %s has no user id (deleted user?); it cannot be attributed", iid, x.ApprovedAt)
		}
		t, err := millis(x.ApprovedAt)
		if err != nil {
			return nil, fmt.Errorf("gitlab-review: approval by user %d approved_at %q: %w", x.User.ID, x.ApprovedAt, err)
		}
		ar := Approval{UserID: x.User.ID, Username: x.User.Username, ApprovedAt: x.ApprovedAt, Binding: "unbound"}
		switch h, ok := gitlabreview.BoundHead(a.skewMillis, bvs, t); {
		case haveReset && t <= resetAt+a.skewMillis:
			ar.Binding = "before_retarget"
		case ok:
			ar.BoundHeadSHA, ar.Binding = &h, "timeline"
		}
		approvals = append(approvals, ar)
	}
	return approvals, nil
}

type apiApprovalState struct {
	ApprovalRulesOverwritten bool `json:"approval_rules_overwritten"`
	Rules                    []struct {
		ID                int64
		Name              string
		RuleType          string `json:"rule_type"`
		ReportType        string `json:"report_type"`
		ApprovalsRequired int    `json:"approvals_required"`
		Approved          bool
		Overridden        bool
		ApprovedBy        []User `json:"approved_by"`
		EligibleApprovers []User `json:"eligible_approvers"`
	}
}

// userShape is a user reference; only its id is recorded, and it must name a
// real user.
var userShape = shape{keys: []string{"id"}, check: func(m map[string]json.RawMessage) error {
	return positiveID(m["id"])
}}

func (*apiApprovalState) shape() shape {
	rule := shape{
		keys: []string{"id", "name", "rule_type", "approvals_required", "approved", "overridden",
			keyApprovedBy, "eligible_approvers"},
		present: []string{"report_type"},
		lists:   map[string]shape{keyApprovedBy: userShape, "eligible_approvers": userShape},
	}
	return shape{keys: []string{"approval_rules_overwritten", "rules"}, lists: map[string]shape{"rules": rule}}
}

// readApprovalState records the Premium approval_state, or why it is unavailable.
func (a *Attestor) readApprovalState(c *client, base string, out *MergeRequest) error {
	var st apiApprovalState
	u, err := a.tiered(c, planPremium, "approval_state", base+"/approval_state", &st)
	if err != nil {
		return err
	}
	if u != nil {
		out.Unavailable = append(out.Unavailable, *u)
		return nil
	}
	as := &ApprovalState{ApprovalRulesOverwritten: st.ApprovalRulesOverwritten, Rules: []Rule{}}
	for _, r := range st.Rules {
		rule := Rule{ID: r.ID, Name: r.Name, RuleType: r.RuleType, ReportType: r.ReportType,
			ApprovalsRequired: r.ApprovalsRequired, Approved: r.Approved, Overridden: r.Overridden,
			ApprovedByIDs: []int64{}, EligibleApproverIDs: []int64{}}
		for _, x := range r.ApprovedBy {
			rule.ApprovedByIDs = append(rule.ApprovedByIDs, x.ID)
		}
		for _, x := range r.EligibleApprovers {
			rule.EligibleApproverIDs = append(rule.EligibleApproverIDs, x.ID)
		}
		as.Rules = append(as.Rules, rule)
	}
	out.ApprovalState = as
	return nil
}

// readApprovalSetting records the Premium project approval settings, or why
// they are unavailable.
func (a *Attestor) readApprovalSetting(c *client, out *MergeRequest) error {
	var set ApprovalSetting
	u, err := a.tiered(c, planPremium, "approval_settings", fmt.Sprintf("/projects/%d/approvals", a.ProjectID), &set)
	if err != nil {
		return err
	}
	if u != nil {
		out.Unavailable = append(out.Unavailable, *u)
	} else {
		out.ApprovalSetting = &set
	}
	return nil
}

type apiDiscussion struct {
	ID    string
	Notes []struct {
		ID         int64
		Resolvable bool
		Resolved   bool
	}
}

// A note always says whether it is resolvable; a resolvable one must say
// whether it is resolved. GitLab omits resolved on a note that cannot be.
func (*apiDiscussion) shape() shape {
	note := shape{keys: []string{"id", "resolvable"}, check: func(m map[string]json.RawMessage) error {
		if string(bytes.TrimSpace(m["resolvable"])) != "true" {
			return nil
		}
		if v, ok := m["resolved"]; !ok || isNull(v) {
			return errors.New(`a resolvable note's field "resolved" is missing or null`)
		}
		return nil
	}}
	return shape{keys: []string{"id", "notes"}, lists: map[string]shape{"notes": note}}
}

// readDiscussions counts resolvable threads. A thread is resolvable when any
// of its notes is, and resolved only when every resolvable note is; an open
// thread is named by its first unresolved note.
func readDiscussions(c *client, base string) (Discussions, error) {
	var disc []apiDiscussion
	if err := c.getAll(base+"/discussions", &disc); err != nil {
		return Discussions{}, err
	}
	out := Discussions{Unresolved: []UnresolvedThread{}}
	for _, d := range disc {
		resolvable, open := false, (*UnresolvedThread)(nil)
		for _, n := range d.Notes {
			if !n.Resolvable {
				continue
			}
			resolvable = true
			if !n.Resolved && open == nil {
				open = &UnresolvedThread{DiscussionID: d.ID, NoteID: n.ID}
			}
		}
		if !resolvable {
			continue
		}
		out.Resolvable++
		if open == nil {
			out.Resolved++
		} else {
			out.Unresolved = append(out.Unresolved, *open)
		}
	}
	return out, nil
}

type apiNote struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	System    bool   `json:"system"`
	CreatedAt string `json:"created_at"`
}

func (*apiNote) shape() shape { return shape{keys: []string{"id", "body", "system", "created_at"}} }

var retargetNote = regexp.MustCompile("^changed target branch from `([^`]+)` to `([^`]+)`$")

// readResets finds the MR's last reset boundary (design doc section 3.3,
// "Retarget"): diff versions are keyed on the head alone, so retargeting an
// MR to another branch keeps the head and every approval bound to it. Two
// signals, either one enough: a "changed target branch" system note, and a
// version whose head repeats the previous version's (no push created it). The
// second does not depend on GitLab's wording of the note.
func readResets(c *client, base string, vs []gitlabreview.Version) ([]Retarget, int64, bool, error) {
	var notes []apiNote
	if err := c.getAll(base+"/notes?sort=asc&order_by=created_at", &notes); err != nil {
		return nil, 0, false, err
	}
	retargets := []Retarget{}
	var at int64
	have := false
	for _, n := range notes {
		m := retargetNote.FindStringSubmatch(n.Body)
		if !n.System || m == nil {
			continue
		}
		t, err := millis(n.CreatedAt)
		if err != nil {
			return nil, 0, false, fmt.Errorf("gitlab-review: note %d created_at %q: %w", n.ID, n.CreatedAt, err)
		}
		retargets = append(retargets, Retarget{From: m[1], To: m[2], At: n.CreatedAt, NoteID: n.ID})
		if !have || t > at {
			at, have = t, true
		}
	}
	sorted := append([]gitlabreview.Version(nil), vs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CreatedAt < sorted[j].CreatedAt })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Head == sorted[i-1].Head && (!have || sorted[i].CreatedAt > at) {
			at, have = sorted[i].CreatedAt, true
		}
	}
	return retargets, at, have, nil
}

type apiApprovals struct {
	Approved   bool `json:"approved"`
	ApprovedBy []struct {
		ApprovedAt string `json:"approved_at"`
		User       User   `json:"user"`
	} `json:"approved_by"`
}

// An approval's user may be null (a deleted user); readMR refuses it by name.
func (*apiApprovals) shape() shape {
	return shape{keys: []string{"approved", keyApprovedBy},
		lists: map[string]shape{keyApprovedBy: {keys: []string{"approved_at"}, present: []string{"user"}}}}
}

func readApprovals(c *client, base string) (apiApprovals, error) {
	var ap apiApprovals
	if st, err := c.get(base+"/approvals", &ap); err != nil || st != 200 {
		return ap, c.fail(base+"/approvals", st, err)
	}
	return ap, nil
}

// unchanged is design doc section 2.4: after every other read, the MR, its
// version count, approvals and approval policy are read again; any difference means the
// record would mix two states, so the attestor fails and records nothing.
func (a *Attestor) unchanged(c *client, base string, first apiMR, nVersions int, firstAp apiApprovals, firstPolicy MergeRequest) error {
	var m apiMR
	if st, err := c.get(base, &m); err != nil || st != 200 {
		return c.fail(base, st, err)
	}
	var vs []Version
	if err := c.getAll(base+"/versions", &vs); err != nil {
		return err
	}
	ap, err := readApprovals(c, base)
	if err != nil {
		return err
	}
	same := m.SHA == first.SHA && m.State == first.State && m.TargetBranch == first.TargetBranch &&
		strPtr(m.MergeCommitSHA) == strPtr(first.MergeCommitSHA) &&
		strPtr(m.SquashCommitSHA) == strPtr(first.SquashCommitSHA) &&
		len(vs) == nVersions && len(ap.ApprovedBy) == len(firstAp.ApprovedBy)
	for i := 0; same && i < len(ap.ApprovedBy); i++ {
		same = ap.ApprovedBy[i].User.ID == firstAp.ApprovedBy[i].User.ID &&
			ap.ApprovedBy[i].ApprovedAt == firstAp.ApprovedBy[i].ApprovedAt
	}
	if !same {
		return fmt.Errorf("gitlab-review: merge request !%d changed while it was being read (head, state, target, versions or approvals); rerun", first.IID)
	}
	return a.unchangedApprovalPolicy(c, base, first.IID, firstPolicy)
}

func (a *Attestor) unchangedApprovalPolicy(c *client, base string, iid int64, first MergeRequest) error {
	var current MergeRequest
	if err := a.readApprovalState(c, base, &current); err != nil {
		return err
	}
	if err := a.readApprovalSetting(c, &current); err != nil {
		return err
	}
	if !reflect.DeepEqual(current.ApprovalState, first.ApprovalState) ||
		!reflect.DeepEqual(current.ApprovalSetting, first.ApprovalSetting) ||
		!reflect.DeepEqual(current.Unavailable, first.Unavailable) {
		return fmt.Errorf("gitlab-review: merge request !%d changed while it was being read (approval rules, settings or availability); rerun", iid)
	}
	return nil
}

func strPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func millis(s string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, err
	}
	return t.UnixMilli(), nil
}

// Subjects are keyed by ids (design doc section 3.5).
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	out := map[string]cryptoutil.DigestSet{}
	sha1 := func(key, sha string) {
		if sha != "" {
			out[key] = cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA1}: sha}
		}
	}
	named := func(key string) {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(key), a.hashes); err == nil {
			out[key] = ds
		}
	}
	sha1("commitsha:"+a.CommitSHA, a.CommitSHA)
	named(fmt.Sprintf("project:%s/%d", a.instanceHostID, a.ProjectID))
	for _, m := range a.MergeRequests {
		sha1("mrhead:"+m.HeadSHA, m.HeadSHA)
		named(fmt.Sprintf("mergerequest:%s/%d!%d", a.instanceHostID, m.ProjectID, m.IID))
		for _, ap := range m.Approvals {
			named(fmt.Sprintf("approver:%s/%d", a.instanceHostID, ap.UserID))
		}
	}
	return out
}

// BackRefs are the commit and the reviewed heads.
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	out := map[string]cryptoutil.DigestSet{}
	for k, v := range a.Subjects() {
		if strings.HasPrefix(k, "commitsha:") || strings.HasPrefix(k, "mrhead:") {
			out[k] = v
		}
	}
	return out
}
