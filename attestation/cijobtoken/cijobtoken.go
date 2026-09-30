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

// Package cijobtoken finds the GitLab CI job's own OIDC ID token for one
// audience.
//
// GitLab does not mint tokens on request the way GitHub Actions does. A job
// declares each token it wants under `id_tokens:`, one variable per audience,
// and the runner exports them into the job's environment. GitLab 17 removed
// the old ambient CI_JOB_JWT, so these declared tokens are the only job
// identity a GitLab 17+ job has.
//
// Select is the one place cilock decides which of those variables to hand to
// a relying party (Fulcio, the platform login, the platform Archivista). It
// picks a token only when its claims say it was issued
//
//   - by this job's GitLab (iss equals CI_SERVER_URL),
//   - to this job (job_id equals CI_JOB_ID),
//   - for exactly the relying party it is about to be sent to (aud is that one
//     audience and nothing else).
//
// The signature is not checked here: the relying party checks it against the
// issuer's keys, and a token that fails there is refused there. What this
// package guarantees is the client-side half: cilock never forwards a token
// minted for a different audience or a different job, so a token the pipeline
// declared for one purpose cannot be replayed by the party it was sent to for
// another. A token that lists several audiences is refused for the same
// reason, even though GitLab can mint one.
//
// The formal model of this selection is Lean `CilockCi.selectToken`
// (subtrees/rookery/formal/cilock-ci/CilockCi/Token.lean); the differential
// test in this package runs both over generated environments.
package cijobtoken

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Audiences and the id_tokens variable names cilock documents for them. Any
// variable name works: Select finds a token by its claims, never by its name.
// The documented name only breaks a tie and appears in the fix a refusal names.
const (
	// FulcioAudience is the audience every Fulcio CA requires.
	FulcioAudience = "sigstore"

	// DefaultFulcioVar is the name GitLab's own Sigstore signing example uses
	// (https://docs.gitlab.com/ci/yaml/signing_examples/) and cosign reads.
	DefaultFulcioVar = "SIGSTORE_ID_TOKEN"
	// DefaultLoginVar holds the token for <platform>/login.
	DefaultLoginVar = "CILOCK_LOGIN_ID_TOKEN"
	// DefaultArchivistaVar holds the token for <platform>/archivista.
	DefaultArchivistaVar = "CILOCK_ARCHIVISTA_ID_TOKEN"
	// DefaultOtherVar is suggested for any other audience.
	DefaultOtherVar = "CILOCK_ID_TOKEN"
)

// DefaultVar is the documented id_tokens variable name for aud.
func DefaultVar(aud string) string {
	switch {
	case aud == FulcioAudience:
		return DefaultFulcioVar
	case strings.HasSuffix(aud, "/login"):
		return DefaultLoginVar
	case strings.HasSuffix(aud, "/archivista"):
		return DefaultArchivistaVar
	default:
		return DefaultOtherVar
	}
}

// Claims are the unverified claims Select reads, plus the ones the platform
// binds (project_id, project_path, ref, ref_type) for callers that report them.
type Claims struct {
	Iss         string
	Aud         []string
	JobID       string
	PipelineID  string
	ProjectID   string
	ProjectPath string
	Ref         string
	RefType     string
	Exp         int64
}

// Token is one job ID token found in the environment. Raw is the compact JWT;
// it is a credential and must never be logged.
type Token struct {
	Var    string
	Raw    string
	Claims Claims
}

// Job is the job identity GitLab exports in its predefined variables.
type Job struct {
	ServerURL string // CI_SERVER_URL, the issuer of the job's ID tokens
	JobID     string // CI_JOB_ID
}

// JobFromEnv returns the GitLab job this process runs in, and false when it is
// not a GitLab CI job. GITLAB_CI must be exactly "true", as GitLab sets it.
func JobFromEnv(getenv func(string) string) (Job, bool) {
	if getenv("GITLAB_CI") != "true" {
		return Job{}, false
	}
	return Job{ServerURL: getenv("CI_SERVER_URL"), JobID: getenv("CI_JOB_ID")}, true
}

// Refusal kinds, one per constructor of the model's `Refusal`.
const (
	RefuseNoAudience    = "noAudience"
	RefuseNoJob         = "noJob"
	RefuseNotJWT        = "notJWT"
	RefuseNotThisJob    = "notThisJob"
	RefuseExpired       = "expired"
	RefuseExplicitEmpty = "explicitEmpty"
	RefuseWrongAud      = "wrongAud"
	RefuseMissing       = "missing"
)

// Refusal says why no token could be selected. Its message names the fix.
type Refusal struct {
	Aud    string
	Kind   string // one of the Refuse* constants
	Var    string // the variable a refusal is about, when it is about one
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

// ParseClaims decodes a compact JWT's payload without verifying it. It reports
// false for anything that is not a three-part JWT with a JSON object payload.
func ParseClaims(raw string) (Claims, bool) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || strings.ContainsAny(raw, " \t\r\n") {
		return Claims{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return Claims{}, false
	}
	var c struct {
		Iss         string          `json:"iss"`
		Aud         json.RawMessage `json:"aud"`
		JobID       json.RawMessage `json:"job_id"`
		PipelineID  json.RawMessage `json:"pipeline_id"`
		ProjectID   json.RawMessage `json:"project_id"`
		ProjectPath string          `json:"project_path"`
		Ref         string          `json:"ref"`
		RefType     string          `json:"ref_type"`
		Exp         int64           `json:"exp"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Claims{}, false
	}
	out := Claims{Iss: c.Iss, ProjectPath: c.ProjectPath, Ref: c.Ref, RefType: c.RefType, Exp: c.Exp,
		JobID: idString(c.JobID), PipelineID: idString(c.PipelineID), ProjectID: idString(c.ProjectID)}
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		out.Aud = []string{one}
	} else {
		_ = json.Unmarshal(c.Aud, &out.Aud)
	}
	return out, true
}

// idString reads a GitLab id claim, which GitLab writes as a JSON string
// ("10") and some issuers as a number (10).
func idString(m json.RawMessage) string {
	var s string
	if json.Unmarshal(m, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(m, &n) == nil {
		return n.String()
	}
	return ""
}

func trimIssuer(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }

// issuedFor reports whether c was issued by the job's GitLab to this job.
func (j Job) issuedFor(c Claims) bool {
	return j.ServerURL != "" && j.JobID != "" && trimIssuer(c.Iss) == trimIssuer(j.ServerURL) && c.JobID == j.JobID
}

// exactAud reports whether aud is exactly [want].
func exactAud(aud []string, want string) bool { return len(aud) == 1 && aud[0] == want }

// Select returns the job's ID token for aud, from environ ("NAME=value"
// entries). explicitVar, when set, is the only variable considered. now is
// Unix seconds; an expired token is refused, because GitLab cannot re-mint
// one mid-job and the relying party would refuse it anyway after the build.
func Select(environ []string, job Job, aud, explicitVar string, now int64) (Token, error) {
	if aud == "" {
		return Token{}, &Refusal{Kind: RefuseNoAudience, Reason: "no audience to select a GitLab ID token for"}
	}
	if job.ServerURL == "" || job.JobID == "" {
		return Token{}, &Refusal{Aud: aud, Kind: RefuseNoJob, Reason: "gitlab ci: CI_SERVER_URL or CI_JOB_ID is not set, so no ID token can be tied to this job"}
	}
	fix := fmt.Sprintf("declare it in the job: `id_tokens: {%s: {aud: %s}}`", DefaultVar(aud), aud)
	toks, refusal := scanJob(environ, job, aud, explicitVar)
	if refusal != nil {
		return Token{}, refusal
	}
	var matches []Token
	var near []string    // tokens of this job for another audience, for the refusal
	var expired []string // tokens of this job for aud that have expired
	for _, t := range toks {
		switch {
		case !exactAud(t.Claims.Aud, aud):
			near = append(near, fmt.Sprintf("$%s has aud %v", t.Var, t.Claims.Aud))
		case t.Claims.Exp != 0 && t.Claims.Exp <= now:
			expired = append(expired, t.Var)
		default:
			matches = append(matches, t)
		}
	}
	if len(matches) == 0 {
		return Token{}, noMatch(aud, explicitVar, fix, near, expired)
	}
	// Every match is this job's token for this audience, so any one is as
	// good as another; prefer the documented name, then the first by name, so
	// the choice is deterministic.
	sort.Slice(matches, func(a, b int) bool {
		da, db := matches[a].Var == DefaultVar(aud), matches[b].Var == DefaultVar(aud)
		if da != db {
			return da
		}
		return matches[a].Var < matches[b].Var
	})
	return matches[0], nil
}

// noMatch is Select's refusal when no token of this job is for aud: an
// expired one first, then an explicit variable that held none, then tokens
// for other audiences, else none at all.
func noMatch(aud, explicitVar, fix string, near, expired []string) *Refusal {
	switch {
	case len(expired) > 0:
		sort.Strings(expired)
		return &Refusal{Aud: aud, Kind: RefuseExpired, Var: expired[0], Reason: fmt.Sprintf("gitlab ci: $%s (aud %s) has expired; GitLab ID tokens expire (one hour by default) and cannot be renewed mid-job",
			expired[0], aud)}
	case explicitVar != "" && len(near) == 0:
		return &Refusal{Aud: aud, Kind: RefuseExplicitEmpty, Var: explicitVar, Reason: fmt.Sprintf("gitlab ci: $%s is empty; %s", explicitVar, strings.Replace(fix, DefaultVar(aud), explicitVar, 1))}
	case len(near) > 0:
		sort.Strings(near)
		return &Refusal{Aud: aud, Kind: RefuseWrongAud, Reason: fmt.Sprintf("gitlab ci: no ID token for audience %s (%s; a token is only sent to the one audience it names); %s",
			aud, strings.Join(near, ", "), fix)}
	default:
		return &Refusal{Aud: aud, Kind: RefuseMissing, Reason: fmt.Sprintf("gitlab ci: no ID token for audience %s; %s", aud, fix)}
	}
}

// scanJob returns the JWTs in environ ("NAME=value") issued to this job.
// explicitVar, when set, is the only variable considered, and a value there
// that is not a JWT, or not this job's, is a refusal rather than skipped.
func scanJob(environ []string, job Job, aud, explicitVar string) ([]Token, *Refusal) {
	var out []Token
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || (explicitVar != "" && name != explicitVar) {
			continue
		}
		c, isJWT := ParseClaims(value)
		switch {
		case !isJWT && explicitVar != "" && strings.TrimSpace(value) != "":
			return nil, &Refusal{Aud: aud, Kind: RefuseNotJWT, Var: name, Reason: fmt.Sprintf("gitlab ci: $%s is not a JWT", name)}
		case !isJWT:
			continue
		case !job.issuedFor(c) && explicitVar != "":
			return nil, &Refusal{Aud: aud, Kind: RefuseNotThisJob, Var: name, Reason: fmt.Sprintf("gitlab ci: $%s was not issued to this job (iss %q, job_id %q; this job is %q job %s)",
				name, c.Iss, c.JobID, trimIssuer(job.ServerURL), job.JobID)}
		case !job.issuedFor(c):
			continue
		}
		out = append(out, Token{Var: name, Raw: strings.TrimSpace(value), Claims: c})
	}
	return out, nil
}

// SelectAny returns one of the job's ID tokens, whatever its audience, for a
// caller that only records its signed claims (the gitlab attestor) and never
// sends it anywhere. explicitVar, when set, is the only variable considered.
// It prefers the Fulcio token, then the documented names, then the first by
// name. ok is false when the job has no ID token at all.
func SelectAny(environ []string, job Job, explicitVar string) (tok Token, ok bool, err error) {
	all, refusal := scanJob(environ, job, "", explicitVar)
	if refusal != nil {
		if refusal.Kind == RefuseNotJWT {
			return Token{}, false, fmt.Errorf("gitlab ci: $%s is not a JWT", refusal.Var)
		}
		return Token{}, false, fmt.Errorf("gitlab ci: $%s was not issued to this job", refusal.Var)
	}
	if len(all) == 0 {
		return Token{}, false, nil
	}
	rank := func(v string) int {
		switch v {
		case DefaultFulcioVar:
			return 0
		case DefaultLoginVar, DefaultArchivistaVar, DefaultOtherVar:
			return 1
		}
		return 2
	}
	sort.Slice(all, func(a, b int) bool {
		if ra, rb := rank(all[a].Var), rank(all[b].Var); ra != rb {
			return ra < rb
		}
		return all[a].Var < all[b].Var
	})
	return all[0], true, nil
}
