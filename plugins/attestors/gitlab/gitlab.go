// Copyright 2021 The Witness Contributors
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

package gitlab

import (
	"crypto"
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cijobtoken"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/redact"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "gitlab"
	Type    = "https://aflock.ai/attestations/gitlab/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ GitLabAttestor         = &Attestor{}
)

type GitLabAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor

	// Subjecter
	Subjects() map[string]cryptoutil.DigestSet

	// Backreffer
	BackRefs() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	},
		registry.StringConfigOption(
			"token-env",
			"The id_tokens variable whose signed job claims to record. If empty, the job's own ID token is found by its claims "+
				"(issued by CI_SERVER_URL to CI_JOB_ID), preferring "+cijobtoken.DefaultFulcioVar+".",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithTokenEnvVar(val)(att)
				return att, nil
			},
		),
	)
	detection.Register(Name, detectorYAML)
}

type ErrNotGitlab struct{}

func (e ErrNotGitlab) Error() string {
	return "not in a gitlab ci job"
}

type Option func(a *Attestor)

type Attestor struct {
	JWT          *jwt.Attestor `json:"jwt,omitempty"`
	CIConfigPath string        `json:"ciconfigpath"`
	JobID        string        `json:"jobid"`
	JobImage     string        `json:"jobimage"`
	JobName      string        `json:"jobname"`
	JobStage     string        `json:"jobstage"`
	JobUrl       string        `json:"joburl"`
	PipelineID   string        `json:"pipelineid"`
	PipelineUrl  string        `json:"pipelineurl"`
	ProjectID    string        `json:"projectid"`
	ProjectUrl   string        `json:"projecturl"`
	RunnerID     string        `json:"runnerid"`
	CIHost       string        `json:"cihost"`
	CIServerUrl  string        `json:"ciserverurl"`
	token        string
	tokenEnvVar  string
}

func WithToken(token string) Option {
	return func(a *Attestor) {
		a.token = token
	}
}

func WithTokenEnvVar(envVar string) Option {
	return func(a *Attestor) {
		a.tokenEnvVar = envVar
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	// DoNotReference inlines nested types instead of emitting shared $defs keyed
	// by bare type name. gitlab.Attestor and the embedded jwt.Attestor are BOTH
	// named "Attestor", so the default reflector collapses them into one
	// "#/$defs/Attestor" and the `jwt` property wrongly inherits gitlab's
	// required fields (ciconfigpath/pipelineid/...) — making a valid gitlab
	// predicate fail its own schema. Inlining gives the jwt field its own schema.
	// (Same collision the github attestor fixed; see github.Schema().)
	r := jsonschema.Reflector{DoNotReference: true}
	s := r.Reflect(a)
	// The embedded jwt.Attestor's VerifiedBy.JWK is a jose.JSONWebKey, a type
	// with a custom MarshalJSON that emits JWK JSON (kty/n/e/kid/...) rather than
	// the reflected Go struct shape. DoNotReference inlines it here as
	// jwt.verifiedBy.jwk, so reuse the jwt attestor's permissive-object patch
	// (one source of jose-marshalling knowledge) — otherwise a valid gitlab
	// predicate fails its own Schema() on the jwk's bogus required fields.
	jwt.PermissiveJWK(s)
	return s
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if os.Getenv("GITLAB_CI") != "true" {
		return ErrNotGitlab{}
	}

	// The recorded URLs lose a login in their userinfo (see
	// redact.URLCredentials). The JWKS fetch is built from the server URL as
	// given, and the jwt attestor redacts its own recorded copy.
	serverURL := os.Getenv("CI_SERVER_URL")
	a.CIServerUrl = redact.URLCredentials(serverURL)
	jwksUrl := os.Getenv("WITNESS_GITLAB_JWKS_URL")
	if jwksUrl == "" {
		jwksUrl = fmt.Sprintf("%s/oauth/discovery/keys", serverURL)
	}

	jwtString, err := a.jobToken()
	if err != nil {
		return err
	}
	if jwtString != "" {
		// The jwt attestor verifies the signature against the issuer's JWKS
		// (self-managed: <CI_SERVER_URL>/oauth/discovery/keys, reachable from
		// an air-gapped runner) and fails the attestor when it does not
		// verify: an unverified token is never recorded as claims.
		a.JWT = jwt.New(jwt.WithToken(jwtString), jwt.WithJWKSUrl(jwksUrl))
		if err := a.JWT.Attest(ctx); err != nil {
			return err
		}
	} else {
		log.Warn("(attestation/gitlab) this job declared no ID token, so no signed job claims are recorded " +
			"(GitLab 17 removed CI_JOB_JWT); declare one with `id_tokens: {" + cijobtoken.DefaultFulcioVar + ": {aud: sigstore}}`")
	}

	a.CIConfigPath = os.Getenv("CI_CONFIG_PATH")
	a.JobID = os.Getenv("CI_JOB_ID")
	a.JobImage = os.Getenv("CI_JOB_IMAGE")
	a.JobName = os.Getenv("CI_JOB_NAME")
	a.JobStage = os.Getenv("CI_JOB_STAGE")
	a.JobUrl = redact.URLCredentials(os.Getenv("CI_JOB_URL"))
	a.PipelineID = os.Getenv("CI_PIPELINE_ID")
	a.PipelineUrl = redact.URLCredentials(os.Getenv("CI_PIPELINE_URL"))
	a.ProjectID = os.Getenv("CI_PROJECT_ID")
	a.ProjectUrl = redact.URLCredentials(os.Getenv("CI_PROJECT_URL"))
	a.RunnerID = os.Getenv("CI_RUNNER_ID")
	a.CIHost = os.Getenv("CI_SERVER_HOST")

	return nil
}

func (a *Attestor) Data() *Attestor {
	return a
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.PipelineUrl), hashes); err == nil {
		subjects[fmt.Sprintf("pipelineurl:%v", a.PipelineUrl)] = ds
	} else {
		log.Debugf("(attestation/gitlab) failed to record gitlab pipelineurl subject: %v", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.JobUrl), hashes); err == nil {
		subjects[fmt.Sprintf("joburl:%v", a.JobUrl)] = ds
	} else {
		log.Debugf("(attestation/gitlab) failed to record gitlab joburl subject: %v", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ProjectUrl), hashes); err == nil {
		subjects[fmt.Sprintf("projecturl:%v", a.ProjectUrl)] = ds
	} else {
		log.Debugf("(attestation/gitlab) failed to record gitlab projecturl subject: %v", err)
	}

	return subjects
}

func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	backRefs := make(map[string]cryptoutil.DigestSet)
	for subj, ds := range a.Subjects() {
		if strings.HasPrefix(subj, "pipelineurl:") {
			backRefs[subj] = ds
			break
		}
	}

	return backRefs
}

// jobToken returns the JWT whose claims the attestor records: the literal
// WithToken value, else this job's own ID token (cijobtoken.SelectAny: issued
// by CI_SERVER_URL to CI_JOB_ID, any audience, since the claims are only
// recorded and the token is never sent anywhere), restricted to the variable
// WithTokenEnvVar names when one is named. The pre-17 CI_JOB_JWT is found the
// same way when a GitLab still sets it. "" means the job has no ID token.
func (a *Attestor) jobToken() (string, error) {
	if a.token != "" {
		return a.token, nil
	}
	job, _ := cijobtoken.JobFromEnv(os.Getenv)
	tok, ok, err := cijobtoken.SelectAny(os.Environ(), job, a.tokenEnvVar)
	if err != nil {
		return "", fmt.Errorf("gitlab attestor: %w", err)
	}
	if !ok {
		if a.tokenEnvVar != "" {
			return "", fmt.Errorf("gitlab attestor: $%s holds no ID token for this job; declare it with `id_tokens: {%s: {aud: ...}}`",
				a.tokenEnvVar, a.tokenEnvVar)
		}
		// GitLab < 17 still sets the pre-17 CI_JOB_JWT for every job; keep recording it (the jwt
		// attestor verifies its signature) when no ID token was declared, but only when it was
		// issued to this job by this GitLab, the binding the id_tokens scan enforces.
		return legacyJobToken(job), nil
	}
	return tok.Raw, nil
}

// legacyJobToken returns CI_JOB_JWT when it names this job and this GitLab, else "". The pre-15.9
// token's iss is the bare host (CI_SERVER_HOST), JWT_V2's is the server URL; either is this GitLab.
func legacyJobToken(job cijobtoken.Job) string {
	raw := os.Getenv("CI_JOB_JWT")
	if raw == "" {
		return ""
	}
	c, ok := cijobtoken.ParseClaims(raw)
	iss := strings.TrimRight(strings.TrimSpace(c.Iss), "/")
	thisGitLab := iss != "" && (iss == strings.TrimRight(strings.TrimSpace(job.ServerURL), "/") ||
		iss == strings.TrimSpace(os.Getenv("CI_SERVER_HOST")))
	if !ok || job.JobID == "" || c.JobID != job.JobID || !thisGitLab {
		log.Warn("(attestation/gitlab) CI_JOB_JWT was not issued to this job by this GitLab, so its claims are not recorded")
		return ""
	}
	return raw
}
