// Copyright 2025 The Aflock Authors
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

package slsa

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	prov "github.com/aflock-ai/rookery/attestation/intoto/provenance"
	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	aws_codebuild "github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/environment"
	"github.com/aflock-ai/rookery/plugins/attestors/git"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/aflock-ai/rookery/plugins/attestors/gitlab"
	"github.com/aflock-ai/rookery/plugins/attestors/jenkins"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/oci"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
)

const (
	Name = "slsa"
	// Type is the predicateType the SLSA v1.0 spec defines
	// (https://slsa.dev/spec/v1.0/provenance). Tools that match it exactly
	// (slsa-verifier, gh attestation verify) ignore any other spelling.
	Type          = "https://slsa.dev/provenance/v1"
	RunType       = attestation.PostProductRunType
	defaultExport = false
	BuildType     = "https://aflock.ai/slsa-build@v0.1"

	// DefaultBuilderId is the id cilock stamps when it cannot name a build
	// platform: no CI attestor ran, or the CI's OIDC token was not verified
	// against that platform's own key set (see builderIDFor). It claims
	// nothing, and the SLSA gate and the policy templates refuse it.
	DefaultBuilderId = "https://aflock.ai/attestation-default-builder@v0.1"

	// builder.id is "the transitive closure of the trusted build platform"
	// (SLSA v1.0). When cilock runs inline in the build job, that closure is
	// the build job itself plus cilock, so the id names the inline mode and
	// the CI vendor. A verifier can tell these ids apart from an isolated
	// signer's (a reusable-workflow identity, see builderIDFor). Each is
	// emitted only on the platform-verified path.
	InlineGHABuilderId = "https://aflock.ai/cilock/inline/github-actions@v1"
	InlineGLCBuilderId = "https://aflock.ai/cilock/inline/gitlab-ci@v1"

	// Deprecated: no longer emitted. The per-vendor ids cilock stamped before
	// #9827 whether cilock ran inline or not; stored provenance still carries
	// them and they remain valid, opaque builder.id values on read.
	GHABuilderId = "https://aflock.ai/attestation-github-action-builder@v0.1"
	// Deprecated: see GHABuilderId.
	GLCBuilderId = "https://aflock.ai/attestation-gitlab-component-builder@v0.1"
	// Deprecated: no longer emitted. Jenkins has no Fulcio issuer mapping, so
	// a Jenkins build never reaches the level a named builder implies (#9839).
	JenkinsBuilderId = "https://aflock.ai/attestation-jenkins-component-builder@v0.1"
	// Deprecated: no longer emitted. CodeBuild issues no workload OIDC token,
	// so a CodeBuild build never reaches the level a named builder implies (#9839).
	AWSCodeBuildBuilderId = "https://aflock.ai/attestation-aws-codebuild-builder@v0.1"

	// githubActionsJWKSURL is GitHub's own OIDC key set. A claim is
	// GitHub-stamped only when the token verified against it; the github
	// attestor's JWKS URL can be redirected by an environment variable
	// (WITNESS_GITHUB_JWKS_URL) a build step controls.
	githubActionsJWKSURL = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

// trustedProvenanceWorkflows lists the reusable workflows, as
// "<owner>/<repo>/.github/workflows/<file>" without a ref, that run cilock as
// an isolated provenance signer. When the job's GitHub-verified OIDC token
// says the job IS one of these (job_workflow_ref), builder.id is that
// workflow's identity, the same pattern slsa-github-generator uses.
//
// It is compiled in on purpose: no CLI flag, environment variable or config
// file can extend it, so a tenant build step cannot promote its own run. The
// claim is also cross-checked at verify time against the signing cert's
// Fulcio Build Signer URI (policy.checkSLSAProvenance), which is what
// actually stops a tenant who controls the cilock process from asserting it.
var trustedProvenanceWorkflows = []string{
	"aflock-ai/cilock-action/.github/workflows/provenance.yml",
}

// builderIssuers is the one OIDC issuer per CI attestor whose token a Fulcio
// CA (public Sigstore and the TestifySec platform alike) maps to a build
// identity, and the key set that platform publishes. See builderIDFor.
//
// The github and gitlab attestors take their JWKS URL from an environment
// variable (WITNESS_GITHUB_JWKS_URL, WITNESS_GITLAB_JWKS_URL) that an earlier
// step of the same CI job can set, and a token verified against a key set the
// build chose can carry any iss it likes. So the issuer only counts when the
// token verified against the platform's own keys.
var builderIssuers = map[string]struct {
	issuer    string
	jwks      string
	builderID string
}{
	github.Name: {"https://token.actions.githubusercontent.com", githubActionsJWKSURL, InlineGHABuilderId},
	gitlab.Name: {"https://gitlab.com", "https://gitlab.com/oauth/discovery/keys", InlineGLCBuilderId},
}

// builderIDFor returns the builder.id to stamp for a CI attestor whose
// verified OIDC token is tok (nil when it had none).
//
// A named builder.id is a claim a verifier may grant a level on, so it is
// only emitted where the formal support matrix (formal/slsa-tracks) shows the
// platform can reach that level: the token's issuer must be the one a Fulcio
// CA maps to a build identity, and the token must have verified against that
// platform's own key set. GitHub Enterprise Server, self-managed GitLab,
// Jenkins, AWS CodeBuild and any token verified against another key set all
// fall back to DefaultBuilderId, which claims nothing. The attestor's run
// data (invocation ID, commit) is still recorded.
//
// On that verified path a GitHub job that IS a trusted provenance workflow
// (its GitHub-stamped job_workflow_ref, pinned to a ref) is named by that
// workflow's identity; every other verified job by its vendor's inline id.
func builderIDFor(attestorName string, tok *jwt.Attestor) string {
	want, ok := builderIssuers[attestorName]
	if !ok || tok == nil || tok.VerifiedBy.JWKSUrl != want.jwks {
		return DefaultBuilderId
	}
	if iss, _ := tok.Claims["iss"].(string); iss != want.issuer {
		return DefaultBuilderId
	}
	if attestorName == github.Name {
		ref, _ := tok.Claims["job_workflow_ref"].(string)
		workflow, at, ok := strings.Cut(ref, "@")
		if ok && at != "" && slices.Contains(trustedProvenanceWorkflows, workflow) {
			return "https://github.com/" + ref
		}
	}
	return want.builderID
}

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Provenance{}
	_ attestation.Subjecter = &Provenance{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			"export",
			"Export the SLSA provenance predicate in its own attestation",
			defaultExport,
			func(a attestation.Attestor, export bool) (attestation.Attestor, error) {
				slsaAttestor, ok := a.(*Provenance)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a SLSA provenance attestor", a)
				}
				WithExport(export)(slsaAttestor)
				return slsaAttestor, nil
			},
		),
	)
}

type Option func(*Provenance)

func WithExport(export bool) Option {
	return func(p *Provenance) {
		p.export = export
	}
}

type Provenance struct {
	PbProvenance prov.Provenance
	products     map[string]attestation.Product
	subjects     map[string]cryptoutil.DigestSet
	export       bool
}

func New() *Provenance {
	return &Provenance{}
}

func (p *Provenance) Name() string {
	return Name
}

func (p *Provenance) Type() string {
	return Type
}

func (p *Provenance) RunType() attestation.RunType {
	return RunType
}

func (p *Provenance) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(prov.Provenance{})
}

func (p *Provenance) Export() bool {
	return p.export
}

func (p *Provenance) Attest(ctx *attestation.AttestationContext) error { //nolint:gocognit,gocyclo,funlen // SLSA provenance construction requires processing multiple attestor types
	builder := prov.Builder{}
	metadata := prov.BuildMetadata{}
	p.PbProvenance.BuildDefinition = &prov.BuildDefinition{}
	p.PbProvenance.RunDetails = &prov.RunDetails{Builder: &builder, Metadata: &metadata}

	p.PbProvenance.BuildDefinition.BuildType = BuildType
	p.PbProvenance.RunDetails.Builder.ID = DefaultBuilderId

	internalParameters := make(map[string]interface{})
	var sources sourceDependencies
	var claims []sourceClaim
	var observed string

	for _, attestor := range ctx.CompletedAttestors() {
		if attestor.Error != nil {
			continue
		}

		switch name := attestor.Attestor.Name(); name {
		// Pre-material Attestors
		case environment.Name:
			envAttestor, ok := attestor.Attestor.(environment.EnvironmentAttestor)
			if !ok {
				continue
			}
			envs := envAttestor.Data().Variables
			pbEnvs := make(map[string]interface{}, len(envs))
			for name, value := range envs {
				pbEnvs[name] = value
			}

			internalParameters["env"] = pbEnvs

		// The git attestor's remotes are deliberately NOT a source dependency:
		// remotes are local, mutable config, so an unused remote naming the
		// expected repository would vouch for any checkout. The source comes
		// from the CI platform's signed claims below, and only the observed
		// checkout's verified commit binds them (bindSources).
		case git.Name:
			g, ok := attestor.Attestor.(git.GitAttestor)
			if !ok {
				continue
			}
			observed = observedCheckout(g.Data())

		case github.Name: //nolint:dupl // github and gitlab cases are structurally similar but differ in types
			gh, ok := attestor.Attestor.(github.GitHubAttestor)
			if !ok {
				continue
			}
			p.PbProvenance.RunDetails.Metadata.InvocationID = gh.Data().PipelineUrl

			if gh.Data().JWT == nil {
				log.Warn("No JWT found in GitHub attestor")
				continue
			}
			p.PbProvenance.RunDetails.Builder.ID = builderIDFor(github.Name, gh.Data().JWT)

			if c, ok := githubSourceClaim(gh.Data()); ok {
				claims = append(claims, c)
			}

		case gitlab.Name: //nolint:dupl // gitlab and github cases are structurally similar but differ in types
			gl, ok := attestor.Attestor.(gitlab.GitLabAttestor)
			if !ok {
				continue
			}
			p.PbProvenance.RunDetails.Metadata.InvocationID = gl.Data().PipelineUrl

			if gl.Data().JWT == nil {
				log.Warn("No JWT found in GitLab attestor")
				continue
			}
			p.PbProvenance.RunDetails.Builder.ID = builderIDFor(gitlab.Name, gl.Data().JWT)

			if c, ok := gitlabSourceClaim(gl.Data()); ok {
				claims = append(claims, c)
			}

		case jenkins.Name:
			jks, ok := attestor.Attestor.(jenkins.JenkinsAttestor)
			if !ok {
				continue
			}
			// Builder stays DefaultBuilderId: see builderIDFor.
			p.PbProvenance.RunDetails.Metadata.InvocationID = jks.Data().PipelineUrl

		case aws_codebuild.Name:
			awsCodeBuild, ok := attestor.Attestor.(aws_codebuild.AWSCodeBuildAttestor)
			if !ok {
				continue
			}
			// Builder stays DefaultBuilderId: see builderIDFor.
			p.PbProvenance.RunDetails.Metadata.InvocationID = awsCodeBuild.Data().BuildInfo.BuildARN

		// Material Attestors
		case material.Name:
			matAttestor, ok := attestor.Attestor.(material.MaterialAttestor)
			if !ok {
				continue
			}
			mats := matAttestor.Materials()
			for name, digestSet := range mats {
				digests, _ := digestSet.ToNameMap()
				p.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					p.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Name:   name,
						Digest: digests,
					})
			}

		// CommandRun Attestors
		case commandrun.Name:
			ep := make(map[string]interface{})
			cmdAttestor, ok := attestor.Attestor.(commandrun.CommandRunAttestor)
			if !ok {
				continue
			}
			ep["command"] = strings.Join(cmdAttestor.Data().Cmd, " ")
			p.PbProvenance.BuildDefinition.ExternalParameters = ep

			startedOn := attestor.StartTime
			finishedOn := attestor.EndTime
			p.PbProvenance.RunDetails.Metadata.StartedOn = &startedOn
			p.PbProvenance.RunDetails.Metadata.FinishedOn = &finishedOn

		// Product Attestors
		case product.ProductName:
			if p.products == nil {
				p.products = ctx.Products()
			} else {
				maps.Copy(p.products, ctx.Products())
			}

			if subjecter, ok := attestor.Attestor.(attestation.Subjecter); ok {
				if p.subjects == nil {
					p.subjects = subjecter.Subjects()
				} else {
					maps.Copy(p.subjects, subjecter.Subjects())
				}
			}

		// Post Attestors
		case oci.Name:
			if subjecter, ok := attestor.Attestor.(attestation.Subjecter); ok {
				if p.subjects == nil {
					p.subjects = subjecter.Subjects()
				} else {
					maps.Copy(p.subjects, subjecter.Subjects())
				}
			}
		}
	}

	// NOTE: We want to warn users that they can use build system attestors to enrich their provenance
	if p.PbProvenance.RunDetails.Builder.ID == DefaultBuilderId {
		log.Warn("SLSA provenance names the default builder: a named builder id is emitted only for GitHub Actions and GitLab.com jobs whose OIDC token the github or gitlab attestor verified")
	}

	bindSources(&sources, claims, observed, internalParameters)
	p.PbProvenance.BuildDefinition.InternalParameters = internalParameters
	p.PbProvenance.BuildDefinition.ResolvedDependencies = append(p.PbProvenance.BuildDefinition.ResolvedDependencies, sources.list()...)

	return nil
}

func (p *Provenance) MarshalJSON() ([]byte, error) {
	return json.Marshal(&p.PbProvenance)
}

func (p *Provenance) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &p.PbProvenance); err != nil {
		return err
	}

	return nil
}

func (p *Provenance) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range p.products {
		subjects[fmt.Sprintf("file:%v", productName)] = product.Digest
	}

	// Include subjects from other attestors (e.g. OCI image digests, tags).
	// Without this, OCI subjects collected during Attest() are silently dropped,
	// causing provenance to omit container image references.
	for k, v := range p.subjects {
		subjects[k] = v
	}

	return subjects
}
