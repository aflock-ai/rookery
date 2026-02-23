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
	"strings"

	prov "github.com/aflock-ai/rookery/attestation/intoto/provenance"
	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
	"github.com/aflock-ai/rookery/attestation"
	aws_codebuild "github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/environment"
	"github.com/aflock-ai/rookery/plugins/attestors/git"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/aflock-ai/rookery/plugins/attestors/gitlab"
	"github.com/aflock-ai/rookery/plugins/attestors/jenkins"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/oci"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/invopop/jsonschema"
	"golang.org/x/exp/maps"
)

const (
	Name                  = "slsa"
	Type                  = "https://slsa.dev/provenance/v1.0"
	RunType               = attestation.PostProductRunType
	defaultExport         = false
	BuildType             = "https://aflock.ai/slsa-build@v0.1"
	DefaultBuilderId      = "https://aflock.ai/attestation-default-builder@v0.1"
	GHABuilderId          = "https://aflock.ai/attestation-github-action-builder@v0.1"
	GLCBuilderId          = "https://aflock.ai/attestation-gitlab-component-builder@v0.1"
	JenkinsBuilderId      = "https://aflock.ai/attestation-jenkins-component-builder@v0.1"
	AWSCodeBuildBuilderId = "https://aflock.ai/attestation-aws-codebuild-builder@v0.1"
)

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

func (p *Provenance) Attest(ctx *attestation.AttestationContext) error {
	builder := prov.Builder{}
	metadata := prov.BuildMetadata{}
	p.PbProvenance.BuildDefinition = &prov.BuildDefinition{}
	p.PbProvenance.RunDetails = &prov.RunDetails{Builder: &builder, Metadata: &metadata}

	p.PbProvenance.BuildDefinition.BuildType = BuildType
	p.PbProvenance.RunDetails.Builder.ID = DefaultBuilderId

	internalParameters := make(map[string]interface{})

	for _, attestor := range ctx.CompletedAttestors() {
		if attestor.Error != nil {
			continue
		}

		switch name := attestor.Attestor.Name(); name {
		// Pre-material Attestors
		case environment.Name:
			envs := attestor.Attestor.(environment.EnvironmentAttestor).Data().Variables
			pbEnvs := make(map[string]interface{}, len(envs))
			for name, value := range envs {
				pbEnvs[name] = value
			}

			internalParameters["env"] = pbEnvs

		case git.Name:
			digestSet := attestor.Attestor.(git.GitAttestor).Data().CommitDigest
			remotes := attestor.Attestor.(git.GitAttestor).Data().Remotes
			digests, _ := digestSet.ToNameMap()

			for _, remote := range remotes {
				p.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					p.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Name:   remote,
						Digest: digests,
					})
			}

		case github.Name:
			gh := attestor.Attestor.(github.GitHubAttestor)
			p.PbProvenance.RunDetails.Builder.ID = GHABuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationID = gh.Data().PipelineUrl

			if gh.Data().JWT == nil {
				log.Warn("No JWT found in GitHub attestor")
				continue
			}

			if sha, ok := gh.Data().JWT.Claims["sha"].(string); ok && sha != "" {
				digest := make(map[string]string)
				digest["sha1"] = sha
				p.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					p.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Digest: digest,
					})
			} else {
				log.Warn("No SHA found in GitHub JWT or SHA is not a string")
			}

		case gitlab.Name:
			gl := attestor.Attestor.(gitlab.GitLabAttestor)
			p.PbProvenance.RunDetails.Builder.ID = GLCBuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationID = gl.Data().PipelineUrl

			if gl.Data().JWT == nil {
				log.Warn("No JWT found in GitLab attestor")
				continue
			}

			if sha, ok := gl.Data().JWT.Claims["sha"].(string); ok && sha != "" {
				digest := make(map[string]string)
				digest["sha1"] = sha
				p.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					p.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Digest: digest,
					})
			} else {
				log.Warn("No SHA found in GitLab JWT")
			}

		case jenkins.Name:
			jks := attestor.Attestor.(jenkins.JenkinsAttestor)
			p.PbProvenance.RunDetails.Builder.ID = JenkinsBuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationID = jks.Data().PipelineUrl

		case aws_codebuild.Name:
			awsCodeBuild := attestor.Attestor.(aws_codebuild.AWSCodeBuildAttestor)
			p.PbProvenance.RunDetails.Builder.ID = AWSCodeBuildBuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationID = awsCodeBuild.Data().BuildInfo.BuildARN

		// Material Attestors
		case material.Name:
			mats := attestor.Attestor.(material.MaterialAttestor).Materials()
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
			ep["command"] = strings.Join(attestor.Attestor.(commandrun.CommandRunAttestor).Data().Cmd, " ")
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

			if p.subjects == nil {
				p.subjects = attestor.Attestor.(attestation.Subjecter).Subjects()
			} else {
				maps.Copy(p.subjects, attestor.Attestor.(attestation.Subjecter).Subjects())
			}

		// Post Attestors
		case oci.Name:
			if p.subjects == nil {
				p.subjects = attestor.Attestor.(attestation.Subjecter).Subjects()
			} else {
				maps.Copy(p.subjects, attestor.Attestor.(attestation.Subjecter).Subjects())
			}
		}
	}

	// NOTE: We want to warn users that they can use build system attestors to enrich their provenance
	if p.PbProvenance.RunDetails.Builder.ID == DefaultBuilderId {
		log.Warn("No build system attestor invoked. Consider using github, gitlab, jenkins, or aws-codebuild attestors (if appropriate) to enrich your SLSA provenance")
	}

	p.PbProvenance.BuildDefinition.InternalParameters = internalParameters

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
