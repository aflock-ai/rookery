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

package link

import (
	"encoding/json"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	intotolink "github.com/aflock-ai/rookery/attestation/intoto/link"
	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/environment"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "link"
	Type    = "https://in-toto.io/attestation/link/v0.3"
	RunType = attestation.PostProductRunType

	defaultExport = false
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Link{}
	_ attestation.Subjecter = &Link{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			"export",
			"Export the Link predicate in its own attestation",
			defaultExport,
			func(a attestation.Attestor, export bool) (attestation.Attestor, error) {
				linkAttestor, ok := a.(*Link)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a Link provenance attestor", a)
				}
				WithExport(export)(linkAttestor)
				return linkAttestor, nil
			},
		),
	)
}

type Option func(*Link)

func WithExport(export bool) Option {
	return func(l *Link) {
		l.export = export
	}
}

type Link struct {
	PbLink   intotolink.Link
	products map[string]attestation.Product
	export   bool
}

func New() *Link {
	return &Link{}
}

func (l *Link) Name() string {
	return Name
}

func (l *Link) Type() string {
	return Type
}

func (l *Link) RunType() attestation.RunType {
	return RunType
}

func (l *Link) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&intotolink.Link{})
}

func (l *Link) Export() bool {
	return l.export
}

func (l *Link) Attest(ctx *attestation.AttestationContext) error { //nolint:gocognit // link attestation processes multiple attestor types
	l.PbLink.Name = ctx.StepName()
	for _, attestor := range ctx.CompletedAttestors() {
		switch name := attestor.Attestor.Name(); name {
		case commandrun.Name:
			if cmdAttestor, ok := attestor.Attestor.(commandrun.CommandRunAttestor); ok {
				l.PbLink.Command = cmdAttestor.Data().Cmd
			}
		case material.Name:
			if matAttestor, ok := attestor.Attestor.(material.MaterialAttestor); ok {
				mats := matAttestor.Materials()
				for name, digestSet := range mats {
					digests, _ := digestSet.ToNameMap()
					l.PbLink.Materials = append(l.PbLink.Materials, &v1.ResourceDescriptor{
						Name:   name,
						Digest: digests,
					})
				}
			}
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
			l.PbLink.Environment = pbEnvs
		case product.ProductName:
			if prodAttestor, ok := attestor.Attestor.(product.ProductAttestor); ok {
				l.products = prodAttestor.Products()
			}
		}
	}
	return nil
}

func (l *Link) MarshalJSON() ([]byte, error) {
	return json.Marshal(&l.PbLink)
}

func (l *Link) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &l.PbLink); err != nil {
		return err
	}

	return nil
}

func (l *Link) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range l.products {
		subjects[fmt.Sprintf("file:%v", productName)] = product.Digest
	}

	return subjects
}
