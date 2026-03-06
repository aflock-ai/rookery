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

// Package provenance provides SLSA Provenance v1.0 predicate types.
// See https://slsa.dev/spec/v1.0/provenance
package provenance

import (
	"time"

	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
)

// Provenance is the SLSA Provenance v1.0 predicate.
type Provenance struct {
	BuildDefinition *BuildDefinition `json:"buildDefinition,omitempty"`
	RunDetails      *RunDetails      `json:"runDetails,omitempty"`
}

// BuildDefinition describes how the build was performed.
type BuildDefinition struct {
	BuildType            string                   `json:"buildType"`
	ExternalParameters   map[string]interface{}   `json:"externalParameters,omitempty"`
	InternalParameters   map[string]interface{}   `json:"internalParameters,omitempty"`
	ResolvedDependencies []*v1.ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// RunDetails describes a particular execution of the build.
type RunDetails struct {
	Builder    *Builder                 `json:"builder,omitempty"`
	Metadata   *BuildMetadata           `json:"metadata,omitempty"`
	Byproducts []*v1.ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder identifies the build platform.
type Builder struct {
	ID                  string                   `json:"id"`
	Version             map[string]string        `json:"version,omitempty"`
	BuilderDependencies []*v1.ResourceDescriptor `json:"builderDependencies,omitempty"`
}

// BuildMetadata contains build timing and invocation information.
type BuildMetadata struct {
	InvocationID string     `json:"invocationId,omitempty"`
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
}
