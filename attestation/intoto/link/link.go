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

// Package link provides the in-toto Link predicate v0.3 types.
// See https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md
package link

import (
	v1 "github.com/aflock-ai/rookery/attestation/intoto/v1"
)

// Link is the in-toto Link predicate (v0.3).
type Link struct {
	Name        string                   `json:"name,omitempty"`
	Command     []string                 `json:"command,omitempty"`
	Materials   []*v1.ResourceDescriptor `json:"materials,omitempty"`
	Byproducts  map[string]interface{}   `json:"byproducts,omitempty"`
	Environment map[string]interface{}   `json:"environment,omitempty"`
}
