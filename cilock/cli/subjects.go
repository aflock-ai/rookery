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

package cli

import (
	"fmt"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/workflow"
)

// parseSubjectFlags is a thin wrapper around workflow.ParseSubjectFlags that
// prefixes the error with "--subjects" so that CLI users see which flag
// produced the error. See workflow.ParseSubjectFlags for the full grammar.
func parseSubjectFlags(raw []string) (map[string]cryptoutil.DigestSet, error) {
	m, err := workflow.ParseSubjectFlags(raw)
	if err != nil {
		return nil, fmt.Errorf("--subjects: %w", err)
	}
	return m, nil
}
