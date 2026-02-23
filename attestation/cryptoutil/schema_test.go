// Copyright 2025 The Witness Contributors
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

package cryptoutil

import (
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// getSchemaProperty looks up a property by name in an ordered map.
func getSchemaProperty(props *orderedmap.OrderedMap[string, *jsonschema.Schema], name string) *jsonschema.Schema {
	if props == nil {
		return nil
	}
	for pair := props.Oldest(); pair != nil; pair = pair.Next() {
		if pair.Key == name {
			return pair.Value
		}
	}
	return nil
}

func TestDigestValueSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&DigestValue{})
	require.NotNil(t, schema)

	props := schema.Definitions["DigestValue"].Properties
	require.NotNil(t, props, "DigestValue should have properties in schema")

	tests := []struct {
		fieldName string
		title     string
	}{
		{"GitOID", "Git OID"},
		{"DirHash", "Directory Hash"},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			prop := getSchemaProperty(props, tt.fieldName)
			require.NotNil(t, prop, "property %s should exist", tt.fieldName)
			assert.Equal(t, tt.title, prop.Title, "title mismatch for %s", tt.fieldName)
			assert.NotEmpty(t, prop.Description, "description should not be empty for %s", tt.fieldName)
		})
	}
}
