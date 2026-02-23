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

package dsse

import (
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// getProperty looks up a property by JSON name in an ordered map.
func getProperty(props *orderedmap.OrderedMap[string, *jsonschema.Schema], name string) *jsonschema.Schema {
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

func TestEnvelopeSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Envelope{})
	require.NotNil(t, schema)

	props := schema.Definitions["Envelope"].Properties
	require.NotNil(t, props, "Envelope should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"payload", "Payload"},
		{"payloadType", "Payload Type"},
		{"signatures", "Signatures"},
	}

	for _, tt := range tests {
		t.Run(tt.jsonName, func(t *testing.T) {
			prop := getProperty(props, tt.jsonName)
			require.NotNil(t, prop, "property %s should exist", tt.jsonName)
			assert.Equal(t, tt.title, prop.Title, "title mismatch for %s", tt.jsonName)
			assert.NotEmpty(t, prop.Description, "description should not be empty for %s", tt.jsonName)
		})
	}
}

func TestSignatureSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Signature{})
	require.NotNil(t, schema)

	props := schema.Definitions["Signature"].Properties
	require.NotNil(t, props, "Signature should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"keyid", "Key ID"},
		{"sig", "Signature"},
		{"certificate", "Certificate"},
		{"intermediates", "Intermediates"},
		{"timestamps", "Timestamps"},
	}

	for _, tt := range tests {
		t.Run(tt.jsonName, func(t *testing.T) {
			prop := getProperty(props, tt.jsonName)
			require.NotNil(t, prop, "property %s should exist", tt.jsonName)
			assert.Equal(t, tt.title, prop.Title, "title mismatch for %s", tt.jsonName)
			assert.NotEmpty(t, prop.Description, "description should not be empty for %s", tt.jsonName)
		})
	}
}

func TestSignatureTimestampSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&SignatureTimestamp{})
	require.NotNil(t, schema)

	props := schema.Definitions["SignatureTimestamp"].Properties
	require.NotNil(t, props, "SignatureTimestamp should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"type", "Type"},
		{"data", "Data"},
	}

	for _, tt := range tests {
		t.Run(tt.jsonName, func(t *testing.T) {
			prop := getProperty(props, tt.jsonName)
			require.NotNil(t, prop, "property %s should exist", tt.jsonName)
			assert.Equal(t, tt.title, prop.Title, "title mismatch for %s", tt.jsonName)
			assert.NotEmpty(t, prop.Description, "description should not be empty for %s", tt.jsonName)
		})
	}
}
