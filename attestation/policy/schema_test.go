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

package policy

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

func TestPolicySchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Policy{})
	require.NotNil(t, schema)

	props := schema.Definitions["Policy"].Properties
	require.NotNil(t, props, "Policy should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"expires", "Expires"},
		{"roots", "Root Certificates"},
		{"timestampauthorities", "Timestamp Authorities"},
		{"publickeys", "Public Keys"},
		{"steps", "Steps"},
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

func TestRootSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Root{})
	require.NotNil(t, schema)

	props := schema.Definitions["Root"].Properties
	require.NotNil(t, props, "Root should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"certificate", "Certificate"},
		{"intermediates", "Intermediates"},
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

func TestPublicKeySchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&PublicKey{})
	require.NotNil(t, schema)

	props := schema.Definitions["PublicKey"].Properties
	require.NotNil(t, props, "PublicKey should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"keyid", "Key ID"},
		{"key", "Key"},
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

func TestStepSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Step{})
	require.NotNil(t, schema)

	props := schema.Definitions["Step"].Properties
	require.NotNil(t, props, "Step should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"name", "Name"},
		{"functionaries", "Functionaries"},
		{"attestations", "Attestations"},
		{"artifactsFrom", "Artifacts From"},
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

func TestFunctionarySchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Functionary{})
	require.NotNil(t, schema)

	props := schema.Definitions["Functionary"].Properties
	require.NotNil(t, props, "Functionary should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"type", "Type"},
		{"certConstraint", "Certificate Constraint"},
		{"publickeyid", "Public Key ID"},
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

func TestAttestationSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&Attestation{})
	require.NotNil(t, schema)

	props := schema.Definitions["Attestation"].Properties
	require.NotNil(t, props, "Attestation should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"type", "Type"},
		{"regopolicies", "Rego Policies"},
		{"aipolicies", "AI Policies"},
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

func TestRegoPolicySchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&RegoPolicy{})
	require.NotNil(t, schema)

	props := schema.Definitions["RegoPolicy"].Properties
	require.NotNil(t, props, "RegoPolicy should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"module", "Module"},
		{"name", "Name"},
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

func TestAiPolicySchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&AiPolicy{})
	require.NotNil(t, schema)

	props := schema.Definitions["AiPolicy"].Properties
	require.NotNil(t, props, "AiPolicy should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"name", "Name"},
		{"prompt", "Prompt"},
		{"model", "Model"},
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

func TestCertConstraintSchemaTagsPresent(t *testing.T) {
	schema := jsonschema.Reflect(&CertConstraint{})
	require.NotNil(t, schema)

	props := schema.Definitions["CertConstraint"].Properties
	require.NotNil(t, props, "CertConstraint should have properties in schema")

	tests := []struct {
		jsonName string
		title    string
	}{
		{"commonname", "Common Name"},
		{"dnsnames", "DNS Names"},
		{"emails", "Emails"},
		{"organizations", "Organizations"},
		{"uris", "URIs"},
		{"roots", "Roots"},
		{"extensions", "Extensions"},
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
