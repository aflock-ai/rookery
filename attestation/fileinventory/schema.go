// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

package fileinventory

import (
	"sort"

	"github.com/invopop/jsonschema"
)

func constantFields(values map[string]any) *jsonschema.Schema {
	// Use the schema library's map type across the versions embedded by callers.
	properties := (&jsonschema.Reflector{DoNotReference: true}).Reflect(&struct{}{}).Properties
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		properties.Set(key, &jsonschema.Schema{Const: values[key]})
	}
	return &jsonschema.Schema{Properties: properties}
}

func (Reference) JSONSchema() *jsonschema.Schema {
	type plain Reference
	schema := (&jsonschema.Reflector{DoNotReference: true}).Reflect(&plain{})
	omitted := constantFields(map[string]any{fieldState: StateOmitted})
	omitted.Not = &jsonschema.Schema{AnyOf: []*jsonschema.Schema{{Required: []string{fieldDigest}}, {Required: []string{fieldBytes}}}}
	detached := constantFields(map[string]any{fieldState: StateDetached})
	detached.Required = []string{fieldDigest, fieldBytes}
	schema.OneOf = []*jsonschema.Schema{omitted, detached}
	schema.AllOf = []*jsonschema.Schema{{OneOf: []*jsonschema.Schema{
		constantFields(map[string]any{fieldCaptureMode: "walk", fieldCaptureScope: "working-directory"}),
		constantFields(map[string]any{fieldCaptureMode: "trace", fieldCaptureScope: "trace-provider"}),
		constantFields(map[string]any{fieldCaptureMode: "unknown", fieldCaptureScope: "unspecified"}),
	}}}
	return schema
}

// ParentSchema adds constraints only for modern references, leaving the shipped
// legacy predicate schema intact. Runtime decoding also checks cross-field counts.
func ParentSchema(schema *jsonschema.Schema, kind string) *jsonschema.Schema {
	modern := constantFields(map[string]any{"hashAlgorithm": "sha256", "construction": "RFC6962"})
	modern.Properties.Set("inventory", constantFields(map[string]any{fieldKind: kind}))
	modern.Properties.Set("treeSize", &jsonschema.Schema{Minimum: "1", Maximum: "1000000"})
	modern.Properties.Set("merkleRoot", &jsonschema.Schema{Pattern: "^[0-9a-f]{64}$"})
	modern.Not = &jsonschema.Schema{AnyOf: []*jsonschema.Schema{
		{Required: []string{"leaves"}}, {Required: []string{"manifest"}}, {Required: []string{"manifestUploaded"}},
	}}
	schema.If = &jsonschema.Schema{Required: []string{"inventory"}}
	schema.Then = modern
	return schema
}
