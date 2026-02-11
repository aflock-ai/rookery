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

// Package v1 provides in-toto attestation v1 types as plain Go structs
// with JSON serialization. These are equivalent to the protobuf-generated
// types in github.com/in-toto/attestation/go/v1 but without the protobuf
// runtime dependency.
package v1

// ResourceDescriptor describes a software artifact or resource.
// See https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
type ResourceDescriptor struct {
	Name             string                 `json:"name,omitempty"`
	URI              string                 `json:"uri,omitempty"`
	Digest           map[string]string      `json:"digest,omitempty"`
	Content          []byte                 `json:"content,omitempty"`
	DownloadLocation string                 `json:"downloadLocation,omitempty"`
	MediaType        string                 `json:"mediaType,omitempty"`
	Annotations      map[string]interface{} `json:"annotations,omitempty"`
}
