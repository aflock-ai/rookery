// Copyright 2022 The Witness Contributors
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

package docker

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalJSON_BasicFieldsNoProvenance(t *testing.T) {
	input := `{
		"buildx.build.ref": "abc123",
		"containerimage.config.digest": "sha256:config",
		"containerimage.descriptor": {
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest": "sha256:desc",
			"size": 1234,
			"platform": {"architecture": "amd64", "os": "linux"}
		},
		"containerimage.digest": "sha256:image",
		"image.name": "myimage:latest"
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	assert.Equal(t, "abc123", b.BuildRef)
	assert.Equal(t, "sha256:config", b.ContainerImageConfigDigest)
	assert.Equal(t, "sha256:desc", b.ContainerImageDescriptor.Digest)
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", b.ContainerImageDescriptor.MediaType)
	assert.Equal(t, 1234, b.ContainerImageDescriptor.Size)
	assert.Equal(t, "amd64", b.ContainerImageDescriptor.Platform.Architecture)
	assert.Equal(t, "linux", b.ContainerImageDescriptor.Platform.OS)
	assert.Equal(t, "sha256:image", b.ContainerImageDigest)
	assert.Equal(t, "myimage:latest", b.ImageName)
	assert.NotNil(t, b.Provenance)
	assert.Empty(t, b.Provenance)
}

func TestUnmarshalJSON_ProvenanceWithPlatformQueryParam(t *testing.T) {
	// The "buildx.build.provenance" key (exact match) should extract the platform
	// from the last material that has a ?platform= query param in its URI.
	input := `{
		"buildx.build.ref": "ref1",
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "pkg:docker/alpine@sha256:abc?platform=linux%2Famd64",
					"digest": {"sha256": "abc123"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {
					"frontend": "dockerfile.v0",
					"args": {"cmdline": "build .", "source": "."},
					"locals": [{"name": "context"}]
				},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	assert.Equal(t, "ref1", b.BuildRef)
	require.Contains(t, b.Provenance, "linux/amd64")
	assert.Equal(t, "dockerfile", b.Provenance["linux/amd64"].BuildType)
	assert.Len(t, b.Provenance["linux/amd64"].Materials, 1)
	assert.Equal(t, "abc123", b.Provenance["linux/amd64"].Materials[0].Digest.Sha256)
}

func TestUnmarshalJSON_ProvenanceWithArchSuffix(t *testing.T) {
	// Keys like "buildx.build.provenance/linux/amd64" use CutPrefix to extract the arch.
	input := `{
		"buildx.build.provenance/linux/amd64": {
			"buildType": "dockerfile",
			"materials": [],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		},
		"buildx.build.provenance/linux/arm64": {
			"buildType": "dockerfile",
			"materials": [],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/arm64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	require.Len(t, b.Provenance, 2)
	assert.Contains(t, b.Provenance, "linux/amd64")
	assert.Contains(t, b.Provenance, "linux/arm64")
	assert.Equal(t, "linux/amd64", b.Provenance["linux/amd64"].Invocation.Environment.Platform)
	assert.Equal(t, "linux/arm64", b.Provenance["linux/arm64"].Invocation.Environment.Platform)
}

func TestUnmarshalJSON_BothProvenanceTypes(t *testing.T) {
	// Mix of exact "buildx.build.provenance" and suffixed keys.
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "pkg:docker/alpine@sha256:abc?platform=linux%2Famd64",
					"digest": {"sha256": "abc"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		},
		"buildx.build.provenance/linux/arm64": {
			"buildType": "dockerfile",
			"materials": [],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/arm64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	require.Len(t, b.Provenance, 2)
	assert.Contains(t, b.Provenance, "linux/amd64")
	assert.Contains(t, b.Provenance, "linux/arm64")
}

func TestUnmarshalJSON_URLEncodedPlatformValue(t *testing.T) {
	// Verify that URL-encoded platform values (e.g. linux%2Farm%2Fv7) are decoded properly.
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "pkg:docker/debian@sha256:def?platform=linux%2Farm%2Fv7",
					"digest": {"sha256": "def456"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/arm/v7"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	require.Contains(t, b.Provenance, "linux/arm/v7")
	assert.Equal(t, "dockerfile", b.Provenance["linux/arm/v7"].BuildType)
}

func TestUnmarshalJSON_MaterialWithoutPlatformParam(t *testing.T) {
	// Materials with no ?platform= query param should be skipped without error.
	// When all materials lack a platform, the arch is "" and we still insert into the map.
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "pkg:docker/alpine@sha256:abc",
					"digest": {"sha256": "abc123"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	// No materials had a platform query param, so arch stays as "".
	// The provenance is still stored with key "".
	require.Contains(t, b.Provenance, "")
	assert.Equal(t, "dockerfile", b.Provenance[""].BuildType)
}

func TestUnmarshalJSON_MaterialWithMalformedURI(t *testing.T) {
	// Malformed URIs in materials should be skipped (continue), not cause an error.
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "://completely-broken",
					"digest": {"sha256": "bad"}
				},
				{
					"uri": "pkg:docker/alpine@sha256:good?platform=linux%2Famd64",
					"digest": {"sha256": "good"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	// The second material should still be processed successfully.
	require.Contains(t, b.Provenance, "linux/amd64")
}

func TestUnmarshalJSON_InvalidJSON(t *testing.T) {
	input := `{not valid json}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	assert.Error(t, err)
}

func TestUnmarshalJSON_EmptyObject(t *testing.T) {
	input := `{}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	assert.Equal(t, "", b.BuildRef)
	assert.Equal(t, "", b.ContainerImageDigest)
	assert.Equal(t, "", b.ImageName)
	assert.NotNil(t, b.Provenance)
	assert.Empty(t, b.Provenance)
}

func TestUnmarshalJSON_UnexpectedProvenancePrefix(t *testing.T) {
	// A key that contains "buildx.build.provenance" but does NOT start with
	// "buildx.build.provenance/" will hit the CutPrefix failure path.
	// E.g., "extra-buildx.build.provenance" passes strings.Contains but fails CutPrefix.
	input := `{
		"extra-buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected provenance prefix on key")
}

func TestUnmarshalJSON_UnicodeAmpersandReplacement(t *testing.T) {
	// The code does strings.ReplaceAll(mat.URI, `\u0026`, "&")
	// This handles URIs that have literal backslash-u-0-0-2-6 sequences
	// (which can occur when JSON is double-encoded or stringified oddly).
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "pkg:docker/alpine@sha256:abc?foo=bar\\u0026platform=linux%2Famd64",
					"digest": {"sha256": "abc"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	// The \u0026 in the URI should be replaced with &, allowing platform parsing.
	require.Contains(t, b.Provenance, "linux/amd64")
}

func TestUnmarshalJSON_MultipleMaterialsLastPlatformWins(t *testing.T) {
	// When "buildx.build.provenance" has multiple materials with platform params,
	// the loop overwrites `arch` each time, so the last material's platform wins.
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [
				{
					"uri": "pkg:docker/alpine@sha256:abc?platform=linux%2Famd64",
					"digest": {"sha256": "abc"}
				},
				{
					"uri": "pkg:docker/debian@sha256:def?platform=linux%2Farm64",
					"digest": {"sha256": "def"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/arm64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	// Last material with platform wins -- linux/arm64.
	require.Contains(t, b.Provenance, "linux/arm64")
	// The earlier platform should NOT be a key (overwritten).
	assert.NotContains(t, b.Provenance, "linux/amd64")
}

func TestUnmarshalJSON_InvalidProvenanceValue(t *testing.T) {
	// If the provenance value can't be unmarshalled into a Provenance struct,
	// it's silently skipped (the `if err == nil` guard).
	input := `{
		"buildx.build.provenance/linux/amd64": "this is a string, not an object"
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	// The invalid provenance should be skipped, resulting in an empty map.
	assert.Empty(t, b.Provenance)
}

func TestUnmarshalJSON_BuildRefFromRawMap(t *testing.T) {
	// Verify that buildx.build.ref is parsed both via the struct tag and the raw map.
	input := `{
		"buildx.build.ref": "my-build-reference-123"
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	assert.Equal(t, "my-build-reference-123", b.BuildRef)
}

func TestUnmarshalJSON_InvalidBuildRefValue(t *testing.T) {
	// If buildx.build.ref is not a valid string, the Unmarshal of the ref should error.
	input := `{
		"buildx.build.ref": {"not": "a string"}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	assert.Error(t, err)
}

func TestUnmarshalJSON_EmptyMaterials(t *testing.T) {
	// Provenance with empty materials array -- the loop body never executes,
	// arch stays "", provenance is stored with key "".
	input := `{
		"buildx.build.provenance": {
			"buildType": "dockerfile",
			"materials": [],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {"frontend": "dockerfile.v0", "args": {"cmdline": "", "source": ""}, "locals": []},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	require.Contains(t, b.Provenance, "")
	assert.Equal(t, "dockerfile", b.Provenance[""].BuildType)
}

func TestUnmarshalJSON_ProvenanceInvocationFields(t *testing.T) {
	// Verify that nested invocation fields are properly populated.
	input := `{
		"buildx.build.provenance/linux/amd64": {
			"buildType": "https://mobyproject.org/buildkit",
			"materials": [
				{
					"uri": "pkg:docker/golang@1.21?platform=linux%2Famd64",
					"digest": {"sha256": "abc123def456"}
				}
			],
			"invocation": {
				"configSource": {"entryPoint": "Dockerfile"},
				"parameters": {
					"frontend": "dockerfile.v0",
					"args": {"cmdline": "docker build .", "source": "Dockerfile"},
					"locals": [{"name": "context"}, {"name": "dockerfile"}]
				},
				"environment": {"platform": "linux/amd64"}
			}
		}
	}`

	var b BuildInfo
	err := json.Unmarshal([]byte(input), &b)
	require.NoError(t, err)

	prov := b.Provenance["linux/amd64"]
	assert.Equal(t, "https://mobyproject.org/buildkit", prov.BuildType)
	assert.Equal(t, "Dockerfile", prov.Invocation.ConfigSource.EntryPoint)
	assert.Equal(t, "dockerfile.v0", prov.Invocation.Parameters.Frontend)
	assert.Equal(t, "docker build .", prov.Invocation.Parameters.Args.Cmdline)
	assert.Equal(t, "Dockerfile", prov.Invocation.Parameters.Args.Source)
	assert.Len(t, prov.Invocation.Parameters.Locals, 2)
	assert.Equal(t, "context", prov.Invocation.Parameters.Locals[0].Name)
	assert.Equal(t, "dockerfile", prov.Invocation.Parameters.Locals[1].Name)
	assert.Equal(t, "linux/amd64", prov.Invocation.Environment.Platform)
}
