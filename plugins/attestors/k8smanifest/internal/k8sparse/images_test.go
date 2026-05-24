// Copyright 2026 The Aflock Authors
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

package k8sparse

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractImages covers every kind the k8smanifest attestor maps to
// a pod spec. Each case feeds a minimal JSON manifest, asserts the
// expected image set, and exercises both `containers` and
// `initContainers` arrays.
func TestExtractImages(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		want     []string
	}{
		{
			name: "Pod single container",
			manifest: `{
				"kind": "Pod",
				"spec": {
					"containers": [{"name": "app", "image": "nginx:1.27"}]
				}
			}`,
			want: []string{"nginx:1.27"},
		},
		{
			name: "Pod with init containers",
			manifest: `{
				"kind": "Pod",
				"spec": {
					"initContainers": [{"image": "busybox:1.36"}],
					"containers":     [{"image": "nginx:1.27"}]
				}
			}`,
			want: []string{"nginx:1.27", "busybox:1.36"},
		},
		{
			name: "Deployment via spec.template.spec",
			manifest: `{
				"kind": "Deployment",
				"spec": {"template": {"spec": {"containers": [{"image": "myapp:v1"}]}}}
			}`,
			want: []string{"myapp:v1"},
		},
		{
			name: "StatefulSet",
			manifest: `{
				"kind": "StatefulSet",
				"spec": {"template": {"spec": {"containers": [{"image": "db:13"}]}}}
			}`,
			want: []string{"db:13"},
		},
		{
			name: "DaemonSet",
			manifest: `{
				"kind": "DaemonSet",
				"spec": {"template": {"spec": {"containers": [{"image": "node-exporter:1.7"}]}}}
			}`,
			want: []string{"node-exporter:1.7"},
		},
		{
			name: "ReplicaSet",
			manifest: `{
				"kind": "ReplicaSet",
				"spec": {"template": {"spec": {"containers": [{"image": "app:rs"}]}}}
			}`,
			want: []string{"app:rs"},
		},
		{
			name: "Job",
			manifest: `{
				"kind": "Job",
				"spec": {"template": {"spec": {"containers": [{"image": "runner:job"}]}}}
			}`,
			want: []string{"runner:job"},
		},
		{
			name: "CronJob (deeper path through jobTemplate)",
			manifest: `{
				"kind": "CronJob",
				"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"image": "cron:weekly"}]}}}}}
			}`,
			want: []string{"cron:weekly"},
		},
		{
			name: "Service (no pod spec) returns empty",
			manifest: `{
				"kind": "Service",
				"spec": {"selector": {"app": "x"}}
			}`,
			want: nil,
		},
		{
			name: "Unknown CRD returns empty",
			manifest: `{
				"kind": "MyCustomResource",
				"spec": {"containers": [{"image": "should-not-be-picked-up"}]}
			}`,
			want: nil,
		},
		{
			name: "Multiple containers preserve order",
			manifest: `{
				"kind": "Pod",
				"spec": {
					"containers": [
						{"image": "first:1"},
						{"image": "second:2"},
						{"image": "third:3"}
					]
				}
			}`,
			want: []string{"first:1", "second:2", "third:3"},
		},
		{
			name: "Missing image field on a container is skipped, not an error",
			manifest: `{
				"kind": "Pod",
				"spec": {
					"containers": [
						{"name": "no-image"},
						{"image": "real:1"}
					]
				}
			}`,
			want: []string{"real:1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(tc.manifest), &doc))
			got := ExtractImages(ExtractKind(doc), doc)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestExtractNodeSystemInfo verifies the Node.status.nodeInfo extraction
// against an example matching the published k8s API shape.
func TestExtractNodeSystemInfo(t *testing.T) {
	const manifest = `{
		"kind": "Node",
		"metadata": {"name": "node-1"},
		"status": {
			"nodeInfo": {
				"machineID":               "abc-123",
				"systemUUID":              "uuid-1",
				"bootID":                  "boot-1",
				"kernelVersion":           "6.5.0",
				"osImage":                 "Ubuntu 22.04",
				"containerRuntimeVersion": "containerd://1.7.0",
				"kubeletVersion":          "v1.30.0",
				"kubeProxyVersion":        "v1.30.0",
				"operatingSystem":         "linux",
				"architecture":            "amd64"
			}
		}
	}`
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(manifest), &doc))

	got := ExtractNodeSystemInfo(doc)
	want := NodeSystemInfo{
		MachineID:               "abc-123",
		SystemUUID:              "uuid-1",
		BootID:                  "boot-1",
		KernelVersion:           "6.5.0",
		OSImage:                 "Ubuntu 22.04",
		ContainerRuntimeVersion: "containerd://1.7.0",
		KubeletVersion:          "v1.30.0",
		KubeProxyVersion:        "v1.30.0",
		OperatingSystem:         "linux",
		Architecture:            "amd64",
	}
	assert.Equal(t, want, got)
}

// TestExtractNodeSystemInfo_MissingNodeInfo_ReturnsZero pins the
// non-Node-or-malformed-Node behaviour.
func TestExtractNodeSystemInfo_MissingNodeInfo_ReturnsZero(t *testing.T) {
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"kind": "Node"}`), &doc))
	assert.Equal(t, NodeSystemInfo{}, ExtractNodeSystemInfo(doc))
}

// TestIsList_Recognises catches the top-level corev1.List shape that
// drives the multi-item code path in the attestor.
func TestIsList_Recognises(t *testing.T) {
	const manifest = `{
		"kind": "List",
		"items": [
			{"kind": "Pod",        "spec": {"containers": [{"image": "a:1"}]}},
			{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [{"image": "b:2"}]}}}}
		]
	}`
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(manifest), &doc))

	items, ok := IsList(doc)
	require.True(t, ok)
	require.Len(t, items, 2)
	assert.Equal(t, "Pod", ExtractKind(items[0]))
	assert.Equal(t, "Deployment", ExtractKind(items[1]))
}

func TestIsList_NotAList(t *testing.T) {
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"kind": "Pod"}`), &doc))
	items, ok := IsList(doc)
	assert.False(t, ok)
	assert.Nil(t, items)
}
