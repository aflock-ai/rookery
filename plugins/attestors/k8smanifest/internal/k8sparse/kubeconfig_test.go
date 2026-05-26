// Copyright 2026 TestifySec, Inc.
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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exampleKubeconfig = `apiVersion: v1
kind: Config
current-context: dev
contexts:
- name: dev
  context:
    cluster: dev-cluster
    user: dev-user
    namespace: default
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
clusters:
- name: dev-cluster
  cluster:
    server: https://dev.example.test:6443
- name: prod-cluster
  cluster:
    server: https://prod.example.test:6443
users: []
`

// TestLoadKubeconfig exercises the happy path against a realistic
// kubeconfig file: parses YAML, resolves current-context, looks up the
// cluster, returns the server URL.
func TestLoadKubeconfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(exampleKubeconfig), 0o600))

	kc, err := LoadKubeconfig(path)
	require.NoError(t, err)

	assert.Equal(t, "dev", kc.CurrentContext)

	ctx := kc.ContextByName(kc.CurrentContext)
	require.NotNil(t, ctx, "current-context must resolve")
	assert.Equal(t, "dev-cluster", ctx.Cluster)

	cluster := kc.ClusterByName(ctx.Cluster)
	require.NotNil(t, cluster, "context's cluster must resolve")
	assert.Equal(t, "https://dev.example.test:6443", cluster.Server)
}

// TestLoadKubeconfig_OtherContext exercises lookup by explicit name (the
// flow when --context overrides current-context).
func TestLoadKubeconfig_OtherContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(exampleKubeconfig), 0o600))

	kc, err := LoadKubeconfig(path)
	require.NoError(t, err)

	ctx := kc.ContextByName("prod")
	require.NotNil(t, ctx)
	assert.Equal(t, "prod-cluster", ctx.Cluster)

	cluster := kc.ClusterByName(ctx.Cluster)
	require.NotNil(t, cluster)
	assert.Equal(t, "https://prod.example.test:6443", cluster.Server)
}

// TestLoadKubeconfig_MissingFile returns a usable error message.
func TestLoadKubeconfig_MissingFile(t *testing.T) {
	_, err := LoadKubeconfig(filepath.Join(t.TempDir(), "absent"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read kubeconfig")
}

// TestLoadKubeconfig_MalformedYAML returns a parse error rather than
// silently parsing a partial file.
func TestLoadKubeconfig_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml:::"), 0o600))
	_, err := LoadKubeconfig(path)
	assert.Error(t, err)
}

// TestContextByName_NotFound returns nil, signaling the caller to error.
func TestContextByName_NotFound(t *testing.T) {
	kc := &Kubeconfig{}
	assert.Nil(t, kc.ContextByName("nope"))
	assert.Nil(t, kc.ClusterByName("nope"))
}
