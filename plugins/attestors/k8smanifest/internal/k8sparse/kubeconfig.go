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
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Kubeconfig is the minimal subset of the kubeconfig schema we need to
// resolve a context to a cluster server URL. The full schema is in the
// Kubernetes API reference:
//
//	https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
//
// We only consume `current-context`, `contexts[]`, and `clusters[]`.
// Authentication-related fields (users, auth-provider, etc.) are not
// read here — k8smanifest only needs the cluster server URL for the
// attestation's ClusterInfo.Server field.
type Kubeconfig struct {
	CurrentContext string         `yaml:"current-context"`
	Contexts       []NamedContext `yaml:"contexts"`
	Clusters       []NamedCluster `yaml:"clusters"`
}

// NamedContext mirrors a kubeconfig contexts[] entry.
type NamedContext struct {
	Name    string         `yaml:"name"`
	Context ContextDetails `yaml:"context"`
}

// ContextDetails references the cluster + (optionally) user/namespace.
type ContextDetails struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
}

// NamedCluster mirrors a kubeconfig clusters[] entry.
type NamedCluster struct {
	Name    string         `yaml:"name"`
	Cluster ClusterDetails `yaml:"cluster"`
}

// ClusterDetails carries the server URL we need.
type ClusterDetails struct {
	Server string `yaml:"server"`
}

// DefaultPath returns the conventional default kubeconfig path:
// $HOME/.kube/config. Matches client-go's RecommendedHomeFile.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

// LoadKubeconfig reads + parses the kubeconfig at `path`.
func LoadKubeconfig(path string) (*Kubeconfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path provided by caller
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig %s: %w", path, err)
	}
	var kc Kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("parse kubeconfig %s: %w", path, err)
	}
	return &kc, nil
}

// ContextByName looks up a named context. Returns nil if not found.
func (kc *Kubeconfig) ContextByName(name string) *ContextDetails {
	for i := range kc.Contexts {
		if kc.Contexts[i].Name == name {
			return &kc.Contexts[i].Context
		}
	}
	return nil
}

// ClusterByName looks up a named cluster. Returns nil if not found.
func (kc *Kubeconfig) ClusterByName(name string) *ClusterDetails {
	for i := range kc.Clusters {
		if kc.Clusters[i].Name == name {
			return &kc.Clusters[i].Cluster
		}
	}
	return nil
}
