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

// Package k8sparse provides minimal type definitions and helpers for
// extracting image references, NodeSystemInfo, and kubeconfig data from
// Kubernetes manifests, without depending on the full k8s.io/api +
// k8s.io/apimachinery + k8s.io/client-go libraries (~141 transitive
// packages).
//
// The types here are hand-written from the published Kubernetes API
// reference documentation, not copied from any Go library:
//   https://kubernetes.io/docs/reference/kubernetes-api/
//
// The JSON tags are byte-compatible with what k8s.io/api emits, so
// attestation wire-format is unchanged.
package k8sparse

// NodeSystemInfo is the subset of the Kubernetes Node.status.nodeInfo
// fields that the k8smanifest attestor records. JSON tags match the
// published k8s API (lowerCamelCase) so attestations recorded with the
// old k8s.io/api dependency and the new local type are byte-identical
// on the wire.
//
// Spec reference: https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/node-v1/#NodeSystemInfo
type NodeSystemInfo struct {
	MachineID               string `json:"machineID"`
	SystemUUID              string `json:"systemUUID"`
	BootID                  string `json:"bootID"`
	KernelVersion           string `json:"kernelVersion"`
	OSImage                 string `json:"osImage"`
	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
	KubeletVersion          string `json:"kubeletVersion"`
	KubeProxyVersion        string `json:"kubeProxyVersion"`
	OperatingSystem         string `json:"operatingSystem"`
	Architecture            string `json:"architecture"`
}
