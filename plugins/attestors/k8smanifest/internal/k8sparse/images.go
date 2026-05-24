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

// ExtractImages returns every container image reference reachable from a
// Kubernetes object's spec, for the workload kinds the k8smanifest
// attestor recognises. Each kind has a known path to the pod spec:
//
//	Pod:                                spec
//	ReplicaSet/StatefulSet/DaemonSet:   spec.template.spec
//	Deployment/Job:                     spec.template.spec
//	CronJob:                            spec.jobTemplate.spec.template.spec
//
// Both `containers` and `initContainers` arrays are scanned. Anything
// off this list (CustomResourceDefinitions, etc.) returns an empty
// slice — same behaviour as the old typed code path.
//
// `kind` is the value of the top-level "kind" field. `doc` is the
// already-JSON-decoded document body.
func ExtractImages(kind string, doc map[string]interface{}) []string {
	podSpec := podSpecForKind(kind, doc)
	if podSpec == nil {
		return nil
	}
	containers := imagesFromContainerArray(podSpec, "containers")
	initContainers := imagesFromContainerArray(podSpec, "initContainers")
	images := make([]string, 0, len(containers)+len(initContainers))
	images = append(images, containers...)
	images = append(images, initContainers...)
	return images
}

// podSpecForKind walks `doc` and returns the embedded pod spec for the
// given Kubernetes kind. Returns nil if the doc doesn't have a pod spec
// at the expected path.
func podSpecForKind(kind string, doc map[string]interface{}) map[string]interface{} {
	switch kind {
	case "Pod":
		return getMap(doc, "spec")
	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
		return getMap(doc, "spec", "template", "spec")
	case "CronJob":
		return getMap(doc, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return nil
	}
}

// imagesFromContainerArray reads `containers[].image` (or initContainers,
// etc.) from a pod spec.
func imagesFromContainerArray(podSpec map[string]interface{}, field string) []string {
	raw, ok := podSpec[field]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, c := range arr {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		img, ok := cm["image"].(string)
		if !ok || img == "" {
			continue
		}
		out = append(out, img)
	}
	return out
}

// ExtractNodeSystemInfo pulls the .status.nodeInfo fields from a Node
// manifest into a NodeSystemInfo. Returns the zero value if the input
// doesn't have a nodeInfo block.
func ExtractNodeSystemInfo(doc map[string]interface{}) NodeSystemInfo {
	ni := getMap(doc, "status", "nodeInfo")
	if ni == nil {
		return NodeSystemInfo{}
	}
	return NodeSystemInfo{
		MachineID:               getString(ni, "machineID"),
		SystemUUID:              getString(ni, "systemUUID"),
		BootID:                  getString(ni, "bootID"),
		KernelVersion:           getString(ni, "kernelVersion"),
		OSImage:                 getString(ni, "osImage"),
		ContainerRuntimeVersion: getString(ni, "containerRuntimeVersion"),
		KubeletVersion:          getString(ni, "kubeletVersion"),
		KubeProxyVersion:        getString(ni, "kubeProxyVersion"),
		OperatingSystem:         getString(ni, "operatingSystem"),
		Architecture:            getString(ni, "architecture"),
	}
}

// ExtractNodeLabels pulls metadata.labels off a Node manifest into a
// flat string→string map.
func ExtractNodeLabels(doc map[string]interface{}) map[string]string {
	labels := getMap(doc, "metadata", "labels")
	if labels == nil {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// ExtractName reads .metadata.name off a doc.
func ExtractName(doc map[string]interface{}) string {
	return getString(getMap(doc, "metadata"), "name")
}

// ExtractKind reads top-level .kind off a doc.
func ExtractKind(doc map[string]interface{}) string {
	return getString(doc, "kind")
}

// IsList returns true if the doc is a top-level Kubernetes List
// (kind="List"), and returns the .items slice for caller iteration.
func IsList(doc map[string]interface{}) (items []map[string]interface{}, ok bool) {
	if ExtractKind(doc) != "List" {
		return nil, false
	}
	raw, present := doc["items"]
	if !present {
		return nil, true
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, true
	}
	out := make([]map[string]interface{}, 0, len(arr))
	for _, el := range arr {
		if m, ok := el.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out, true
}

// getMap walks a nested map by string keys. Returns nil if any step
// fails (key missing, value not a map).
func getMap(m map[string]interface{}, keys ...string) map[string]interface{} {
	cur := m
	for _, k := range keys {
		if cur == nil {
			return nil
		}
		next, ok := cur[k].(map[string]interface{})
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// getString reads a string key off a map. Returns "" if missing.
func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
