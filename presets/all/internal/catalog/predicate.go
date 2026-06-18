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

package catalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// summarizePredicate renders a detection.Predicate tree into one human-usable
// line, e.g. `any_of(argv_prefix:[syft], argv_prefix:[cdxgen])` or
// `product_glob:[*.spdx.json, **/*.spdx.json]`. Composer children are sorted by
// their rendered text so the output is deterministic regardless of source
// ordering. A nil predicate renders the empty string.
func summarizePredicate(p *detection.Predicate) string {
	if p == nil {
		return ""
	}
	switch {
	// Recursive composites.
	case len(p.AnyOf) > 0:
		return "any_of(" + joinSorted(p.AnyOf) + ")"
	case len(p.AllOf) > 0:
		return "all_of(" + joinSorted(p.AllOf) + ")"
	case p.Not != nil:
		return "not(" + summarizePredicate(p.Not) + ")"
	case p.ExecObserved != nil:
		return "exec_observed(" + summarizePredicate(p.ExecObserved) + ")"
	}
	if s := summarizePreGateLeaf(p); s != "" {
		return s
	}
	return summarizePostGateLeaf(p)
}

// summarizePreGateLeaf renders the pre-execution leaves (argv/env/file/binary/
// imds/gcp/azure/socket). Returns "" when no pre-gate leaf is set so the caller
// can fall through to the post-gate leaves.
func summarizePreGateLeaf(p *detection.Predicate) string {
	switch {
	case len(p.ArgvPrefix) > 0:
		return "argv_prefix:[" + strings.Join(p.ArgvPrefix, " ") + "]"
	case p.ArgvContains != "":
		return "argv_contains:" + p.ArgvContains
	case p.ArgvRegex != "":
		return "argv_regex:" + p.ArgvRegex
	case p.EnvSet != "":
		return "env_set:" + p.EnvSet
	case p.EnvEquals != nil:
		return "env_equals:" + p.EnvEquals.Var + "=" + p.EnvEquals.Value
	case p.FileExists != "":
		return "file_exists:" + p.FileExists
	case len(p.FileGlob) > 0:
		return "file_glob:[" + strings.Join(p.FileGlob, ", ") + "]"
	case p.BinaryDigestIn != "":
		return "binary_digest_in:" + p.BinaryDigestIn
	case p.IMDSReachable != nil:
		return fmt.Sprintf("imds_reachable:%t", *p.IMDSReachable)
	case p.GCPMetadataReachable != nil:
		return fmt.Sprintf("gcp_metadata_reachable:%t", *p.GCPMetadataReachable)
	case p.AzureMetadataReachable != nil:
		return fmt.Sprintf("azure_metadata_reachable:%t", *p.AzureMetadataReachable)
	case p.SocketListening != nil:
		return fmt.Sprintf("socket_listening:%d", *p.SocketListening)
	default:
		return ""
	}
}

// summarizePostGateLeaf renders the post-execution leaves (product/material/
// exit). Returns "" when no post-gate leaf is set.
func summarizePostGateLeaf(p *detection.Predicate) string {
	switch {
	case len(p.ProductGlob) > 0:
		return "product_glob:[" + strings.Join(p.ProductGlob, ", ") + "]"
	case p.ProductMime != "":
		return "product_mime:" + p.ProductMime
	case p.MaterialChanged != "":
		return "material_changed:" + p.MaterialChanged
	case p.ExitCode != nil:
		return "exit_code:" + exitCodeString(p.ExitCode)
	default:
		return ""
	}
}

// joinSorted renders each child predicate, sorts the rendered strings, and
// joins them — the sort is what makes any_of/all_of summaries deterministic.
func joinSorted(children []detection.Predicate) string {
	rendered := make([]string, 0, len(children))
	for i := range children {
		rendered = append(rendered, summarizePredicate(&children[i]))
	}
	sort.Strings(rendered)
	return strings.Join(rendered, ", ")
}

func exitCodeString(e *detection.ExitCodeLeaf) string {
	switch {
	case e.Eq != nil:
		return fmt.Sprintf("eq=%d", *e.Eq)
	case e.Ne != nil:
		return fmt.Sprintf("ne=%d", *e.Ne)
	case len(e.In) > 0:
		parts := make([]string, len(e.In))
		for i, v := range e.In {
			parts[i] = fmt.Sprintf("%d", v)
		}
		return "in=[" + strings.Join(parts, ",") + "]"
	default:
		return ""
	}
}

// convertPredicate projects a detection.Predicate tree into the JSON-friendly
// PredicateNode, preserving the exact tagged-union structure (the raw
// applicability) while sorting composer children deterministically. Returns nil
// for a nil input or an empty node.
func convertPredicate(p *detection.Predicate) *PredicateNode {
	if p == nil {
		return nil
	}
	n := &PredicateNode{
		ArgvPrefix:      p.ArgvPrefix,
		ArgvContains:    p.ArgvContains,
		ArgvRegex:       p.ArgvRegex,
		EnvSet:          p.EnvSet,
		FileExists:      p.FileExists,
		FileGlob:        p.FileGlob,
		BinaryDigestIn:  p.BinaryDigestIn,
		IMDSReachable:   p.IMDSReachable,
		GCPMetadata:     p.GCPMetadataReachable,
		AzureMetadata:   p.AzureMetadataReachable,
		SocketListen:    p.SocketListening,
		ProductGlob:     p.ProductGlob,
		ProductMime:     p.ProductMime,
		MaterialChanged: p.MaterialChanged,
	}
	if p.EnvEquals != nil {
		n.EnvEquals = p.EnvEquals.Var + "=" + p.EnvEquals.Value
	}
	if p.ExitCode != nil {
		n.ExitCode = exitCodeString(p.ExitCode)
	}
	if p.ExecObserved != nil {
		n.ExecObserved = convertPredicate(p.ExecObserved)
	}
	if p.Not != nil {
		n.Not = convertPredicate(p.Not)
	}
	n.AnyOf = convertChildren(p.AnyOf)
	n.AllOf = convertChildren(p.AllOf)
	return n
}

// convertChildren converts and deterministically sorts a composer's children
// by their summarized rendering, so the raw tree is as diff-stable as the
// flattened summary.
func convertChildren(children []detection.Predicate) []PredicateNode {
	if len(children) == 0 {
		return nil
	}
	idx := make([]int, len(children))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return summarizePredicate(&children[idx[a]]) < summarizePredicate(&children[idx[b]])
	})
	out := make([]PredicateNode, 0, len(children))
	for _, i := range idx {
		if c := convertPredicate(&children[i]); c != nil {
			out = append(out, *c)
		}
	}
	return out
}
