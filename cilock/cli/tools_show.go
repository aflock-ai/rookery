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

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/spf13/cobra"
)

// toolShow is the full machine-readable record for one catalog entry:
// the structured metadata (toolEntry) plus the long-form doc parsed from
// the embedded <name>.doc.md. The cilock-docs website generator consumes
// `cilock tools show <name> --format json` and renders one page from it,
// so the website and this CLI surface read the exact same source.
type toolShow struct {
	toolEntry
	Doc *detection.DetectorDoc `json:"doc,omitempty"`
}

func toolsShowCmd() *cobra.Command {
	var (
		format  string
		section string
	)
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show full catalog detail for one tool/attestor (the same source the website renders)",
		Args:  cobra.ExactArgs(1),
		Example: `  # Summary + the list of documentation sections
  cilock tools show sarif

  # Print just one section by slug
  cilock tools show sarif --section policy-gotcha

  # Full machine-readable record (what the website generates from)
  cilock tools show sarif --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			entry, ok := findToolEntry(name)
			if !ok {
				return fmt.Errorf("unknown tool/attestor %q (try `cilock tools list`)", name)
			}
			doc, _, docErr := detection.Default().LookupDoc(name)
			if docErr != nil {
				return fmt.Errorf("parse doc for %q: %w", name, docErr)
			}

			switch strings.ToLower(format) {
			case formatJSON:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(toolShow{toolEntry: entry, Doc: doc})
			case "", formatText:
				if section != "" {
					return writeToolSection(cmd.OutOrStdout(), name, doc, section)
				}
				return writeToolSummary(cmd.OutOrStdout(), entry, doc)
			default:
				return fmt.Errorf("unknown --format %q (want text|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", formatText, "Output format: text (default) or json")
	cmd.Flags().StringVar(&section, "section", "", "Print only one documentation section, by slug (see the summary)")
	return cmd
}

func findToolEntry(name string) (toolEntry, bool) {
	for _, e := range buildToolEntries() {
		if e.Name == name {
			return e, true
		}
	}
	return toolEntry{}, false
}

func writeToolSection(w io.Writer, name string, doc *detection.DetectorDoc, slug string) error {
	if doc == nil {
		return fmt.Errorf("%q has no documentation in the catalog yet", name)
	}
	for _, s := range doc.Sections {
		if s.Slug == slug {
			_, err := fmt.Fprintln(w, s.Markdown)
			return err
		}
	}
	avail := make([]string, 0, len(doc.Sections))
	for _, s := range doc.Sections {
		avail = append(avail, s.Slug)
	}
	return fmt.Errorf("no section %q for %q; available: %s", slug, name, strings.Join(avail, ", "))
}

func writeToolSummary(w io.Writer, e toolEntry, doc *detection.DetectorDoc) error {
	desc := e.Description
	if doc != nil && doc.Description != "" {
		desc = doc.Description
	}
	// Write directly to w via a helper that latches the first error, so
	// each Fprintf's error is handled (errcheck) without WriteString(Sprintf)
	// (staticcheck QF1012).
	var werr error
	pr := func(format string, a ...any) {
		if werr == nil {
			_, werr = fmt.Fprintf(w, format, a...)
		}
	}
	pr("%s\n\n", e.Name)
	if desc != "" {
		pr("%s\n\n", desc)
	}
	pr("  source:            %s\n", e.Source)
	if len(e.Categories) > 0 {
		pr("  category:          %s\n", joinCategories(e.Categories))
	}
	if e.PredicateType != "" {
		pr("  predicate type:    %s\n", e.PredicateType)
	}
	if len(e.EmitsFormats) > 0 {
		pr("  emits format:      %s\n", strings.Join(e.EmitsFormats, ", "))
	}
	pr("  recommended trace: %s\n", e.RecommendedTrace)
	if e.Upstream != nil && e.Upstream.Source != "" {
		pr("  upstream:          %s\n", e.Upstream.Source)
	}
	if len(e.Triggers) > 0 {
		pr("  detected when:\n")
		for _, t := range e.Triggers {
			pr("    - [%s] %s: %s\n", t.Gate, t.Kind, t.Value)
		}
	}

	if doc != nil && len(doc.Sections) > 0 {
		pr("\nDocumentation sections (use --section <slug>):\n")
		for _, s := range doc.Sections {
			pr("    %-22s %s\n", s.Slug, s.Title)
		}
		pr("\nFull docs: https://cilock.aflock.ai/%s/%s\n", docArea(e), e.Name)
	} else {
		pr("\n(no long-form documentation in the catalog yet — add %s.doc.md)\n", e.Name)
	}
	return werr
}

// docArea picks the website section a catalog entry's page lives under.
func docArea(e toolEntry) string {
	if e.Source == sourceAttestorBacked && e.PredicateType != "" {
		return "attestors"
	}
	return "tools"
}
