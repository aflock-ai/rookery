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

	"github.com/aflock-ai/rookery/attestation/standards"
	"github.com/spf13/cobra"
)

// standardsCatalogListing is `cilock tools standards --format json`: the
// embedded standards guidance catalog, the same data run and verify consult
// to phrase their next steps, and what the docs site generates from.
type standardsCatalogListing struct {
	Schema         string              `json:"schema"`
	GuidanceSchema string              `json:"guidance_schema"`
	Notice         string              `json:"notice"`
	Standards      []standards.Catalog `json:"standards"`
}

func toolsStandardsCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "standards",
		Short: "Show the SLSA Build and ALPS guidance catalog: level requirements, how cilock observes them, and next steps",
		Long: "standards prints the embedded guidance catalog that `cilock run` and `cilock verify` use to report an\n" +
			"observed CEILING per standard and the next steps that would raise it. A ceiling is never a verified\n" +
			"level. Steps marked planned are coming and have no copyable snippet yet; levels marked future have\n" +
			"no action at all.",
		Example: `  cilock tools standards
  cilock tools standards --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cats, err := standards.SortedCatalogs()
			if err != nil {
				return fmt.Errorf("standards catalog: %w", err)
			}
			switch strings.ToLower(format) {
			case formatJSON:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(standardsCatalogListing{
					Schema: standards.CatalogSchema, GuidanceSchema: standards.GuidanceSchema,
					Notice: standards.CeilingNotice, Standards: cats,
				})
			case "", formatText:
				return writeStandardsCatalog(cmd.OutOrStdout(), cats)
			default:
				return fmt.Errorf("unknown --format %q (want text|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", formatText, "Output format: text (default) or json")
	return cmd
}

func writeStandardsCatalog(w io.Writer, cats []standards.Catalog) error {
	var b strings.Builder
	b.WriteString(standards.CeilingNotice + "\n")
	for _, c := range cats {
		fmt.Fprintf(&b, "\n%s (%s) %s\n", c.Title, c.Spec, c.SpecURL)
		for _, l := range c.Levels {
			fmt.Fprintf(&b, "  %s [%s]\n    requires:    %s\n    observed by: %s\n", l.Level, l.Status, l.Requires, l.ObservedBy)
		}
		b.WriteString("  next steps:\n")
		for _, s := range c.Steps {
			fmt.Fprintf(&b, "    %s -> %s [%s, when: %s, closes: %s]\n      %s\n", s.ID, s.TargetLevel, s.Status, s.When, s.Closes, s.Action)
			if s.Command != "" {
				fmt.Fprintf(&b, "      $ %s\n", s.Command)
			}
			if s.Snippet != "" {
				note := ""
				if s.Status != standards.StatusAvailable || s.RenderedSnippet() == "" {
					note = " (not yet published; not shown in run or verify output)"
				}
				fmt.Fprintf(&b, "      snippet%s:\n", note)
				for _, line := range strings.Split(strings.TrimRight(s.Snippet, "\n"), "\n") {
					fmt.Fprintf(&b, "        %s\n", line)
				}
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
