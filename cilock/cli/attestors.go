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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func AttestorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestors",
		Short: "Get information about available attestors",
		Long:  "Get information about all the available attestors in CIlock",
	}

	cmd.AddCommand(SchemaCmd())
	cmd.AddCommand(ListCmd())

	return cmd
}

func ListCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available attestors",
		Long:  "Lists all the available attestors in CIlock with supporting information",
		Example: `  # List every attestor, as a table
  cilock attestors list

  # Machine-readable list for an agent to consume
  cilock attestors list --format json`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd.OutOrStdout(), format)
		},
	}
	// Mirror `cilock tools list`: table by default, json for agents.
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table (default) or json")
	return cmd
}

func SchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "schema",
		Short:             "Show the JSON schema of a specific attestor",
		Long:              "Print the JSON schema of the predicate that the specified attestor generates",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSchema(cmd.Context(), args)
		},
	}
	return cmd
}

// attestorListEntry is the machine-readable shape emitted by
// `cilock attestors list --format json`. The markers the table appends to the
// name (" (always run)", " (default)") are split into booleans so an agent
// enumerating attestors doesn't have to scrape ASCII.
type attestorListEntry struct {
	Name          string `json:"name"`
	PredicateType string `json:"predicate_type"`
	RunType       string `json:"run_type"`
	AlwaysRun     bool   `json:"always_run"`
	Default       bool   `json:"default"`
}

func buildAttestorListEntries() []attestorListEntry {
	entries := attestation.RegistrationEntries()
	out := make([]attestorListEntry, 0, len(entries))
	for _, entry := range entries {
		f := entry.Factory()
		name := f.Name()
		out = append(out, attestorListEntry{
			Name:          name,
			PredicateType: f.Type(),
			RunType:       fmt.Sprintf("%v", f.RunType()),
			AlwaysRun:     isAlwaysRunAttestor(name),
			Default:       isDefaultAttestor(name),
		})
	}
	return out
}

// isAlwaysRunAttestor reports whether the named attestor fires on every
// `cilock run` regardless of --attestations (product, material, command-run).
func isAlwaysRunAttestor(name string) bool {
	if name == attestorCommandRun {
		return true
	}
	for _, a := range alwaysRunAttestors {
		if name == a.Name() {
			return true
		}
	}
	return false
}

// isDefaultAttestor reports whether the named attestor is in the default set
// recorded when --attestations is omitted.
func isDefaultAttestor(name string) bool {
	for _, a := range options.DefaultAttestors {
		if name == a {
			return true
		}
	}
	return false
}

func runList(w io.Writer, format string) error {
	entries := buildAttestorListEntries()
	switch strings.ToLower(format) {
	case "", "table":
		return writeAttestorsTable(w, entries)
	case formatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	default:
		return fmt.Errorf("unknown --format %q (want table|json)", format)
	}
}

func writeAttestorsTable(w io.Writer, entries []attestorListEntry) error {
	items := make([][]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name
		if e.AlwaysRun {
			name += " (always run)"
		}
		if e.Default {
			name += " (default)"
		}
		items = append(items, []string{name, e.PredicateType, e.RunType})
	}

	table := tablewriter.NewWriter(w)
	table.Header([]string{"Name", "Type", "RunType"})
	if err := table.Bulk(items); err != nil {
		return fmt.Errorf("error adding items to table: %w", err)
	}

	if err := table.Render(); err != nil {
		return fmt.Errorf("error rendering table: %w", err)
	}

	return nil
}

func runSchema(_ context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("you must specify an attestor to view the schema of. Use 'cilock attestors list' for a list of available attestors")
	} else if len(args) > 1 {
		return fmt.Errorf("you can only get one attestor schema at a time")
	}

	attestor, err := attestation.GetAttestor(args[0])
	if err != nil {
		return fmt.Errorf("error getting attestor: %w", err)
	}

	schema := attestor.Schema()
	schemaJson, err := schema.MarshalJSON()
	if err != nil {
		return fmt.Errorf("error marshalling JSON schema: %w", err)
	}

	var indented bytes.Buffer
	err = json.Indent(&indented, schemaJson, "", "  ")
	if err != nil {
		return fmt.Errorf("error indenting JSON schema: %w", err)
	}

	fmt.Print(indented.String())
	return nil
}
