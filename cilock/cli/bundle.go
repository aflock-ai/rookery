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

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/bundle"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/spf13/cobra"
)

// BundleCmd is the `cilock bundle` parent command.
func BundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "bundle",
		Short:             "Create and inspect attestation bundles",
		Long:              "Attestation bundles are tar.gz packages of DSSE envelopes — portable evidence sets for `cilock verify --bundle`.",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
	}
	cmd.AddCommand(bundleCreateCmd())
	cmd.AddCommand(bundleInspectCmd())
	return cmd
}

type bundleCreateOptions struct {
	Subjects       []string
	ArchivistaURL  string
	ArchivistaHdrs []string
	Output         string
	MaxEnvelopes   int
	MaxDepth       int
}

func bundleCreateCmd() *cobra.Command {
	o := bundleCreateOptions{}
	cmd := &cobra.Command{
		Use:               "create",
		Short:             "Build a bundle by walking an Archivista subject graph",
		Long:              "Pulls every DSSE envelope reachable from the given subject digest(s) via Archivista's subject graph and packs them into a tar.gz bundle.",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Output == "" {
				return fmt.Errorf("--output is required")
			}
			if len(o.Subjects) == 0 {
				return fmt.Errorf("at least one --subject is required")
			}
			if o.ArchivistaURL == "" {
				return fmt.Errorf("--archivista-url is required")
			}
			return runBundleCreate(cmd.Context(), o)
		},
	}
	cmd.Flags().StringSliceVarP(&o.Subjects, "subject", "s", nil, "Subject digest(s) to seed the graph walk (e.g. sha256:abc...). Repeatable.")
	cmd.Flags().StringVar(&o.ArchivistaURL, "archivista-url", "", "Archivista server URL")
	cmd.Flags().StringArrayVar(&o.ArchivistaHdrs, "archivista-headers", nil, "Headers to send with each Archivista request (e.g. Authorization: Bearer ...)")
	cmd.Flags().StringVarP(&o.Output, "output", "o", "", "Path to write the bundle (tar.gz)")
	cmd.Flags().IntVar(&o.MaxEnvelopes, "max-envelopes", 10000, "Maximum envelopes to fetch before aborting")
	cmd.Flags().IntVar(&o.MaxDepth, "max-depth", 5, "Maximum subject-graph traversal depth")
	return cmd
}

func runBundleCreate(ctx context.Context, o bundleCreateOptions) error {
	headers := http.Header{}
	for _, h := range o.ArchivistaHdrs {
		idx := strings.Index(h, ":")
		if idx <= 0 {
			return fmt.Errorf("invalid --archivista-headers entry %q (expected Name: Value)", h)
		}
		name := strings.TrimSpace(h[:idx])
		value := strings.TrimSpace(h[idx+1:])
		headers.Add(name, value)
	}

	client := archivista.New(o.ArchivistaURL, archivista.WithHeaders(headers))
	log.Infof("walking Archivista subject graph (%d seed subjects, max depth %d)", len(o.Subjects), o.MaxDepth)

	envelopes, err := client.FetchAllForSubject(ctx, o.Subjects,
		archivista.WithMaxEnvelopes(o.MaxEnvelopes),
		archivista.WithMaxDepth(o.MaxDepth),
	)
	if err != nil {
		// FetchAllForSubject returns partial envelopes alongside a
		// cap-exceeded error (depth or envelope count). Surface the
		// warning so the operator knows the bundle is incomplete, but
		// keep writing what was collected — a partial bundle is more
		// useful than no bundle for offline debugging.
		if len(envelopes) == 0 {
			return fmt.Errorf("fetch from archivista: %w", err)
		}
		log.Warnf("archivista fetch returned partial results: %v", err)
	}
	log.Infof("fetched %d envelopes; writing %s", len(envelopes), o.Output)

	f, err := os.Create(o.Output) //nolint:gosec // G304: --output is a CLI-provided path
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w := bundle.NewWriter(f)
	w.SetSource(bundle.SourceArchivista, o.ArchivistaURL)
	w.SetSubjects(o.Subjects)
	for _, env := range envelopes {
		if err := w.Add(env); err != nil {
			return fmt.Errorf("add envelope: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close bundle: %w", err)
	}
	log.Infof("wrote bundle with %d envelopes", w.Count())
	return nil
}

func bundleInspectCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:               "inspect <bundle.tar.gz>",
		Short:             "Print a bundle's manifest and a per-envelope summary",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBundleInspect(args[0], jsonOut, cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the manifest as JSON (suppresses the per-envelope summary)")
	return cmd
}

func runBundleInspect(path string, jsonOut bool, out io.Writer) error {
	f, err := os.Open(path) //nolint:gosec // G304: path is a CLI-provided argument
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	r, err := bundle.Read(f)
	if err != nil {
		return err
	}

	mani := r.Manifest()
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(mani)
	}

	envs, err := r.Envelopes()
	if err != nil {
		return err
	}

	b := strings.Builder{}
	writeManifestHeader(&b, path, mani)
	writeEnvelopeSummaries(&b, mani, envs)
	_, err = io.WriteString(out, b.String())
	return err
}

func writeManifestHeader(b *strings.Builder, path string, mani bundle.Manifest) {
	b.WriteString("Bundle: ")
	b.WriteString(path)
	b.WriteString("\n  schema:    ")
	b.WriteString(mani.SchemaVersion)
	b.WriteString("\n  createdAt: ")
	b.WriteString(mani.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	b.WriteByte('\n')
	if mani.Source != "" {
		b.WriteString("  source:    ")
		b.WriteString(mani.Source)
		if mani.SourceURL != "" {
			b.WriteString(" (")
			b.WriteString(mani.SourceURL)
			b.WriteString(")")
		}
		b.WriteByte('\n')
	}
	if len(mani.Subjects) > 0 {
		b.WriteString("  subjects:\n")
		for _, s := range mani.Subjects {
			b.WriteString("    - ")
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	b.WriteString("  envelopes: ")
	b.WriteString(strconv.Itoa(mani.Count))
	b.WriteByte('\n')
}

func writeEnvelopeSummaries(b *strings.Builder, mani bundle.Manifest, envs []dsse.Envelope) {
	for i, env := range envs {
		predicateType, collectionName := summarizeEnvelope(env)
		signers := manifestKeyIDs(mani, i)

		canonical := predicateType
		if alt := attestation.LegacyAlternate(predicateType); alt != "" {
			canonical = alt + " (legacy: " + predicateType + ")"
		}

		parts := []string{"predicate=" + canonical}
		if collectionName != "" {
			parts = append(parts, "collection="+collectionName)
		}
		if signers != "" {
			parts = append(parts, signers)
		}
		b.WriteString("  [")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("] ")
		b.WriteString(strings.Join(parts, " "))
		b.WriteByte('\n')
	}
}

func summarizeEnvelope(env dsse.Envelope) (predicateType, collectionName string) {
	if len(env.Payload) == 0 {
		return "(empty)", ""
	}
	var stmt intoto.Statement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return "(non-statement)", ""
	}
	predicateType = stmt.PredicateType
	if predicateType == "" {
		predicateType = "(unknown)"
	}
	var coll attestation.Collection
	if err := json.Unmarshal(stmt.Predicate, &coll); err == nil {
		collectionName = coll.Name
	}
	return predicateType, collectionName
}

func manifestKeyIDs(mani bundle.Manifest, idx int) string {
	if idx >= len(mani.Envelopes) {
		return ""
	}
	keys := mani.Envelopes[idx].SignerKeyIDs
	if len(keys) == 0 {
		return ""
	}
	return "signers=[" + strings.Join(keys, ",") + "]"
}
