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
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/gobwas/glob"
	"github.com/spf13/cobra"
)

var alwaysRunAttestors = []attestation.Attestor{product.New(), material.New()}

func RunCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters:       make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply platform-derived defaults (archivista, TSA URLs) for any
			// flags not explicitly set by the user or config file.
			o.ResolvePlatformDefaults(cmd)

			signers, err := loadSigners(cmd.Context(), o.SignerOptions, o.KMSSignerProviderOptions, providersFromFlags("signer", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signers: %w", err)
			}

			return runRun(cmd.Context(), o, args, signers...)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

func runRun(ctx context.Context, ro options.RunOptions, args []string, signers ...cryptoutil.Signer) error { //nolint:gocognit,gocyclo,funlen
	if len(signers) > 1 {
		return fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		return fmt.Errorf("no signers found")
	}

	timestampers := []timestamp.Timestamper{}
	for _, url := range ro.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	// Create fresh attestor instances each time to avoid leaking state
	// from prior invocations (alwaysRunAttestors holds shared singletons).
	attestors := []attestation.Attestor{product.New(), material.New()}
	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(ro.Tracing)))
	}

	for _, a := range ro.Attestations {
		if a == "command-run" {
			log.Warnf("'command-run' is a builtin attestor and cannot be called with --attestations flag")
			continue
		}

		duplicate := false
		for _, att := range attestors {
			if a != att.Name() {
			} else {
				log.Warnf("Attestor %s already declared, skipping", a)
				duplicate = true
				break
			}
		}

		if !duplicate {
			attestor, err := attestation.GetAttestor(a)
			if err != nil {
				return fmt.Errorf("failed to create attestor: %w", err)
			}
			attestors = append(attestors, attestor)
		}
	}

	for i, attestor := range attestors {
		setters, ok := ro.AttestorOptSetters[attestor.Name()]
		if !ok {
			continue
		}

		updated, err := registry.SetOptions(attestor, setters...)
		if err != nil {
			return fmt.Errorf("failed to set attestor option for %v: %w", attestor.Type(), err)
		}
		attestors[i] = updated
	}

	var roHashes []cryptoutil.DigestValue
	for _, hashStr := range ro.Hashes {
		hash, err := cryptoutil.HashFromString(hashStr)
		if err != nil {
			return fmt.Errorf("failed to parse hash: %w", err)
		}
		roHashes = append(roHashes, cryptoutil.DigestValue{Hash: hash, GitOID: false})
	}

	for _, dirHashGlobItem := range ro.DirHashGlobs {
		_, err := glob.Compile(dirHashGlobItem)
		if err != nil {
			return fmt.Errorf("failed to compile glob: %v", err)
		}
	}

	// Build attestation context options
	attestationOpts := []attestation.AttestationContextOption{
		attestation.WithWorkingDir(ro.WorkingDir),
		attestation.WithHashes(roHashes),
		attestation.WithDirHashGlob(ro.DirHashGlobs),
	}

	if ro.EnvFilterSensitiveVars {
		attestationOpts = append(attestationOpts, attestation.WithEnvFilterVarsEnabled())
	}
	if ro.EnvDisableSensitiveVars {
		attestationOpts = append(attestationOpts, attestation.WithEnvDisableDefaultSensitiveList())
	}
	if len(ro.EnvAddSensitiveKeys) > 0 {
		attestationOpts = append(attestationOpts, attestation.WithEnvAdditionalKeys(ro.EnvAddSensitiveKeys))
	}
	if len(ro.EnvAllowSensitiveKeys) > 0 {
		attestationOpts = append(attestationOpts, attestation.WithEnvExcludeKeys(ro.EnvAllowSensitiveKeys))
	}
	if len(ro.EnvCaptureAllowlist) > 0 {
		attestationOpts = append(attestationOpts, attestation.WithEnvCaptureAllowlist(ro.EnvCaptureAllowlist))
	}

	additionalSubjects, err := parseSubjectFlags(ro.Subjects)
	if err != nil {
		return fmt.Errorf("failed to parse --subjects: %w", err)
	}

	runOpts := []workflow.RunOption{
		workflow.RunWithSigners(signers...),
		workflow.RunWithAttestors(attestors),
		workflow.RunWithAttestationOpts(attestationOpts...),
		workflow.RunWithTimestampers(timestampers...),
	}
	if len(additionalSubjects) > 0 {
		runOpts = append(runOpts, workflow.RunWithAdditionalSubjects(additionalSubjects))
	}

	results, runErr := workflow.RunWithExports(ro.StepName, runOpts...)
	// Don't return immediately on error — write whatever results were
	// produced first (e.g. secretscan findings), then return the error.
	// This ensures attestation files are always written for forensic
	// analysis even when an attestor fails (e.g. --attestor-secretscan-fail-on-detection).
	if runErr != nil && len(results) == 0 {
		return runErr
	}

	// When multiple results are produced (e.g. MultiExporter attestors), an output
	// file path is required — otherwise exported attestors would create files named
	// "-<name>.json" in the current directory instead of writing to stdout.
	hasExported := false
	for _, result := range results {
		if result.AttestorName != "" {
			hasExported = true
			break
		}
	}
	if hasExported && ro.OutFilePath == "" {
		return fmt.Errorf("--outfile is required when attestors export multiple attestations")
	}

	for _, result := range results {
		signedBytes, err := json.Marshal(&result.SignedEnvelope)
		if err != nil {
			return fmt.Errorf("failed to marshal envelope: %w", err)
		}

		outfile := ro.OutFilePath
		if result.AttestorName != "" {
			// Sanitize attestor name: MultiExporter uses "parent/child" format
			// which would create unintended subdirectories in the output path.
			safeName := strings.ReplaceAll(result.AttestorName, "/", "-")
			outfile += "-" + safeName + ".json"
		}

		out, err := loadOutfile(outfile)
		if err != nil {
			return fmt.Errorf("failed to open out file: %w", err)
		}

		_, writeErr := out.Write(signedBytes)
		closeOutfile(out)
		if writeErr != nil {
			return fmt.Errorf("failed to write envelope to out file: %w", writeErr)
		}

		if ro.ArchivistaOptions.Enable {
			archivistaClient, err := ro.ArchivistaOptions.Client()
			if err != nil {
				return fmt.Errorf("failed to create archivista client: %w", err)
			}

			gitoid, err := archivistaClient.Store(ctx, result.SignedEnvelope)
			if err != nil {
				return fmt.Errorf("failed to store artifact in archivista: %w", err)
			}
			log.Infof("Stored in archivista as %v\n", gitoid)
		}
	}

	// Emit v0.3 product/material tree sidecars adjacent to the signed
	// attestation file. These sidecars carry the full leaf set the
	// Merkle root commits to and are consumed by `cilock prove` to
	// generate per-leaf inclusion proofs. They are NOT signed —
	// integrity comes from the fact that the reconstructed Merkle
	// root must match the root in the signed collection attestation.
	//
	// If --outfile was empty (stdout), no sidecars are written: there
	// is no on-disk anchor to derive the sidecar path from.
	if ro.OutFilePath != "" {
		if err := emitRunSidecars(ro.OutFilePath, attestors); err != nil {
			// Don't fail the whole run on a sidecar write error: the
			// signed attestation is already on disk and is the real
			// artifact. But the sidecar IS required for `cilock prove`,
			// so emit an unambiguous error-tagged line to stderr too so
			// CI log scrapers don't miss it — a missing sidecar surfaces
			// later as a confusing "no such file" from `prove`, which is
			// a known operator footgun.
			log.Errorf("tree sidecar write failed; `cilock prove` will not work against this attestation until the sidecar is regenerated: %v", err)
			fmt.Fprintf(os.Stderr, "error: tree sidecar write failed: %v\n", err)
		}
	}

	// Return the deferred attestor error (e.g. secretscan fail-on-detection)
	// after writing all output files.
	if runErr != nil {
		return runErr
	}
	return nil
}

// emitRunSidecars walks the attestor list looking for product and
// material attestors, extracts their (path -> sha256-hex) maps, and
// hands them to writeSidecarsForRun. Decoupled into its own function
// so the sidecar logic doesn't dominate runRun.
func emitRunSidecars(outfile string, attestors []attestation.Attestor) error {
	products := map[string]string{}
	materials := map[string]string{}
	sha256DV := cryptoutil.DigestValue{Hash: crypto.SHA256}

	for _, att := range attestors {
		if p, ok := att.(attestation.Producer); ok {
			for path, prod := range p.Products() {
				digest, hasSHA := prod.Digest[sha256DV]
				if !hasSHA {
					// A product without a sha256 digest cannot
					// participate in the v0.3 tree. Skip silently —
					// the v0.3 attestor will emit the same skip.
					continue
				}
				products[inclusionproof.NormalizePath(path)] = digest
			}
		}
		if m, ok := att.(attestation.Materialer); ok {
			for path, ds := range m.Materials() {
				digest, hasSHA := ds[sha256DV]
				if !hasSHA {
					continue
				}
				materials[inclusionproof.NormalizePath(path)] = digest
			}
		}
	}

	return writeSidecarsForRun(outfile, products, materials)
}
