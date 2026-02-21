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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
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

func runRun(ctx context.Context, ro options.RunOptions, args []string, signers ...cryptoutil.Signer) error {
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

	attestors := alwaysRunAttestors
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

	for _, attestor := range attestors {
		setters, ok := ro.AttestorOptSetters[attestor.Name()]
		if !ok {
			continue
		}

		attestor, err := registry.SetOptions(attestor, setters...)
		if err != nil {
			return fmt.Errorf("failed to set attestor option for %v: %w", attestor.Type(), err)
		}
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

	results, err := workflow.RunWithExports(
		ro.StepName,
		workflow.RunWithSigners(signers...),
		workflow.RunWithAttestors(attestors),
		workflow.RunWithAttestationOpts(attestationOpts...),
		workflow.RunWithTimestampers(timestampers...),
	)
	if err != nil {
		return err
	}

	for _, result := range results {
		signedBytes, err := json.Marshal(&result.SignedEnvelope)
		if err != nil {
			return fmt.Errorf("failed to marshal envelope: %w", err)
		}

		outfile := ro.OutFilePath
		if result.AttestorName != "" {
			outfile += "-" + result.AttestorName + ".json"
		}

		out, err := loadOutfile(outfile)
		if err != nil {
			return fmt.Errorf("failed to open out file: %w", err)
		}

		defer func() {
			if err := out.Close(); err != nil {
				log.Errorf("failed to write result to disk: %v", err)
			}
		}()

		if _, err := out.Write(signedBytes); err != nil {
			return fmt.Errorf("failed to write envelope to out file: %w", err)
		}
	}
	return nil
}
