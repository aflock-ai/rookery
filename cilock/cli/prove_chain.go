// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation/chain"
	"github.com/aflock-ai/rookery/attestation/dsse"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/spf13/cobra"
)

// ProveChainCmd builds the `cilock prove-chain` subcommand. It reads
// an upstream step's signed DSSE envelope + its leaf sidecar, plus a
// list of materials the downstream step claims to have consumed, and
// emits an unsigned `rookery.chain-proof.sidecar/v0.1` document with
// per-material RFC 6962 inclusion proofs against the upstream tree.
//
// The chain sidecar is NOT signed directly. Its integrity comes from
// the cryptographic chain:
//
//  1. SourceStep.EnvelopeDigest references a specific signed upstream
//     envelope (closes cross-step proof replay).
//  2. Each MaterialProof verifies against SourceStep.MerkleRoot,
//     which itself is bound to the signed upstream predicate.
//
// A verifier with the upstream signed envelope + the chain sidecar
// can confirm that every claimed material was provably a product of
// the upstream step, without seeing the upstream's full leaf set.
func ProveChainCmd() *cobra.Command {
	o := proveChainOptions{}

	cmd := &cobra.Command{
		Use:               "prove-chain",
		Short:             "Build a multi-step chain-of-custody sidecar binding consumed materials to an upstream step's signed Merkle root",
		Long:              "Reads an upstream step's signed DSSE envelope and its v0.3 leaf sidecar, then for each --consumed (path,digest) pair generates an RFC 6962 inclusion proof against the upstream tree. The output is an unsigned rookery.chain-proof.sidecar/v0.1 document that a policy verifier can pair with the signed upstream attestation to confirm provenance.",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProveChain(cmd.Context(), o)
		},
	}

	cmd.Flags().StringVar(&o.SourceEnvelope, "source-envelope", "", "Path to the signed DSSE envelope of the upstream step (required). The sha256 of its payload becomes the chain sidecar's envelopeDigest binding.")
	cmd.Flags().StringVar(&o.SourceSidecar, "source-sidecar", "", "Path to the upstream step's v0.3 leaf sidecar (the JSON written by `cilock run` or sourced from Archivista) (required)")
	cmd.Flags().StringVar(&o.SourceStepName, "source-step", "source", "Name of the upstream step as declared in the policy (default: 'source')")
	cmd.Flags().StringVar(&o.Domain, "domain", "", "Leaf-hash domain tag used when the upstream tree was built (e.g. 'rookery-product/v0.3'); empty for legacy back-compat")
	cmd.Flags().StringArrayVar(&o.Consumed, "consumed", nil, "A consumed material in the form 'path=sha256hex'. Repeat per material. Each must appear in the upstream sidecar's leaf set; the command refuses to fabricate proofs for materials not in the upstream tree.")
	cmd.Flags().StringVarP(&o.OutPath, "outfile", "o", "", "Output path for the chain sidecar JSON (required)")

	return cmd
}

type proveChainOptions struct {
	SourceEnvelope string
	SourceSidecar  string
	SourceStepName string
	Domain         string
	Consumed       []string
	OutPath        string
}

func runProveChain(_ context.Context, o proveChainOptions) error {
	if o.SourceEnvelope == "" {
		return errors.New("--source-envelope is required")
	}
	if o.SourceSidecar == "" {
		return errors.New("--source-sidecar is required")
	}
	if o.OutPath == "" {
		return errors.New("--outfile is required")
	}
	if len(o.Consumed) == 0 {
		return errors.New("at least one --consumed material is required")
	}

	envDigest, err := envelopePayloadSHA256(o.SourceEnvelope)
	if err != nil {
		return fmt.Errorf("compute envelope digest: %w", err)
	}

	upstream, err := inclusionproof.ReadSidecarFile(o.SourceSidecar)
	if err != nil {
		return fmt.Errorf("read source sidecar: %w", err)
	}

	leaves := make([]chain.SidecarLeaf, 0, len(upstream.Leaves))
	for _, l := range upstream.Leaves {
		leaves = append(leaves, chain.SidecarLeaf{
			Path:       l.Path,
			FileDigest: l.FileDigest,
		})
	}

	consumed, err := parseConsumed(o.Consumed)
	if err != nil {
		return err
	}

	source := chain.SourceStepRef{
		StepName:       o.SourceStepName,
		EnvelopeDigest: envDigest,
		MerkleRoot:     upstream.MerkleRoot,
		TreeSize:       upstream.TreeSize,
		Domain:         o.Domain,
	}

	sidecar, err := chain.BuildChainSidecar(source, leaves, consumed)
	if err != nil {
		return fmt.Errorf("build chain sidecar: %w", err)
	}

	// Self-verify before writing. Catches drift in the BuildChainSidecar
	// implementation that would produce a sidecar a verifier would
	// reject. Fail closed at write time, not at verify time.
	if err := chain.VerifyChainSidecar(sidecar); err != nil {
		return fmt.Errorf("self-verify chain sidecar: %w", err)
	}

	return writeChainSidecarFile(o.OutPath, sidecar)
}

// parseConsumed decodes the --consumed flag's "path=sha256hex" pairs
// into chain.ConsumedMaterial structs. Refuses malformed entries.
func parseConsumed(in []string) ([]chain.ConsumedMaterial, error) {
	out := make([]chain.ConsumedMaterial, 0, len(in))
	for _, entry := range in {
		eq := -1
		for i, c := range entry {
			if c == '=' {
				eq = i
				break
			}
		}
		if eq <= 0 || eq == len(entry)-1 {
			return nil, fmt.Errorf("--consumed %q: expected 'path=sha256hex'", entry)
		}
		path := entry[:eq]
		digest := entry[eq+1:]
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("--consumed %q: digest must be hex: %w", entry, err)
		}
		out = append(out, chain.ConsumedMaterial{Path: path, FileDigest: digest})
	}
	return out, nil
}

// envelopePayloadSHA256 returns the lowercase-hex sha256 of the DSSE
// payload bytes inside a signed envelope file. Matches the envelope-
// digest binding the policy verifier derives at verify time.
func envelopePayloadSHA256(envelopePath string) (string, error) {
	f, err := os.Open(envelopePath) //nolint:gosec // operator-supplied path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	var env dsse.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("envelope is not valid DSSE JSON: %w", err)
	}
	sum := sha256.Sum256(env.Payload)
	return hex.EncodeToString(sum[:]), nil
}

// writeChainSidecarFile serialises the sidecar to JSON and writes it
// atomically (write to .tmp, rename). The pretty-printed format is
// stable across writes — different runs over the same logical inputs
// produce byte-identical output.
func writeChainSidecarFile(path string, s chain.ChainSidecar) error {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chain sidecar: %w", err)
	}
	body = append(body, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil { //nolint:gosec // operator-supplied path
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
