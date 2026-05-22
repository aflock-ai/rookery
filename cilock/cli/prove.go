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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/spf13/cobra"
)

// proveOptions carries the flags for `cilock prove`.
type proveOptions struct {
	SignerOptions            options.SignerOptions
	KMSSignerProviderOptions options.KMSSignerProviderOptions

	TreeSidecar      string
	Files            []string
	OutFilePath      string
	TimestampServers []string
}

// ProveCmd builds the `cilock prove` subcommand. It reads a v0.3
// product/material tree sidecar, reconstructs the Merkle tree, and
// emits one signed inclusion-proof DSSE envelope per requested file.
//
// The sidecar itself is produced by `cilock run` (see runWriteSidecars)
// and is NOT signed: the integrity check that matters is that the
// reconstructed Merkle root matches the root claimed in the sidecar,
// AND that root is bound (via the signed product/material attestation)
// to the build run. If a sidecar has been tampered with, reconstruction
// refuses to emit a proof rather than silently producing one that
// would never verify.
func ProveCmd() *cobra.Command {
	o := proveOptions{
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:               "prove",
		Short:             "Emit signed inclusion proofs for files committed to a v0.3 product/material tree",
		Long:              "Reconstructs the Merkle tree carried in --tree-sidecar and emits one signed inclusion-proof DSSE envelope per --file. Each envelope binds (path, fileDigest, treeRoot, leafIndex, auditPath) and is independently verifiable against the matching product/material attestation's root.",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			signers, err := loadSigners(cmd.Context(), o.SignerOptions, o.KMSSignerProviderOptions, providersFromFlags("signer", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signer: %w", err)
			}
			return runProve(cmd.Context(), o, signers...)
		},
	}

	o.SignerOptions.AddFlags(cmd)
	o.KMSSignerProviderOptions.AddFlags(cmd)
	cmd.Flags().StringVar(&o.TreeSidecar, "tree-sidecar", "", "Path to the product/material tree sidecar JSON written by `cilock run` (required)")
	cmd.Flags().StringArrayVar(&o.Files, "file", nil, "Leaf path within the sidecar tree to emit a proof for. Repeat to emit multiple proofs in one call (required).")
	cmd.Flags().StringVarP(&o.OutFilePath, "outfile", "o", "", "Output path for the signed inclusion-proof envelope (required). If multiple --file values are passed, each envelope is written to `<outfile>-<sanitised-path>.json`.")
	cmd.Flags().StringSliceVar(&o.TimestampServers, "timestamp-servers", []string{}, "Timestamp Authority Servers to use when signing the envelope")

	return cmd
}

// runProve is the body of the prove subcommand. Extracted so it can be
// unit-tested without going through cobra.
func runProve(_ context.Context, o proveOptions, signers ...cryptoutil.Signer) error {
	if o.TreeSidecar == "" {
		return errors.New("--tree-sidecar is required")
	}
	if len(o.Files) == 0 {
		return errors.New("at least one --file is required")
	}
	if o.OutFilePath == "" {
		return errors.New("--outfile is required")
	}
	if len(signers) == 0 {
		return errors.New("no signers found")
	}
	if len(signers) > 1 {
		return errors.New("only one signer is supported")
	}

	timestampers := make([]timestamp.Timestamper, 0, len(o.TimestampServers))
	for _, url := range o.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	sidecar, err := inclusionproof.ReadSidecarFile(o.TreeSidecar)
	if err != nil {
		return fmt.Errorf("read sidecar: %w", err)
	}

	tree, leafIndex, err := sidecar.Reconstruct()
	if err != nil {
		// Sentinel-match so the caller sees the diagnostic the design
		// spec mandates rather than just the wrapped err.
		if errors.Is(err, inclusionproof.ErrSidecarRootMismatch) {
			return fmt.Errorf("sidecar root mismatch: %w", err)
		}
		return fmt.Errorf("reconstruct sidecar tree: %w", err)
	}
	rootBytes, err := hex.DecodeString(sidecar.MerkleRoot)
	if err != nil {
		return fmt.Errorf("decode sidecar root: %w", err)
	}

	multi := len(o.Files) > 1
	signOpts := []dsse.SignOption{
		dsse.SignWithSigners(signers[0]),
		dsse.SignWithTimestampers(timestampers...),
	}

	for _, file := range o.Files {
		if err := emitOneProof(&sidecar, tree, leafIndex, rootBytes, file, o.OutFilePath, multi, signOpts); err != nil {
			return err
		}
	}

	return nil
}

// emitOneProof builds, self-verifies, signs, and writes a single
// inclusion-proof envelope for the given leaf. Extracted from runProve
// to keep that function's cognitive complexity below the project's
// linter budget.
func emitOneProof(sidecar *inclusionproof.Sidecar, tree merkleTreeIface, leafIndex map[string]uint64, rootBytes []byte, file, baseOut string, multi bool, signOpts []dsse.SignOption) error {
	idx, ok := leafIndex[file]
	if !ok {
		return fmt.Errorf("file %q is not a leaf of the supplied sidecar (sidecar source=%s, leaves=%d)", file, sidecar.Source, sidecar.TreeSize)
	}

	auditPath, err := tree.InclusionProof(idx)
	if err != nil {
		return fmt.Errorf("build inclusion proof for %q: %w", file, err)
	}

	hexAudit := make([]string, len(auditPath))
	for i, b := range auditPath {
		hexAudit[i] = hex.EncodeToString(b)
	}

	att := inclusionproof.New()
	att.TreeRoot = sidecar.MerkleRoot
	att.LeafIndex = idx
	att.LeafPath = sidecar.Leaves[idx].Path
	att.FileDigest = sidecar.Leaves[idx].FileDigest
	att.AuditPath = hexAudit

	// Belt-and-braces self-verification before signing: if the proof
	// won't verify with the freshly-built tree, refuse to sign. This
	// makes a corrupted leaf set or a bug in the merkle wrapper fail
	// loudly here, where the operator is still watching, rather than
	// at verification time on some downstream consumer.
	if err := att.Verify(sidecar.TreeSize, rootBytes); err != nil {
		return fmt.Errorf("self-check on freshly-built proof for %q failed: %w", file, err)
	}

	env, err := signProvePredicate(att, signOpts...)
	if err != nil {
		return fmt.Errorf("sign envelope for %q: %w", file, err)
	}

	outPath := baseOut
	if multi {
		outPath = appendSanitisedPath(baseOut, file)
	}
	if err := writeEnvelope(outPath, env); err != nil {
		return fmt.Errorf("write envelope for %q: %w", file, err)
	}
	log.Infof("Wrote inclusion proof: file=%s outfile=%s leafIndex=%d", file, outPath, idx)
	return nil
}

// merkleTreeIface is the narrow surface emitOneProof needs from a
// merkle tree. Exists as a method-set declaration so the function
// signature doesn't leak the upstream package type.
type merkleTreeIface interface {
	InclusionProof(index uint64) ([][]byte, error)
}

// signProvePredicate marshals the inclusion-proof predicate into an
// in-toto Statement and produces a DSSE-signed envelope. Inlined here
// because workflow.createAndSignEnvelope is unexported and growing it
// to support the prove path for a single caller would muddy the
// workflow package's contract.
func signProvePredicate(att *inclusionproof.Attestor, opts ...dsse.SignOption) (dsse.Envelope, error) {
	subjects := att.Subjects()
	predicateBytes, err := json.Marshal(att)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("marshal predicate: %w", err)
	}
	stmt, err := intoto.NewStatement(att.Type(), predicateBytes, subjects)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("build in-toto statement: %w", err)
	}
	stmtJSON, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("marshal statement: %w", err)
	}
	return dsse.Sign(intoto.PayloadType, bytes.NewReader(stmtJSON), opts...)
}

// writeEnvelope writes a signed envelope to the given path. The file
// is created or truncated; permissions follow the same convention as
// loadOutfile elsewhere in this package.
func writeEnvelope(path string, env dsse.Envelope) error {
	out, err := loadOutfile(path)
	if err != nil {
		return err
	}
	defer closeOutfile(out)
	data, err := json.Marshal(&env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("write envelope: %w", err)
	}
	return nil
}

// appendSanitisedPath rewrites a leaf path into a filesystem-safe
// fragment and appends it to the base outfile. We don't want a leaf
// path like "dist/binary" to create a `dist/` subdirectory under the
// user's chosen output location.
func appendSanitisedPath(base, leaf string) string {
	safe := strings.ReplaceAll(leaf, "/", "-")
	safe = strings.ReplaceAll(safe, "\\", "-")
	if strings.HasSuffix(base, ".json") {
		return strings.TrimSuffix(base, ".json") + "-" + safe + ".json"
	}
	return base + "-" + safe + ".json"
}

// writeSidecarsForRun is the post-run hook used by `cilock run` to
// emit the product/material tree sidecars adjacent to the signed
// attestation file. It is called from runRun once the workflow result
// is in hand.
//
// Path convention: for an `--outfile` of `attestation.json`, the
// product sidecar lands at `attestation.product.tree.json` and the
// material sidecar at `attestation.material.tree.json`. If the user
// passes an outfile without a `.json` extension, the same suffix is
// appended verbatim. If outfile is empty (stdout), no sidecars are
// written — a sidecar's path is derived from the outfile.
func writeSidecarsForRun(outfile string, products map[string]string, materials map[string]string) error {
	if outfile == "" {
		// stdout output: no on-disk anchor to derive sidecar paths from.
		return nil
	}
	if len(products) > 0 {
		side, err := inclusionproof.BuildSidecar("product", products)
		if err != nil {
			return fmt.Errorf("build product sidecar: %w", err)
		}
		if err := inclusionproof.WriteSidecarFile(sidecarPath(outfile, "product"), side); err != nil {
			return fmt.Errorf("write product sidecar: %w", err)
		}
	}
	if len(materials) > 0 {
		side, err := inclusionproof.BuildSidecar("material", materials)
		if err != nil {
			return fmt.Errorf("build material sidecar: %w", err)
		}
		if err := inclusionproof.WriteSidecarFile(sidecarPath(outfile, "material"), side); err != nil {
			return fmt.Errorf("write material sidecar: %w", err)
		}
	}
	return nil
}

// sidecarPath returns the conventional sidecar location for an outfile.
// "out/x.json" + "product" -> "out/x.product.tree.json"
// "out/x"      + "product" -> "out/x.product.tree.json"
func sidecarPath(outfile, kind string) string {
	if strings.HasSuffix(outfile, ".json") {
		return strings.TrimSuffix(outfile, ".json") + "." + kind + ".tree.json"
	}
	return outfile + "." + kind + ".tree.json"
}
