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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/vex"
	"github.com/aflock-ai/rookery/plugins/attestors/vex/openvex"
	"github.com/spf13/cobra"
)

// defaultVEXOutFile is where the authored document lands when the
// operator doesn't name a path. The `.openvex.json` suffix is what the
// vex attestor's detector already matches on.
const defaultVEXOutFile = "vex.openvex.json"

// vexAuthorOptions are the authoring-side flags. Everything else on this
// command — signer, keyless Fulcio, --outfile, Archivista upload — comes
// from the same options.RunOptions set `cilock attest` uses.
type vexAuthorOptions struct {
	Products        []string
	Vulns           []string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	Author          string
	AuthorRole      string
	OutFile         string

	// now is the clock the document timestamps come from. Injectable so
	// tests are hermetic; nil means time.Now.
	now func() time.Time
}

func (vo *vexAuthorOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&vo.Products, "product", nil,
		"Product this statement is about. Repeat for multiple. Accepts an OCI reference with a digest "+
			"('ghcr.io/org/img@sha256:<hex>'), a package URL ('pkg:golang/example.com/mod@v1.2.3'), or a bare "+
			"sha256 digest. Digests are canonicalized to bare lowercase hex so they join to the digests judge "+
			"records at ingest.")
	cmd.Flags().StringArrayVar(&vo.Vulns, "vuln", nil,
		"Vulnerability this statement is about (CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx). Repeat for multiple; "+
			"each becomes its own OpenVEX statement carrying every --product.")
	cmd.Flags().StringVar(&vo.Status, "status", "",
		"Exploitability status: not_affected, affected, fixed, or under_investigation.")
	cmd.Flags().StringVar(&vo.Justification, "justification", "",
		"Why the product is not affected. REQUIRED when --status=not_affected, rejected otherwise. One of: "+
			"component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, "+
			"vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist.")
	cmd.Flags().StringVar(&vo.ImpactStatement, "impact-statement", "",
		"Free-text elaboration on the justification. Optional, but this is where a human (or an agent) "+
			"explains the reasoning a reviewer will read.")
	cmd.Flags().StringVar(&vo.ActionStatement, "action-statement", "",
		"What is being done about it. REQUIRED when --status=affected — an 'affected' statement with no "+
			"remediation plan is a finding, not triage.")
	cmd.Flags().StringVar(&vo.Author, "author", "cilock",
		"Document author recorded in the OpenVEX metadata. The cryptographic identity is the signer; this "+
			"field is the human-readable attribution.")
	cmd.Flags().StringVar(&vo.AuthorRole, "author-role", "",
		"Optional role of the document author (OpenVEX 'role').")
	cmd.Flags().StringVar(&vo.OutFile, "vex-out", defaultVEXOutFile,
		"Where to write the OpenVEX document. The signed attestation bundle still goes to --outfile.")
}

// build validates the flags and renders the document. Everything that can
// reject the document happens here, before a signer is loaded or a byte
// is written.
func (vo *vexAuthorOptions) build() (*openvex.VEX, error) {
	return openvex.Build(openvex.DocSpec{
		Author:     vo.Author,
		AuthorRole: vo.AuthorRole,
		Tooling:    "cilock/" + Version,
		Now:        vo.now,
		Statements: []openvex.StatementSpec{{
			Vulns:           vo.Vulns,
			Products:        vo.Products,
			Status:          openvex.Status(vo.Status),
			Justification:   openvex.Justification(vo.Justification),
			ImpactStatement: vo.ImpactStatement,
			ActionStatement: vo.ActionStatement,
		}},
	})
}

// write renders the document to vo.OutFile and returns the ABSOLUTE path
// it landed on plus the exact bytes it wrote.
//
// Absolute is load-bearing, not tidiness: resolving here — once, against
// the process working directory that a relative --workingdir is itself
// relative to — leaves exactly one interpretation of the path, both for
// where the courtesy copy lands and for the stable name the attestor
// derives from it.
//
// The returned bytes are the SIGNING INPUT. The attestor gets these bytes
// directly (WithVEXBytes) and never re-reads the file, so nothing that
// happens to the file after this write — replacement, truncation, a
// malicious workspace process racing the signer — can change what gets
// signed. The on-disk copy is for the operator; the signature binds to
// what this process rendered.
func (vo *vexAuthorOptions) write(doc *openvex.VEX, workingDir string) (string, []byte, error) {
	raw, err := openvex.Marshal(doc)
	if err != nil {
		return "", nil, err
	}

	path := vo.OutFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(workingDir, path)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve VEX document path %q: %w", vo.OutFile, err)
	}

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", nil, fmt.Errorf("write VEX document: %w", err)
	}
	return path, raw, nil
}

// AttestVexCmd is `cilock attest vex` — author an OpenVEX document and
// attest it in one pass.
//
// It is a subcommand of `attest` rather than a verb of its own because
// authoring a VEX document IS recording an attestation without wrapping a
// command: the assessment already happened, and what's being captured is
// the triage decision, not a build. The nesting follows `cilock policy`.
//
// Before this existed, cilock could only CONSUME a VEX document — the vex
// attestor reads one out of the product set — so producing one meant
// vexctl or hand-written JSON, neither of which validates the spec rules
// that make a statement meaningful.
//
// The document is authored before the (no-op) wrapped command runs, which
// makes it a material rather than a product. The authored bytes are
// handed to the vex attestor in memory (WithVEXBytes); the --vex-out file
// is the operator's copy, never the signing input.
func AttestVexCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters:       make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}
	vo := &vexAuthorOptions{}

	cmd := &cobra.Command{
		Use:   "vex",
		Short: "Author a signed OpenVEX document from a triage decision",
		Long: `vex authors an OpenVEX document from the flags you pass, validates it
against the spec's own rules, writes it to disk, and attests it with the
same signer, timestamper, and Archivista destination every other cilock
command uses.

Validation is fail-closed. A statement that suppresses a finding has to
say why:

  --status=not_affected  requires --justification
  --status=affected      requires --action-statement

Unknown statuses, unknown justifications, and malformed vulnerability IDs
are rejected rather than recorded. A VEX document without a justification
is an opinion, not evidence.

Digests are canonicalized to bare lowercase hex, which is how judge stores
an image digest at ingest — so a statement authored here joins to the
image it is about.`,
		Example: `  # Triage a CVE as unreachable in a specific image, signed keyless
  cilock attest vex \
    --product ghcr.io/acme/api@sha256:2f3c50f223e2c4e30b100dbcbaa5ff5e2f4bffd09b57ff0a687e766e79a76d1f \
    --vuln CVE-2024-12345 \
    --status not_affected \
    --justification vulnerable_code_not_in_execute_path \
    --impact-statement "the vulnerable parser is never reached from the request path" \
    -s vex-triage -o vex.bundle.json

  # Accept a finding with a remediation plan, signed with a local key
  cilock attest vex \
    --product pkg:golang/github.com/example/mod@v1.2.3 \
    --vuln CVE-2024-99999 --vuln CVE-2024-11111 \
    --status affected \
    --action-statement "upgrade to v1.2.4 in the next release train" \
    -k cosign.key -s vex-triage -o vex.bundle.json`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return vo.run(cmd, &o)
		},
	}

	o.AddFlags(cmd)
	vo.addFlags(cmd)
	return cmd
}

// run authors the document, wires it to the vex attestor, and hands off
// to the same run pipeline `cilock attest` uses.
func (vo *vexAuthorOptions) run(cmd *cobra.Command, o *options.RunOptions) error {
	// Author and validate FIRST. A rejected document must not reach a
	// signer, a network, or the filesystem.
	doc, err := vo.build()
	if err != nil {
		return err
	}

	docPath, raw, err := vo.write(doc, o.WorkingDir)
	if err != nil {
		return err
	}

	// Hand the freshly authored BYTES to the vex attestor, not the path.
	// Re-reading docPath at attest time would open a TOCTOU window: any
	// process with write access to the workspace could swap the file
	// between this write and the attestor's read, and cilock would sign a
	// document the operator never authored. The setter runs after the
	// registry flag setters, so these bytes win even if someone also
	// passes --attestor-vex-file; the on-disk file at docPath remains the
	// operator's copy.
	o.AttestorOptSetters[vex.Name] = append(o.AttestorOptSetters[vex.Name], vexBytesSetter(raw, docPath))
	o.Attestations = appendAttestor(o.Attestations, vex.Name)

	o.ResolvePlatformDefaults(cmd)

	signerProviders := providersFromFlags("signer", cmd.Flags())
	signers, err := loadSigners(cmd.Context(), o.SignerOptions, o.KMSSignerProviderOptions, signerProviders)
	if err != nil {
		return fmt.Errorf("failed to load signers: %w", err)
	}

	userSetFlags := map[string]bool{
		flagAttestorProductIncludeGlob: cmd.Flags().Changed(flagAttestorProductIncludeGlob),
	}
	return runRun(cmd.Context(), *o, []string{noopCommand}, userSetFlags, signerProviders, signers...)
}

// appendAttestor adds name to the attestor set if it isn't already there.
func appendAttestor(names []string, name string) []string {
	for _, n := range names {
		if n == name {
			return names
		}
	}
	return append(names, name)
}

// vexBytesSetter is the AttestorOptSetters entry that pins the vex
// attestor to the authored bytes. Split out so the wiring is testable
// without driving the whole signing pipeline.
func vexBytesSetter(raw []byte, docPath string) func(attestation.Attestor) (attestation.Attestor, error) {
	return func(a attestation.Attestor) (attestation.Attestor, error) {
		vexAttestor, ok := a.(*vex.Attestor)
		if !ok {
			return a, fmt.Errorf("unexpected attestor type: %T is not a VEX attestor", a)
		}
		vex.WithVEXBytes(raw, docPath)(vexAttestor)
		return vexAttestor, nil
	}
}
