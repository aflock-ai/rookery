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
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/spf13/cobra"
)

// KeyidCmd is `cilock keyid` — utility for inspecting the canonical
// keyid that cilock derives from a public or private key. The same id
// is what `cilock verify` expects in a witness policy's
// functionaries[].publickeyid field. Without this subcommand users
// learn the convention by failing a verify and reading the error
// message ("expected X but got Y"); explicit help is cheaper.
//
// Algorithm: hex(sha256(PEM(public-key))). PEM here is the PKIX
// SubjectPublicKeyInfo PEM produced by Go's
// x509.MarshalPKIXPublicKey → pem.Encode. The hash is fixed at SHA-256
// for ed25519 (matching attestation/cryptoutil/ed25519.go); for RSA
// and ECDSA the per-signer default applies — both currently SHA-256
// in stock cilock.
func KeyidCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "keyid",
		Short:             "Inspect the canonical keyid derived from a public or private key",
		Long:              "keyid prints the deterministic identifier cilock uses to refer to a signing key in attestations and policies. Use `cilock keyid show <key-file>` to find what to put in your policy's functionaries[].publickeyid field.",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
	}
	cmd.AddCommand(keyidShowCmd())
	return cmd
}

func keyidShowCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show <key-file>...",
		Short: "Print the keyid(s) for one or more key files",
		Long: `show reads each file as either a PEM public key (PKIX SubjectPublicKeyInfo)
or a PEM private key (PKCS#8 / PKCS#1 / SEC1). For private keys the public
half is extracted before hashing. Output is one line per input:

    <keyid>  <path>

matching sha256sum's shape so it pipes cleanly into other tools. Use
--format=json for jq consumption.

Examples:
  cilock keyid show signer.pub
  cilock keyid show signer.key signer.pub other.pem
  cilock keyid show --format=json signer.key | jq .`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, err := parseKeyidFormat(format)
			if err != nil {
				return err
			}
			results, anyError := collectKeyids(args)
			if err := renderKeyids(cmd.OutOrStdout(), cmd.ErrOrStderr(), results, asJSON); err != nil {
				return err
			}
			if anyError {
				return fmt.Errorf("one or more keys failed to load")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "Output format: empty/text = sha256sum-style lines, 'json' = JSON array")
	return cmd
}

// keyidEntry is one row of the show subcommand's output. Exported as
// a struct so the JSON marshaller and the test code can share the
// shape.
type keyidEntry struct {
	Path  string `json:"path"`
	KeyID string `json:"keyid,omitempty"`
	Error string `json:"error,omitempty"`
}

// parseKeyidFormat normalizes the --format flag into a boolean.
// Empty/"text"/"lines" mean sha256sum-style; "json" means JSON array.
// Anything else is a user error.
func parseKeyidFormat(format string) (bool, error) {
	switch format {
	case "", "text", "lines":
		return false, nil
	case "json":
		return true, nil
	default:
		return false, fmt.Errorf("unknown --format %q (want 'json' or 'text')", format)
	}
}

// collectKeyids resolves a list of key-file paths into keyidEntry
// records, capturing both success and failure cases. anyError is true
// when at least one entry failed — used by the caller to set a
// non-zero exit code.
func collectKeyids(paths []string) (results []keyidEntry, anyError bool) {
	results = make([]keyidEntry, 0, len(paths))
	for _, path := range paths {
		kid, err := keyidForFile(path)
		e := keyidEntry{Path: path}
		if err != nil {
			e.Error = err.Error()
			anyError = true
		} else {
			e.KeyID = kid
		}
		results = append(results, e)
	}
	return results, anyError
}

// renderKeyids writes the result set to stdout / stderr in the chosen
// format. Errors during the actual write (rare) propagate up; per-key
// load errors are surfaced via the entry's Error field and don't stop
// rendering of the rest.
func renderKeyids(out, errOut io.Writer, results []keyidEntry, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	for _, r := range results {
		if r.Error != "" {
			_, _ = fmt.Fprintf(errOut, "ERROR  %s  %s\n", r.Path, r.Error)
			continue
		}
		_, _ = fmt.Fprintf(out, "%s  %s\n", r.KeyID, r.Path)
	}
	return nil
}

// keyidForFile loads a key file (public or private) and returns the
// canonical keyid. Tries the private-key reader first; on any error
// falls back to the public-key reader. This mirrors how a user would
// expect it to work: "I have this PEM, what's its keyid?" without
// having to know which kind it is.
func keyidForFile(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // user-provided path is the whole point
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	// Try as private key first.
	if signer, sErr := cryptoutil.NewSignerFromReader(byteReader(raw)); sErr == nil {
		kid, kErr := signer.KeyID()
		if kErr == nil {
			return kid, nil
		}
		return "", fmt.Errorf("derive keyid from private key %s: %w", path, kErr)
	}

	// Fall back to public key.
	verifier, vErr := cryptoutil.NewVerifierFromReader(byteReader(raw))
	if vErr != nil {
		return "", fmt.Errorf("file %s is not a recognized public or private PEM key (private: %w; public: %w)",
			path, errParsePriv, vErr)
	}
	kid, kErr := verifier.KeyID()
	if kErr != nil {
		return "", fmt.Errorf("derive keyid from public key %s: %w", path, kErr)
	}
	return kid, nil
}

// errParsePriv is a sentinel used inside keyidForFile's wrapped error
// for the private-key parse leg. Keeping it as a package var keeps the
// error message structure stable for tests.
var errParsePriv = errors.New("not a private key")

// byteReader is a tiny io.Reader factory; we need a fresh reader for
// each parse attempt because Signer/Verifier readers consume the input.
func byteReader(b []byte) io.Reader {
	return &readerOnce{b: b}
}

type readerOnce struct {
	b []byte
	o int
}

func (r *readerOnce) Read(p []byte) (int, error) {
	if r.o >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.o:])
	r.o += n
	return n, nil
}
