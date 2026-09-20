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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// gitoidHexPattern is the ONLY argument form `cilock fetch` accepts: the
// lowercase hex string gitoid.GitOID.String() renders and the one Archivista
// keys its /download/{gitoid} route on. Nothing here normalizes a near-miss —
// a gitoid is a content address, and silently rewriting one turns "you asked
// for the wrong object" into "you got an object you did not ask for".
var gitoidHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// gitoidURIPattern recognizes the `gitoid:blob:sha256:<hex>` URI form (what
// GitOID.URI() renders, and what appears in omnitrail/subject fields) purely so
// the refusal can point at the part to pass. It is a DIAGNOSTIC, not an
// accepted input.
var gitoidURIPattern = regexp.MustCompile(`^gitoid:blob:sha256:([0-9a-f]{64})$`)

// fetchProjection selects which bytes of the fetched envelope are written.
type fetchProjection int

const (
	// fetchEnvelope writes the exact stored bytes. This is the only mode whose
	// output re-hashes to the gitoid.
	fetchEnvelope fetchProjection = iota
	// fetchStatement writes the base64-decoded DSSE payload.
	fetchStatement
	// fetchPredicate writes only the statement's predicate member.
	fetchPredicate
)

// suffix is the filename tail used under --outdir. It varies per projection so
// fetching the same gitoid three ways cannot silently overwrite itself.
func (p fetchProjection) suffix() string {
	switch p {
	case fetchStatement:
		return ".payload.json"
	case fetchPredicate:
		return ".predicate.json"
	case fetchEnvelope:
		return ".dsse.json"
	}
	return ".dsse.json"
}

type fetchOptions struct {
	Gitoids        []string
	PlatformURL    string
	ArchivistaURL  string
	ArchivistaHdrs []string
	Outfile        string
	Outdir         string
	Payload        bool
	Predicate      bool
	Force          bool
}

func (o fetchOptions) projection() fetchProjection {
	switch {
	case o.Payload:
		return fetchStatement
	case o.Predicate:
		return fetchPredicate
	default:
		return fetchEnvelope
	}
}

// FetchCmd is the `cilock fetch` command: download ANY attestation from
// Archivista by its gitoid.
func FetchCmd() *cobra.Command {
	o := fetchOptions{}
	cmd := &cobra.Command{
		Use:   "fetch <gitoid> [<gitoid>...]",
		Short: "Download an attestation from Archivista by its gitoid",
		Long: `Download an attestation from Archivista by its gitoid.

fetch is generic over attestation type: it downloads whatever DSSE envelope the
gitoid names and knows nothing about the predicate inside it.

By default it writes the EXACT stored bytes, so re-hashing the saved file
reproduces the gitoid it was fetched by. --payload writes the base64-decoded
DSSE payload (the in-toto statement); --predicate writes only that statement's
predicate member.

What this verifies, and what it does not:

  fetch verifies the CONTENT ADDRESS. The bytes it writes are re-hashed locally
  and must equal the gitoid you asked for, so a compromised or on-path
  Archivista cannot hand you different evidence under the name you requested.

  fetch DOES NOT VERIFY THE SIGNATURE, and it does not verify who signed. An
  envelope that downloads cleanly may be signed by anyone, or carry a signature
  that does not validate at all. ` + "`cilock verify`" + ` is what establishes signer
  trust — run it against a policy before you act on what you fetched.

  --payload and --predicate output is content lifted out of an envelope whose
  signature fetch did not check. It is untrusted until ` + "`cilock verify`" + ` says
  otherwise.`,
		Example: `  # Print an attestation's exact stored bytes (re-hashes to the gitoid)
  cilock fetch 4d0f2e6c9a1b83f5c7e2a0d4b6981f3e5c7a9b0d2e4f6183a5c7e9b0d2f4a618

  # Save it, refusing to clobber an existing file
  cilock fetch 4d0f2e6c9a1b83f5c7e2a0d4b6981f3e5c7a9b0d2e4f6183a5c7e9b0d2f4a618 -o evidence.json

  # Several at once, one file per gitoid
  cilock fetch --outdir ./evidence 4d0f2e6c9a1b83f5c7e2a0d4b6981f3e5c7a9b0d2e4f6183a5c7e9b0d2f4a618 7a1c3e5b9d0f2846ac5e7b9d1f3058a2c4e6b8d0f2143a5c7e9b0d2f4a61835c

  # Just the predicate, for a tool that only wants the payload's contents
  cilock fetch --predicate 4d0f2e6c9a1b83f5c7e2a0d4b6981f3e5c7a9b0d2e4f6183a5c7e9b0d2f4a618`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Gitoids = args
			// Validate BEFORE resolving the platform: a usage error must not
			// read the credential store or make a discovery request.
			if err := validateFetchOptions(o); err != nil {
				return err
			}
			// Platform resolution mirrors bundle create and
			// resolvePolicySession: explicit flag, else the logged-in
			// platform, else the compiled default — so the credential looked
			// up below belongs to the SAME platform the URL was derived from.
			if o.PlatformURL == "" {
				if active := auth.ActivePlatformURL(); active != "" {
					o.PlatformURL = active
				} else {
					o.PlatformURL = platformconfig.DefaultPlatformURL
				}
			}
			if o.ArchivistaURL == "" {
				o.ArchivistaURL = resolveArchivistaURL(o.PlatformURL)
			}
			return runFetch(cmdContext(cmd), o, cmd.OutOrStdout())
		},
	}

	f := cmd.Flags()
	f.StringVarP(&o.Outfile, flagOutfile, "o", "", "Path to write the fetched attestation (default: stdout); a single gitoid only")
	f.StringVar(&o.Outdir, "outdir", "", "Directory to write one file per gitoid into, named <gitoid>.dsse.json; required for more than one gitoid")
	f.BoolVar(&o.Payload, "payload", false, "Write the base64-decoded DSSE payload (the in-toto statement) instead of the envelope")
	f.BoolVar(&o.Predicate, "predicate", false, "Write only the statement's predicate member instead of the envelope")
	f.BoolVar(&o.Force, "force", false, "Overwrite the output if it already exists")
	f.StringVar(&o.PlatformURL, "platform-url", "", "TestifySec platform URL (default "+platformconfig.DefaultPlatformURL+")")
	f.StringVar(&o.ArchivistaURL, "archivista-url", "", "Archivista server URL (default: the platform's own Archivista)")
	f.StringArrayVar(&o.ArchivistaHdrs, "archivista-headers", nil, "Headers to send with each Archivista request (e.g. Authorization: Bearer ...)")

	cmd.MarkFlagsMutuallyExclusive("payload", "predicate")
	cmd.MarkFlagsMutuallyExclusive(flagOutfile, "outdir")
	return cmd
}

// validateFetchOptions rejects every usage error before a single byte moves,
// and names the flag that fixes it.
func validateFetchOptions(o fetchOptions) error {
	for _, g := range o.Gitoids {
		if err := validateGitoidArg(g); err != nil {
			return err
		}
	}
	if len(o.Gitoids) > 1 && o.Outdir == "" {
		return fmt.Errorf("%d gitoids were given but --outfile and stdout write a single attestation — pass --outdir <dir> to write one file per gitoid", len(o.Gitoids))
	}
	if o.Outdir != "" {
		info, err := os.Stat(o.Outdir)
		if err != nil {
			return fmt.Errorf("--outdir %q is not usable: %w", o.Outdir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("--outdir %q is not a directory", o.Outdir)
		}
	}
	return nil
}

// validateGitoidArg accepts exactly what gitoid.GitOID.String() renders and
// what Archivista's /download/{gitoid} route is keyed on, and nothing else.
func validateGitoidArg(arg string) error {
	if gitoidHexPattern.MatchString(arg) {
		return nil
	}
	msg := fmt.Sprintf("invalid gitoid %q: expected the 64-character lowercase hex sha256 gitoid that Archivista stores", arg)
	if m := gitoidURIPattern.FindStringSubmatch(arg); m != nil {
		return fmt.Errorf("%s\n\n  that is a gitoid URI — pass the hex part alone:\n    %s", msg, m[1])
	}
	return fmt.Errorf("%s", msg)
}

// runFetch downloads each gitoid, verifies its content address, and only then
// writes anything anywhere.
func runFetch(ctx context.Context, o fetchOptions, out io.Writer) error {
	headers, err := archivistaReadHeaders(o.ArchivistaHdrs, o.ArchivistaURL, o.PlatformURL)
	if err != nil {
		return err
	}
	client := archivista.New(o.ArchivistaURL, archivista.WithHeaders(headers))
	projection := o.projection()

	// Check every destination BEFORE the first request, so an accidental
	// clobber is refused without spending a download (mirrors policy draft).
	destinations := make([]string, 0, len(o.Gitoids))
	destFlag := "--outfile"
	if o.Outdir != "" {
		destFlag = "--outdir"
	}
	for _, gid := range o.Gitoids {
		switch {
		case o.Outdir != "":
			destinations = append(destinations, filepath.Join(o.Outdir, gid+projection.suffix()))
		case o.Outfile != "":
			destinations = append(destinations, o.Outfile)
		default:
			destinations = append(destinations, "")
		}
	}
	for _, path := range destinations {
		if path == "" {
			continue
		}
		if err := ensureWritableOutput(path, destFlag, o.Force); err != nil {
			return err
		}
	}

	for i, gid := range o.Gitoids {
		data, err := fetchProjectedBytes(ctx, client, gid, projection)
		if err != nil {
			return err
		}
		if path := destinations[i]; path != "" {
			if err := writeFetchedFile(path, data, o.Force); err != nil {
				return err
			}
			continue
		}
		if _, err := out.Write(data); err != nil {
			return fmt.Errorf("write attestation %s: %w", gid, err)
		}
	}
	return nil
}

// fetchProjectedBytes returns the bytes to write for one gitoid. Every error
// names the gitoid, because a multi-gitoid run's failure is meaningless
// without it.
func fetchProjectedBytes(ctx context.Context, client *archivista.Client, gid string, projection fetchProjection) ([]byte, error) {
	raw, err := client.DownloadRaw(ctx, gid)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", gid, err)
	}
	if projection == fetchEnvelope {
		// The stored bytes, untouched. Nothing is appended — a trailing
		// newline would change the content address.
		return raw, nil
	}

	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("fetch %s: decode envelope: %w", gid, err)
	}
	if len(env.Payload) == 0 {
		return nil, fmt.Errorf("fetch %s: the envelope has an empty payload", gid)
	}
	if projection == fetchStatement {
		// The DSSE payload verbatim: these are the bytes the signature is
		// computed over, so appending anything would break a later check.
		return env.Payload, nil
	}

	var stmt intoto.Statement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return nil, fmt.Errorf("fetch %s: --predicate needs an in-toto statement payload, which this is not: %w", gid, err)
	}
	if len(stmt.Predicate) == 0 {
		return nil, fmt.Errorf("fetch %s: the statement has no predicate member", gid)
	}
	return stmt.Predicate, nil
}

// writeFetchedFile puts data at path leaving no window in which a partial or
// empty file is visible, and refusing to clobber unless force.
//
// The two branches exist because the two promises need different primitives.
// Without --force the promise is "never replace what is there", which only
// O_EXCL can make atomically — a stat-then-write loses to anything that
// creates the path (or a symlink to elsewhere) in the gap. With --force the
// promise is "the old file survives a failed write", which O_TRUNC cannot
// make at all, so the bytes are staged beside the destination and renamed over
// it in one step.
func writeFetchedFile(path string, data []byte, force bool) error {
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path is --outfile/--outdir, a CLI-provided destination
		if os.IsExist(err) {
			return fmt.Errorf("output %q already exists — pass --force to overwrite it, or choose another path", path)
		}
		if err != nil {
			return fmt.Errorf("create %q: %w", path, err)
		}
		if err := writeAndCloseFetched(f, data); err != nil {
			// We created this file, so removing it cannot destroy anyone's
			// data — and leaving a truncated attestation behind would.
			_ = os.Remove(path)
			return fmt.Errorf("write %q: %w", path, err)
		}
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".cilock-fetch-*")
	if err != nil {
		return fmt.Errorf("stage output next to %q: %w", path, err)
	}
	tmpName := tmp.Name()
	if err := writeAndCloseFetched(tmp, data); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %q: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace %q: %w", path, err)
	}
	return nil
}

// writeAndCloseFetched writes data and closes f, reporting the close error when
// the write itself succeeded — a buffered write only fails at close.
func writeAndCloseFetched(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// archivistaReadHeaders builds the header set for an Archivista READ.
//
// A logged-in operator's session authorizes reads against the platform's own
// Archivista, the same way `cilock run` authorizes uploads
// (applyPlatformCredential): attach the bearer only when no Authorization
// header was passed explicitly AND the target shares the PLATFORM's origin —
// never leak the session JWT to a third-party --archivista-url.
//
// auth.Lookup, not LookupAny: Lookup is Resolve(url, ForBearer) — the
// token-obtaining path — while LookupAny is the status/display shim whose own
// doc forbids using it for a bearer. No session is not an error here; the
// server answers 401 and that message names `cilock login`, which is the
// accurate remediation.
func archivistaReadHeaders(rawHeaders []string, archivistaURL, platformURL string) (http.Header, error) {
	headers := http.Header{}
	for _, h := range rawHeaders {
		idx := strings.Index(h, ":")
		if idx <= 0 {
			return nil, fmt.Errorf("invalid --archivista-headers entry %q (expected Name: Value)", h)
		}
		name := strings.TrimSpace(h[:idx])
		value := strings.TrimSpace(h[idx+1:])
		headers.Add(name, value)
	}

	if headers.Get("Authorization") == "" && sameOriginDoctor(archivistaURL, platformconfig.Derive(platformURL).Archivista) {
		if cred, err := auth.Lookup(platformURL); err == nil && cred != nil && cred.Token != "" {
			headers.Set("Authorization", "Bearer "+cred.Token)
		}
	}
	return headers, nil
}
