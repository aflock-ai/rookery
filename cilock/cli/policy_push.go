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
	"net/http"
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

// dsseUploader is the slice of the Archivista client `push` needs. It exists so
// the upload step is mockable in tests without standing up a real client.
type dsseUploader interface {
	Store(ctx context.Context, env dsse.Envelope) (string, error)
}

// newArchivistaUploader is a seam over the real Archivista client construction
// so tests can substitute an in-memory uploader. It builds the same client
// `cilock run --enable-archivista` uses (Bearer auth via WithHeaders).
var newArchivistaUploader = func(archivistaURL, bearer string) dsseUploader {
	headers := http.Header{}
	if bearer != "" {
		headers.Set("Authorization", "Bearer "+bearer)
	}
	return archivista.New(archivistaURL, archivista.WithHeaders(headers))
}

// PolicyPushCmd is `cilock policy push`. It uploads an already-signed witness
// policy DSSE to the platform's Archivista, ensures a PolicyDefinition exists
// (create-if-missing), and creates a PolicyRelease pinning that definition to
// the uploaded policy under a tag.
//
// Flow: sign (`cilock sign`) → push (this) → bind (`cilock policy bind`).
func PolicyPushCmd() *cobra.Command {
	var (
		file          string
		definition    string
		tag           string
		description   string
		platformURL   string
		archivistaURL string
	)

	cmd := &cobra.Command{
		Use:   "push",
		Short: "Upload a signed policy DSSE to the platform and create a release",
		Long: "Publish an author-signed witness policy to the TestifySec platform.\n\n" +
			"push uploads the signed policy DSSE to the platform's Archivista (reusing\n" +
			"the same upload path as `cilock run --enable-archivista`), ensures the named\n" +
			"PolicyDefinition exists (creating it if absent), then creates a PolicyRelease\n" +
			"that pins the definition to the uploaded policy under --tag.\n\n" +
			"The policy file must already be DSSE-signed — produce it with `cilock sign`\n" +
			"against the platform's keyless Fulcio (a trusted root, so no trust-source\n" +
			"registration is needed).\n\n" +
			"Auth: the DSSE upload needs attestation:upload; createPolicyRelease needs\n" +
			"policy:write. If the platform rejects the call for a missing scope, run\n" +
			"`cilock login` again to pick up policy:write.",
		Example: "  # Publish a release tagged v1.0.0 (sign first: cilock sign -f policy.json -o policy.signed.json)\n" +
			"  cilock policy push --file policy.signed.json --definition supply-chain --tag v1.0.0\n\n" +
			"  # Publish to a specific platform\n" +
			"  cilock policy push -f policy.signed.json -d supply-chain -t v1.0.0 --platform-url https://platform.testifysec.com",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyPush(cmd, policyPushOpts{
				file:          file,
				definition:    definition,
				tag:           tag,
				description:   description,
				platformURL:   platformURL,
				archivistaURL: archivistaURL,
			})
		},
	}

	f := cmd.Flags()
	f.StringVarP(&file, "file", "f", "", "Path to the DSSE-signed policy (from cilock sign) (required)")
	f.StringVarP(&definition, "definition", "d", "", "PolicyDefinition name; created if it doesn't exist (required)")
	f.StringVarP(&tag, "tag", "t", "", "Release tag (e.g. a semver or string) (required)")
	f.StringVar(&description, "description", "", "Description used only when creating a new PolicyDefinition")
	f.StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default: the logged-in platform)")
	f.StringVar(&archivistaURL, "archivista-server", "", "Archivista server URL (default: ${platform-url}/archivista)")

	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("definition")
	_ = cmd.MarkFlagRequired("tag")
	return cmd
}

// policyPushOpts groups the resolved flag values for `policy push`.
type policyPushOpts struct {
	file          string
	definition    string
	tag           string
	description   string
	platformURL   string
	archivistaURL string
}

// runPolicyPush executes the push flow: load the signed DSSE, upload it to
// Archivista, resolve the gitoid to the platform Dsse id, ensure the definition,
// then create the release.
func runPolicyPush(cmd *cobra.Command, o policyPushOpts) error {
	out := cmd.OutOrStdout()
	ctx := cmdContext(cmd)

	sess, err := resolvePolicySession(o.platformURL)
	if err != nil {
		return err
	}

	// Load and parse the signed policy DSSE. `cilock sign -o` writes a
	// JSON-encoded dsse.Envelope, so this round-trips that exact format.
	env, err := loadSignedEnvelope(o.file)
	if err != nil {
		return err
	}

	// Resolve the Archivista URL: explicit flag, else discovery, else derived.
	archivistaURL := o.archivistaURL
	if archivistaURL == "" {
		archivistaURL = resolveArchivistaURL(sess.platformURL)
	}

	// (a) Upload the signed DSSE to Archivista with the credential's bearer
	// (attestation:upload). This is the same path `cilock run` uses.
	_, _ = fmt.Fprintf(out, "Uploading signed policy to %s ...\n", archivistaURL)
	uploader := newArchivistaUploader(archivistaURL, sess.cred.Token)
	gitoid, err := uploader.Store(ctx, env)
	if err != nil {
		return fmt.Errorf("upload policy DSSE to archivista: %w", err)
	}
	_, _ = fmt.Fprintf(out, "  policy DSSE gitoid: %s\n", gitoid)

	pc := sess.policyClient()

	// Resolve the uploaded gitoid to the platform Dsse record id. The gitoid is
	// NOT the Dsse edge id createPolicyRelease wants. Archivista ingest is
	// usually synchronous, but retry briefly to absorb any indexing lag.
	dsseID, err := resolveDsseIDWithRetry(ctx, pc, gitoid)
	if err != nil {
		return err
	}

	// (b) Ensure the PolicyDefinition exists (query first, create if absent).
	def, err := pc.ResolvePolicyDefinitionByName(ctx, o.definition)
	if err != nil {
		return err
	}
	if def == nil {
		_, _ = fmt.Fprintf(out, "Creating policy definition %q ...\n", o.definition)
		def, err = pc.CreatePolicyDefinition(ctx, sess.cred.TenantID, o.definition, o.description)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "  created definition id: %s\n", def.ID)
	} else {
		_, _ = fmt.Fprintf(out, "Using existing policy definition %q (id %s)\n", def.Name, def.ID)
	}

	// (c) Create the PolicyRelease pinning the definition to the uploaded DSSE.
	rel, err := pc.CreatePolicyRelease(ctx, sess.cred.TenantID, def.ID, dsseID, o.tag)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "\n✓ published %q release %q\n", def.Name, rel.Tag)
	_, _ = fmt.Fprintf(out, "  definition: %s\n  release:    %s\n  dsse:       %s (gitoid %s)\n",
		def.ID, rel.ID, dsseID, gitoid)
	_, _ = fmt.Fprintf(out, "\nBind it to a product with:\n"+
		"  cilock policy bind --definition %q --tag %q --product <id-or-name>\n",
		def.Name, rel.Tag)
	return nil
}

// loadSignedEnvelope reads a DSSE-signed policy file and parses it into a
// dsse.Envelope. The file must be the JSON envelope `cilock sign` writes; a
// raw (unsigned) policy with no signatures is rejected early so the user gets a
// clear "sign it first" message instead of an opaque server-side trust failure.
func loadSignedEnvelope(path string) (dsse.Envelope, error) {
	if path == "" {
		return dsse.Envelope{}, fmt.Errorf("--file is required (a DSSE-signed policy from `cilock sign`)")
	}
	data, err := os.ReadFile(path) //nolint:gosec // user-supplied policy path
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	var env dsse.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return dsse.Envelope{}, fmt.Errorf("parse %q as a DSSE envelope (did you `cilock sign` it?): %w", path, err)
	}
	if len(env.Payload) == 0 {
		return dsse.Envelope{}, fmt.Errorf("policy file %q has an empty DSSE payload", path)
	}
	if len(env.Signatures) == 0 {
		return dsse.Envelope{}, fmt.Errorf("policy file %q is not signed (no DSSE signatures) — sign it first: cilock sign -f <policy> -o <policy>.signed.json", path)
	}
	return env, nil
}

// dsseResolveAttempts / dsseResolveDelay bound the gitoid→Dsse-id resolution
// retry. Vars (not consts) so tests can shrink them.
var (
	dsseResolveAttempts = 5
	dsseResolveDelay    = 500 * time.Millisecond
)

// resolveDsseIDWithRetry resolves the uploaded gitoid to the platform Dsse id,
// retrying a few times to absorb indexing lag after upload. A persistent miss is
// an error — without the Dsse id there is no release to create.
func resolveDsseIDWithRetry(ctx context.Context, pc *options.PolicyClient, gitoid string) (string, error) {
	var lastErr error
	for i := 0; i < dsseResolveAttempts; i++ {
		id, err := pc.ResolveDsseIDByGitoid(ctx, gitoid)
		if err != nil {
			lastErr = err
		} else if id != "" {
			return id, nil
		}
		if i < dsseResolveAttempts-1 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(dsseResolveDelay):
			}
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("uploaded policy (gitoid %s) but could not resolve it to a platform DSSE record: %w", gitoid, lastErr)
	}
	return "", fmt.Errorf("uploaded policy (gitoid %s) but the platform has not indexed it yet — retry `cilock policy push` shortly", gitoid)
}
