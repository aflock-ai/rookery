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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/slsa/l3"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

const sha256Alg = "sha256"

var sha256Subject = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// slsaLevelTrusts builds the dsse trust for each root the L3 policy names.
// Tests replace it to run against a test CA and a fake TSA.
var slsaLevelTrusts = buildSLSALevelTrusts

// runSLSALevelVerify is `cilock verify --slsa-level 3`: the built-in L3
// policy (attestation/slsa/l3) over the -a envelopes, for the artifact or
// --subjects named on the command line.
func runSLSALevelVerify(cmd *cobra.Command, vo options.VerifyOptions) error {
	if vo.SLSALevel != 3 {
		return fmt.Errorf("--slsa-level %d: only level 3 is supported (the built-in policy verifies SLSA Build L3)", vo.SLSALevel)
	}
	if vo.PolicyFilePath != "" {
		return fmt.Errorf("--slsa-level uses the built-in L3 policy; drop -p/--policy (or drop --slsa-level to verify your policy)")
	}
	if vo.ArtifactDirectoryPath != "" {
		return fmt.Errorf("--slsa-level verifies a file or sha256 subject, not a directory; name the artifact file or pass --subjects sha256:<hex>")
	}
	subjects, resource, err := slsaCallerSubjects(vo)
	if err != nil {
		return err
	}
	pol, err := slsaLevelPolicy(vo)
	if err != nil {
		return err
	}
	envs, inputs, err := loadSLSALevelEvidence(vo.AttestationFilePaths)
	if err != nil {
		return err
	}
	trusts, err := slsaLevelTrusts(&vo, pol.Roots)
	if err != nil {
		return err
	}

	r := l3.Verify(pol, trusts, envs, subjects)
	writeSLSALevelHuman(cmd.ErrOrStderr(), r, subjects)
	if strings.EqualFold(vo.OutputFormat, "json") {
		v := VerifyVerdict{Passed: r.ObservedLevel == 3, SLSALevel: r.ObservedLevel, SLSAFailures: r.Verdict.Failures}
		if v.Passed {
			v.MatchedSubject = subjects[0]
		}
		if err := writeVerifyVerdictJSON(os.Stdout, v); err != nil {
			return err
		}
	}
	if vo.VSAOutFilePath != "" {
		if err := writeSLSALevelVSA(cmd, vo, pol, r, resource, subjects, inputs); err != nil {
			return err
		}
	}
	return slsaLevelError(r)
}

// slsaLevelPolicy is the built-in L3 policy the --slsa-* flags name.
func slsaLevelPolicy(vo options.VerifyOptions) (l3.Policy, error) {
	if vo.SLSABuilderDigest == "" {
		return l3.Policy{}, fmt.Errorf("--slsa-level 3 needs --slsa-builder-digest: the commit SHA of %s your workflow pins with uses: ...provenance.yml@<sha>", l3.WorkflowPath)
	}
	if vo.SLSASourceRepo == "" {
		return l3.Policy{}, fmt.Errorf("--slsa-level 3 needs --slsa-source-repo <owner>/<name>: the repository the artifact must be built from")
	}
	roots := make([]l3.Root, 0, len(vo.SLSARoots))
	for _, r := range vo.SLSARoots {
		roots = append(roots, l3.Root(strings.TrimSpace(r)))
	}
	pol := l3.Policy{Roots: roots, Path: l3.WorkflowPath, SHA: vo.SLSABuilderDigest, Repo: vo.SLSASourceRepo}
	return pol, pol.Validate()
}

func slsaLevelError(r l3.Result) error {
	if r.ObservedLevel == 3 {
		return nil
	}
	reqs := make([]string, 0, len(r.Verdict.Failures))
	for _, f := range r.Verdict.Failures {
		reqs = append(reqs, string(f.Requirement))
	}
	return fmt.Errorf("SLSA Build L3 not verified: %s", strings.Join(reqs, ", "))
}

// loadSLSALevelEvidence reads each -a file once: the envelope, and the
// digest of the same bytes for the VSA's inputAttestations.
func loadSLSALevelEvidence(paths []string) ([]dsse.Envelope, []l3.VSADescriptor, error) {
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("--slsa-level 3 needs the evidence as files: pass the provenance envelope and the build collection(s) with --attestations/-a")
	}
	envs := make([]dsse.Envelope, 0, len(paths))
	inputs := make([]l3.VSADescriptor, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // G304: path is from the --attestations CLI flag
		if err != nil {
			return nil, nil, fmt.Errorf("read attestation %s: %w", p, err)
		}
		var env dsse.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, nil, fmt.Errorf("decode attestation %s: %w", p, err)
		}
		envs = append(envs, env)
		sum := sha256.Sum256(raw)
		inputs = append(inputs, l3.VSADescriptor{URI: filepath.Base(p), Digest: map[string]string{sha256Alg: hex.EncodeToString(sum[:])}})
	}
	return envs, inputs, nil
}

// slsaCallerSubjects returns the "sha256:<hex>" lookup keys the caller asked
// about (requirement 7): the positional/--artifactfile artifact's digest and
// each --subjects value, which must already be sha256:<64 hex>.
func slsaCallerSubjects(vo options.VerifyOptions) (subjects []string, resource string, err error) {
	if vo.ArtifactFilePath != "" {
		f, err := os.Open(vo.ArtifactFilePath)
		if err != nil {
			return nil, "", fmt.Errorf("open artifact: %w", err)
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil, "", fmt.Errorf("hash artifact: %w", err)
		}
		subjects = append(subjects, "sha256:"+hex.EncodeToString(h.Sum(nil)))
		resource = filepath.Base(vo.ArtifactFilePath)
	}
	for _, s := range vo.AdditionalSubjects {
		if !sha256Subject.MatchString(s) {
			return nil, "", fmt.Errorf("--slsa-level: subject %q must be sha256:<64 lowercase hex>", s)
		}
		subjects = append(subjects, s)
	}
	if len(subjects) == 0 {
		return nil, "", fmt.Errorf("--slsa-level: name the artifact to verify (cilock verify ./artifact) or pass --subjects sha256:<hex>")
	}
	if resource == "" {
		resource = subjects[0]
	}
	return subjects, resource, nil
}

// buildSLSALevelTrusts turns each root into dsse verification options. The
// platform root is the policy-signature trust (--policy-ca-roots, platform
// discovery, or this build's embedded platform roots); public Sigstore takes
// its own flags. Both require a timestamp authority: a Fulcio certificate
// lives ten minutes, so without a trusted signing time it cannot verify.
func buildSLSALevelTrusts(vo *options.VerifyOptions, roots []l3.Root) ([]l3.Trust, error) {
	trusts := make([]l3.Trust, 0, len(roots))
	for _, root := range roots {
		switch root {
		case l3.RootPlatform:
			emb, err := loadEmbeddedPolicyTrust(*vo)
			if err != nil {
				return nil, err
			}
			st, err := resolvePolicySignatureTrust(vo, emb, false)
			if err != nil {
				return nil, err
			}
			if len(st.roots) == 0 {
				return nil, fmt.Errorf("--slsa-roots platform: no platform Fulcio root; pass --policy-ca-roots (or log in so discovery supplies it)")
			}
			if len(st.timestampVerifiers) == 0 {
				return nil, fmt.Errorf("--slsa-roots platform: no timestamp authority; pass --policy-timestamp-servers")
			}
			trusts = append(trusts, l3.Trust{Root: root, Options: []dsse.VerificationOption{
				dsse.VerifyWithRoots(st.roots...), dsse.VerifyWithIntermediates(st.intermediates...),
				dsse.VerifyWithTimestampVerifiers(st.timestampVerifiers...),
			}})
		case l3.RootPublicSigstore:
			t, err := publicSigstoreTrust(vo)
			if err != nil {
				return nil, err
			}
			trusts = append(trusts, t)
		default:
			return nil, fmt.Errorf("--slsa-roots: unknown root %q (want platform or public-sigstore)", root)
		}
	}
	return trusts, nil
}

// publicSigstoreTrust reads the public Sigstore Fulcio chain and TSA
// certificates named by the --slsa-public-sigstore-* flags.
func publicSigstoreTrust(vo *options.VerifyOptions) (l3.Trust, error) {
	if len(vo.SLSAPublicSigstoreCARootPaths) == 0 {
		return l3.Trust{}, fmt.Errorf("--slsa-roots public-sigstore needs --slsa-public-sigstore-ca-roots")
	}
	if len(vo.SLSAPublicSigstoreTimestampServers) == 0 {
		return l3.Trust{}, fmt.Errorf("--slsa-roots public-sigstore needs --slsa-public-sigstore-timestamp-servers")
	}
	var rootCerts, intermediates []*x509.Certificate
	for _, p := range vo.SLSAPublicSigstoreCARootPaths {
		data, err := os.ReadFile(p) //nolint:gosec // G304: path is from a CLI flag
		if err != nil {
			return l3.Trust{}, fmt.Errorf("read public Sigstore CA %s: %w", p, err)
		}
		r, i, err := splitPEMCertsBySelfSigned(data)
		if err != nil {
			return l3.Trust{}, fmt.Errorf("parse public Sigstore CA %s: %w", p, err)
		}
		rootCerts, intermediates = append(rootCerts, r...), append(intermediates, i...)
	}
	if len(rootCerts) == 0 {
		return l3.Trust{}, fmt.Errorf("--slsa-public-sigstore-ca-roots holds no self-signed root")
	}
	tsas := make([]timestamp.TimestampVerifier, 0, len(vo.SLSAPublicSigstoreTimestampServers))
	for _, p := range vo.SLSAPublicSigstoreTimestampServers {
		data, err := os.ReadFile(p) //nolint:gosec // G304: path is from a CLI flag
		if err != nil {
			return l3.Trust{}, fmt.Errorf("read public Sigstore TSA %s: %w", p, err)
		}
		certs, err := parsePEMCerts(data)
		if err != nil {
			return l3.Trust{}, fmt.Errorf("parse public Sigstore TSA %s: %w", p, err)
		}
		tsas = append(tsas, timestamp.NewVerifier(timestamp.VerifyWithCerts(certs)))
	}
	return l3.Trust{Root: l3.RootPublicSigstore, Options: []dsse.VerificationOption{
		dsse.VerifyWithRoots(rootCerts...), dsse.VerifyWithIntermediates(intermediates...),
		dsse.VerifyWithTimestampVerifiers(tsas...),
	}}, nil
}

func writeSLSALevelHuman(w io.Writer, r l3.Result, subjects []string) {
	if r.ObservedLevel == 3 {
		_, _ = fmt.Fprintln(w, "SLSA Build L3: PASSED")
	} else {
		_, _ = fmt.Fprintln(w, "SLSA Build L3: FAILED")
	}
	if r.Signer != nil && r.Statement != nil {
		x := r.Signer.Ext
		_, _ = fmt.Fprintf(w, "  signer:   https://github.com/%s@%s (digest %s, %s root)\n", x.SignerPath, x.SignerRef, x.SignerDigest, r.Signer.Root)
		_, _ = fmt.Fprintf(w, "  source:   %s @ %s, run %s, trigger %s\n", x.SourceRepo, x.SourceDigest, x.RunID, x.Trigger)
	}
	for _, s := range subjects {
		_, _ = fmt.Fprintf(w, "  subject:  %s\n", s)
	}
	for _, f := range r.Verdict.Failures {
		_, _ = fmt.Fprintf(w, "  FAILED %s: %s\n", f.Requirement, f.Detail)
	}
	for _, p := range r.Problems {
		_, _ = fmt.Fprintf(w, "  skipped: %s\n", p)
	}
}

func writeSLSALevelVSA(cmd *cobra.Command, vo options.VerifyOptions, pol l3.Policy, r l3.Result, resource string, subjects []string, inputs []l3.VSADescriptor) error {
	var signers []cryptoutil.Signer
	if providers := providersFromFlags("signer", cmd.Flags()); len(providers) > 0 {
		var err error
		signers, err = loadSigners(cmd.Context(), vo.SignerOptions, vo.KMSSignerProviderOptions, providers)
		if err != nil {
			return fmt.Errorf("failed to load VSA signer: %w", err)
		}
	}
	predicate, err := json.Marshal(l3.NewVSA(pol, r, resource, inputs, time.Now()))
	if err != nil {
		return fmt.Errorf("marshal VSA: %w", err)
	}
	vsaSubjects := map[string]cryptoutil.DigestSet{}
	for _, s := range subjects {
		ds, err := cryptoutil.NewDigestSet(map[string]string{sha256Alg: strings.TrimPrefix(s, sha256Alg+":")})
		if err != nil {
			return err
		}
		vsaSubjects[s] = ds
	}
	return writeVSAStatement(vo.VSAOutFilePath, predicate, vsaSubjects, signers, vo.VSATimestampServers)
}
