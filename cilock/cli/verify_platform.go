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
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// Platform verify mode (verify-on-demand, Cole 2026-08-31): the DEFAULT for a
// flagless-policy `cilock verify` with a platform session. The platform never
// verifies on its own — this command at the end of a pipeline IS the trigger —
// and the answer is a VSA: the platform verifies inline against the product's
// bound policy, signs and uploads a VSA for the verdict, and hands back its
// gitoid so the verdict is portable evidence, not a trusted string.
//
// The mode rule, chosen so no existing invocation changes meaning:
//
//   - `-p/--policy` given        -> LOCAL verification of that policy (the
//     historical behavior; a local policy file cannot be evaluated by the
//     platform, which verifies the BOUND policy).
//   - `--client`                 -> LOCAL verification under the platform-bound
//     policy (the pre-existing resolveBoundPolicyRef path).
//   - `--platform-url ""`        -> fully offline; platform mode is
//     structurally impossible and the local path answers.
//   - otherwise                  -> PLATFORM mode, this file.
//
// platformVerifyTimeout bounds the door call. The inline verify runs well
// under a minute on a bounded anchor; three gives slack for a cold policy
// download without letting a wedged platform hold a pipeline forever.
const platformVerifyTimeout = 3 * time.Minute

// platformVerifyMode reports whether this invocation goes to the platform
// door rather than the local verifier.
func platformVerifyMode(vo *options.VerifyOptions) bool {
	if vo.ClientSide {
		return false
	}
	if vo.PolicyFilePath != "" {
		return false
	}
	return vo.PlatformURL != ""
}

// platformModeConflicts lists the local-evidence and local-output flags this
// invocation set that the platform door would SILENTLY ignore. The door
// evaluates the bound policy against platform-held evidence and answers with
// an uploaded VSA — it reads no local envelopes and writes no local files, so
// an invocation combining it with these flags is asking for two different
// verifies at once. Refusing is the only honest answer: routing to the door
// would exit 0 with (for example) no --vsa-outfile ever written, breaking the
// pipeline stage that reads it (#8743).
//
// flagChanged distinguishes an operator's explicit choice from a session
// default: ResolvePlatformDefaults turns ArchivistaOptions.Enable on for
// every logged-in session — exactly the population that reaches platform
// mode — so gating on the FIELD would refuse every logged-in platform verify.
// Only an explicit --enable-archivista conflicts.
func platformModeConflicts(vo *options.VerifyOptions, flagChanged func(string) bool) []string {
	var conflicts []string
	if len(vo.AttestationFilePaths) > 0 {
		conflicts = append(conflicts, "-a/--attestations")
	}
	if len(vo.BundlePaths) > 0 {
		conflicts = append(conflicts, "--bundle")
	}
	if vo.OutputBundlePath != "" {
		conflicts = append(conflicts, "--output-bundle")
	}
	if vo.VSAOutFilePath != "" {
		conflicts = append(conflicts, "--vsa-outfile")
	}
	if len(vo.VSATimestampServers) > 0 {
		conflicts = append(conflicts, "--vsa-timestamp-servers")
	}
	if vo.ArchivistaOptions.Enable && (flagChanged("enable-archivista") || flagChanged("enable-archivist")) {
		conflicts = append(conflicts, "--enable-archivista")
	}
	return conflicts
}

// runPlatformVerify asks the platform's verify door for a verdict and renders
// the answer. Exit contract matches local verify: nil on PASSED, error (exit
// 1) otherwise — gate on the exit code, never on grepped output.
//
// It refuses, before touching the platform, any invocation that also set
// local-evidence/output flags the door cannot honor — silently ignoring them
// exits 0 with (for example) no --vsa-outfile ever written (#8743).
func runPlatformVerify(ctx context.Context, vo options.VerifyOptions, flagChanged func(string) bool) error {
	if conflicts := platformModeConflicts(&vo, flagChanged); len(conflicts) > 0 {
		return fmt.Errorf(
			"platform verify cannot honor %s: the platform door evaluates the bound policy "+
				"against platform-held evidence and answers with an uploaded VSA — it reads no "+
				"local attestations and writes no local files. Pass --client to verify locally "+
				"under the bound policy (honoring these flags), or -p <policy> to verify against "+
				"a local policy",
			strings.Join(conflicts, ", "))
	}
	session, err := resolvePolicySession(vo.PlatformURL)
	if err != nil {
		return fmt.Errorf("platform verify needs a session: %w (or pass -p for local verification)", err)
	}
	if session.cred.ProductID == "" {
		return fmt.Errorf("no working product on this session — run `cilock use` to select one, or pass -p for local verification")
	}

	pc := session.policyClient()
	// The door verifies inline while this call waits; the client default
	// (30s) is sized for metadata queries, not a verification.
	pc.HTTPClient = &http.Client{Timeout: platformVerifyTimeout}

	productLabel := session.cred.ProductName
	if productLabel == "" {
		productLabel = session.cred.ProductID
	}

	commit, subjects, err := platformVerifyAnchors(&vo)
	if err != nil {
		return err
	}

	gate, err := evaluateAllBindings(ctx, pc, session.cred.ProductID, commit, subjects)
	if errors.Is(err, errNoBoundPolicy) {
		return fmt.Errorf("no policy bound for product %q: bind one with `cilock policy bind`, or pass -p/--policy for local verification", productLabel)
	}
	if err != nil {
		return err
	}
	return renderPlatformGate(vo, gate, os.Stdout, os.Stderr)
}

// platformVerifyAnchors assembles the request's anchors from what the caller
// holds: --commit, the positional artifact's computed sha256, and -s subjects.
// At least one is required — an anchor is an immutable name for the ONE
// artifact to verify, already in the caller's hand, and a request without one
// is "verify something", which this design makes unaskable.
func platformVerifyAnchors(vo *options.VerifyOptions) (commit string, subjects []string, err error) {
	commit = strings.TrimSpace(vo.CommitHash)
	subjects = append(subjects, vo.AdditionalSubjects...)

	if vo.ArtifactFilePath != "" {
		ds, derr := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if derr != nil {
			return "", nil, fmt.Errorf("failed to calculate artifact digest: %w", derr)
		}
		hex := suppliedSHA256(ds)
		log.Infof("anchor: sha256:%s (computed from %s)", hex, vo.ArtifactFilePath)
		subjects = append(subjects, hex)
	}
	if vo.ArtifactDirectoryPath != "" {
		ds, derr := cryptoutil.CalculateDigestSetFromDir(vo.ArtifactDirectoryPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if derr != nil {
			return "", nil, fmt.Errorf("failed to calculate directory digest: %w", derr)
		}
		hex := suppliedSHA256(ds)
		log.Infof("anchor: sha256:%s (computed from directory %s)", hex, vo.ArtifactDirectoryPath)
		subjects = append(subjects, hex)
	}

	if commit == "" && len(subjects) == 0 {
		return "", nil, fmt.Errorf("no anchor: a platform verify needs an immutable name for the one artifact to verify — " +
			"pass --commit <sha>, an artifact path (its sha256 is computed for you), or -s sha256:<hex> / -s gitoid:<gitoid>")
	}
	return commit, subjects, nil
}

// gateAccepts is THE acceptance rule, and both consumers derive from it —
// the JSON `passed` field and the exit code (Codex, #8666 round 3: the two
// had drifted, so a JSON consumer branching on `passed` accepted a verdict
// the exit code was refusing). A verdict is accepted only when it PASSED and
// carries the VSA that makes it independently verifiable; the mode's
// contract is "the answer is a VSA", and an answer without one is degraded
// on every surface, not just one of them.
func gateAccepts(eval *options.PlatformEvaluation) bool {
	return eval != nil && eval.Passed() && eval.VsaGitoidSha256 != ""
}
