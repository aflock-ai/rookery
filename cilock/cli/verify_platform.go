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
	"encoding/json"
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

// runPlatformVerify asks the platform's verify door for a verdict and renders
// the answer. Exit contract matches local verify: nil on PASSED, error (exit
// 1) otherwise — gate on the exit code, never on grepped output.
func runPlatformVerify(ctx context.Context, vo options.VerifyOptions) error {
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

	bound, err := pc.ResolveBoundPolicy(ctx, session.cred.ProductID)
	if err != nil {
		return err
	}
	productLabel := session.cred.ProductName
	if productLabel == "" {
		productLabel = session.cred.ProductID
	}
	if bound == nil {
		return fmt.Errorf("no policy bound for product %q — bind one with `cilock policy bind`, or pass -p/--policy for local verification", productLabel)
	}

	// The loud provenance line, BEFORE any verdict output — same contract as
	// the local bound-policy path: name what is about to be trusted, and on
	// whose authority.
	log.Infof("platform verify: policy %q release %q for product %q — bound by %s at %s; --client verifies locally instead",
		bound.DefinitionName, bound.ReleaseTag, productLabel, bound.BoundBy, bound.BoundAt)

	commit, subjects, err := platformVerifyAnchors(&vo)
	if err != nil {
		return err
	}

	eval, err := pc.VerifyComplianceSync(ctx, bound.BindingID, commit, subjects, false)
	if err != nil {
		return err
	}
	return renderPlatformEvaluation(vo, eval)
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
	return eval.Passed() && eval.VsaGitoidSha256 != ""
}

// platformVerdictJSON is the machine-readable platform-mode verdict, the
// sibling of the local mode's VerifyVerdict: `passed` for branching — and it
// means "this gate accepts", never the raw platform verdict, so branching on
// it and branching on the exit code are the same branch. Status carries the
// platform's own verdict for consumers that need the distinction.
type platformVerdictJSON struct {
	Passed          bool     `json:"passed"`
	Status          string   `json:"status"`
	Reasons         []string `json:"reasons,omitempty"`
	VsaGitoidSha256 string   `json:"vsaGitoidSha256,omitempty"`
	EvaluationID    string   `json:"evaluationId,omitempty"`
	CommitHash      string   `json:"commitHash,omitempty"`
}

// renderPlatformEvaluation reports the door's answer. The VSA gitoid is
// printed on success AND failure when present: the signed claim exists either
// way, and the failure VSA is exactly what an auditor wants.
func renderPlatformEvaluation(vo options.VerifyOptions, eval *options.PlatformEvaluation) error {
	if vo.OutputJSON() {
		out := platformVerdictJSON{
			Passed:          gateAccepts(eval),
			Status:          strings.ToUpper(eval.Status),
			Reasons:         eval.Reasons,
			VsaGitoidSha256: eval.VsaGitoidSha256,
			EvaluationID:    eval.ID,
			CommitHash:      eval.CommitHash,
		}
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encode platform verdict: %w", err)
		}
	} else {
		switch {
		case eval.Passed():
			log.Infof("PASSED — the platform's signed answer is VSA %s", orNoVSA(eval.VsaGitoidSha256))
		case strings.EqualFold(eval.Status, "pending"):
			log.Errorf("PENDING — the bound policy's evidence has not arrived for this anchor yet; " +
				"if the pipeline just uploaded, confirm the upload returned before verifying")
		default:
			log.Errorf("FAILED — VSA %s", orNoVSA(eval.VsaGitoidSha256))
		}
		for _, r := range eval.Reasons {
			log.Errorf("  reason: %s", r)
		}
	}
	if gateAccepts(eval) {
		return nil
	}
	// A PASSED verdict with no VSA is a degraded answer, and the gate fails
	// CLOSED on it (Codex, #8666 rounds 1 and 3). RunSync deliberately
	// preserves the verdict when the VSA upload fails — right for the ROW —
	// but an answer nobody can independently re-verify is refused on EVERY
	// surface: the exit code and the JSON `passed` field derive from the one
	// predicate above, so they cannot drift again. The human-readable verdict
	// still prints, so a retry for the evidence is an informed one.
	if eval.Passed() {
		return fmt.Errorf("the policy passed, but the platform could not record the VSA for it — " +
			"the verdict is not independently verifiable, so this gate fails closed; re-run to mint one")
	}
	return fmt.Errorf("platform verification did not pass: status %s", strings.ToUpper(eval.Status))
}

// orNoVSA renders a missing VSA gitoid honestly rather than as an empty
// string: an upload that failed leaves the verdict standing and the gitoid
// blank, loudly, and hiding that would launder a degraded answer.
func orNoVSA(gitoid string) string {
	if gitoid == "" {
		return "(none recorded — the VSA upload failed; the verdict stands but is not independently checkable)"
	}
	return gitoid
}
