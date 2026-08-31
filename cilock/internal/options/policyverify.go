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

package options

import (
	"context"
	"fmt"
	"strings"
)

// PlatformEvaluation is the platform verify door's answer: the persisted
// ComplianceEvaluation row for one explicitly-triggered verification. The
// answer's evidence half is the VSA — VsaGitoidSha256 names the signed
// envelope the platform uploaded to Archivista for exactly this verdict, so a
// caller can fetch and re-verify the claim rather than trusting this struct.
type PlatformEvaluation struct {
	ID string `json:"id"`
	// Status carries the schema's `result` enum: PASSED / FAILED / PENDING.
	Status          string   `json:"result"`
	Reasons         []string `json:"reasons"`
	VsaGitoidSha256 string   `json:"vsaGitoidSha256"`
	CommitHash      string   `json:"commitHash"`
}

// Passed reports the terminal-success status. PENDING (evidence not arrived)
// and FAILED are both non-passed; the caller distinguishes them by Status.
func (e *PlatformEvaluation) Passed() bool {
	return strings.EqualFold(e.Status, "passed")
}

const verifyComplianceSyncMutation = `mutation CilockVerify($bindingID: ID!, $commitHash: String, $subjectDigests: [String!], $force: Boolean) {
  verifyComplianceSync(bindingID: $bindingID, commitHash: $commitHash, subjectDigests: $subjectDigests, force: $force) {
    id
    result
    reasons
    vsaGitoidSha256
    commitHash
  }
}`

// VerifyComplianceSync asks the platform's verify door for a verdict on the
// given anchors, under the policy bound to bindingID. The platform verifies
// inline (the caller waits), signs and uploads a VSA for the answer, and the
// returned row carries that VSA's gitoid.
//
// Anchors ride in two fields the door already speaks: commitHash for the
// commit anchor, subjectDigests for artifact sha256s / image digests /
// envelope gitoids (gitoid-prefixed values are expanded server-side to their
// statement's subject closure). At least one is required — an anchorless
// request would mean "verify something", and the whole design exists to make
// that unaskable.
//
// force skips the platform's verdict cache; leave it false so an unchanged
// (policy, evidence) pair answers from the cache.
func (c *PolicyClient) VerifyComplianceSync(ctx context.Context, bindingID, commitHash string, subjectDigests []string, force bool) (*PlatformEvaluation, error) {
	if bindingID == "" {
		return nil, fmt.Errorf("no binding id — the platform verify door is addressed by the product's policy binding")
	}
	if commitHash == "" && len(subjectDigests) == 0 {
		return nil, fmt.Errorf("no anchor: a platform verify needs a commit (--commit), an artifact digest, or a subject digest — an immutable name for the one artifact to verify")
	}
	var out struct {
		VerifyComplianceSync *PlatformEvaluation `json:"verifyComplianceSync"`
	}
	vars := map[string]any{
		"bindingID": bindingID,
		"force":     force,
	}
	if commitHash != "" {
		vars["commitHash"] = commitHash
	}
	if len(subjectDigests) > 0 {
		vars["subjectDigests"] = subjectDigests
	}
	if err := c.post(ctx, verifyComplianceSyncMutation, vars, &out); err != nil {
		return nil, fmt.Errorf("platform verify: %w", err)
	}
	if out.VerifyComplianceSync == nil {
		return nil, fmt.Errorf("platform verify: the mutation answered with no evaluation row")
	}
	return out.VerifyComplianceSync, nil
}
