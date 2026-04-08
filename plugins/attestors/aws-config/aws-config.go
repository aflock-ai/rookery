// Copyright 2022 The Witness Contributors
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

package awsconfig

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "aws-config"
	Type    = "https://aflock.ai/attestations/aws-config/v0.1"
	RunType = attestation.PostProductRunType
)

// compile-time interface check
var _ attestation.Attestor = &Attestor{}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// evaluationResults mirrors the JSON produced by:
//
//	aws configservice get-compliance-details-by-config-rule
type evaluationResults struct {
	EvaluationResults []evaluationResult `json:"EvaluationResults"`
}

type evaluationResult struct {
	EvaluationResultIdentifier evaluationResultIdentifier `json:"EvaluationResultIdentifier"`
	ComplianceType             string                     `json:"ComplianceType"`
	ResultRecordedTime         string                     `json:"ResultRecordedTime,omitempty"`
	ConfigRuleInvokedTime      string                     `json:"ConfigRuleInvokedTime,omitempty"`
	Annotation                 string                     `json:"Annotation,omitempty"`
}

type evaluationResultIdentifier struct {
	EvaluationResultQualifier evaluationResultQualifier `json:"EvaluationResultQualifier"`
}

type evaluationResultQualifier struct {
	ConfigRuleName string `json:"ConfigRuleName"`
	ResourceType   string `json:"ResourceType"`
	ResourceId     string `json:"ResourceId"`
}

// ComplianceSummary tracks rule evaluation counts.
type ComplianceSummary struct {
	TotalRules            int      `json:"totalRules"`
	CompliantCount        int      `json:"compliantCount"`
	NonCompliantCount     int      `json:"nonCompliantCount"`
	NonCompliantResources []string `json:"nonCompliantResources"`
}

// Attestor reads AWS Config rule evaluation results and attests to compliance
// status, exposing resource ARNs, rule names, and account IDs as subjects.
type Attestor struct {
	ReportFile      string               `json:"reportFile"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
	Summary         ComplianceSummary    `json:"summary"`

	subjects map[string]cryptoutil.DigestSet
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/aws-config) error getting candidate: %v", err)
		return err
	}
	return nil
}

// Subjects implements attestation.Subjecter.
// Exposes subjects for every Config rule name, every non-compliant resource,
// and the AWS account ID extracted from resource ARNs.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		// Accept only .json files.
		if !strings.HasSuffix(path, ".json") {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/aws-config) error calculating digest set from file %s: %v", path, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/aws-config) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/aws-config) error opening file %s: %v", path, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/aws-config) error reading file %s: %v", path, err)
			continue
		}

		var results evaluationResults
		if err := json.Unmarshal(reportBytes, &results); err != nil {
			log.Debugf("(attestation/aws-config) error parsing JSON from %s: %v", path, err)
			continue
		}

		// Require at least the expected top-level key to be present.
		if len(results.EvaluationResults) == 0 {
			log.Debugf("(attestation/aws-config) no EvaluationResults in %s, skipping", path)
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.buildSummaryAndSubjects(results)
		return nil
	}

	return fmt.Errorf("no aws config evaluation results JSON found in products")
}

func (a *Attestor) buildSummaryAndSubjects(results evaluationResults) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	var summary ComplianceSummary
	ruleSet := make(map[string]struct{})
	accountSet := make(map[string]struct{})

	for _, result := range results.EvaluationResults {
		q := result.EvaluationResultIdentifier.EvaluationResultQualifier

		// Track unique rules.
		ruleSet[q.ConfigRuleName] = struct{}{}

		// Emit subject: aws-config:rule:<name>
		ruleKey := fmt.Sprintf("aws-config:rule:%s", q.ConfigRuleName)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(q.ConfigRuleName), hashes); err == nil {
			subjects[ruleKey] = ds
		} else {
			log.Debugf("(attestation/aws-config) failed to hash rule subject %s: %v", q.ConfigRuleName, err)
		}

		// Emit subject: aws-config:resource:<resourceType>/<resourceId>
		resourceRef := fmt.Sprintf("%s/%s", q.ResourceType, q.ResourceId)
		resourceKey := fmt.Sprintf("aws-config:resource:%s", resourceRef)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(resourceRef), hashes); err == nil {
			subjects[resourceKey] = ds
		} else {
			log.Debugf("(attestation/aws-config) failed to hash resource subject %s: %v", resourceRef, err)
		}

		// Extract account ID from ARN if the ResourceId looks like an ARN.
		// ARN format: arn:aws:<service>:<region>:<account-id>:<resource>
		if strings.HasPrefix(q.ResourceId, "arn:") {
			parts := strings.Split(q.ResourceId, ":")
			if len(parts) >= 5 && parts[4] != "" {
				accountID := parts[4]
				accountSet[accountID] = struct{}{}
			}
		}

		switch result.ComplianceType {
		case "COMPLIANT":
			summary.CompliantCount++
		case "NON_COMPLIANT":
			summary.NonCompliantCount++
			summary.NonCompliantResources = append(summary.NonCompliantResources, resourceRef)
		}
	}

	summary.TotalRules = len(ruleSet)

	// Emit subjects for each account ID discovered.
	for accountID := range accountSet {
		accountKey := fmt.Sprintf("aws:account:%s", accountID)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(accountID), hashes); err == nil {
			subjects[accountKey] = ds
		} else {
			log.Debugf("(attestation/aws-config) failed to hash account subject %s: %v", accountID, err)
		}
	}

	a.Summary = summary
	a.subjects = subjects
}
