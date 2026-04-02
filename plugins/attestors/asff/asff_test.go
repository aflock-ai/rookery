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

package asff

import (
	"encoding/json"
	"testing"
)

// ---- validateASFF tests ----

func TestValidateASFF_EmptyFindings(t *testing.T) {
	err := validateASFF([]Finding{})
	if err == nil {
		t.Fatal("expected error for empty findings, got nil")
	}
}

func TestValidateASFF_MissingId(t *testing.T) {
	findings := []Finding{
		{
			Id:         "", // missing
			Severity:   Severity{Label: "HIGH"},
			Compliance: Compliance{Status: "PASSED"},
		},
	}
	err := validateASFF(findings)
	if err == nil {
		t.Fatal("expected error for missing Id, got nil")
	}
}

func TestValidateASFF_InvalidSeverity(t *testing.T) {
	findings := []Finding{
		{
			Id:         "arn:aws:securityhub:us-east-1:123456789012:finding/abc",
			Severity:   Severity{Label: "UNKNOWN"},
			Compliance: Compliance{Status: "PASSED"},
		},
	}
	err := validateASFF(findings)
	if err == nil {
		t.Fatal("expected error for invalid severity label, got nil")
	}
}

func TestValidateASFF_InvalidComplianceStatus(t *testing.T) {
	findings := []Finding{
		{
			Id:         "arn:aws:securityhub:us-east-1:123456789012:finding/abc",
			Severity:   Severity{Label: "HIGH"},
			Compliance: Compliance{Status: "INVALID_STATUS"},
		},
	}
	err := validateASFF(findings)
	if err == nil {
		t.Fatal("expected error for invalid compliance status, got nil")
	}
}

func TestValidateASFF_ValidFindings(t *testing.T) {
	findings := []Finding{
		{
			Id:           "arn:aws:securityhub:us-east-1:123456789012:finding/abc",
			Title:        "S3 bucket is public",
			AwsAccountId: "123456789012",
			Severity:     Severity{Label: "CRITICAL"},
			Compliance:   Compliance{Status: "FAILED"},
			Resources: []Resource{
				{Type: "AwsS3Bucket", Id: "arn:aws:s3:::my-public-bucket"},
			},
		},
		{
			Id:           "arn:aws:securityhub:us-east-1:123456789012:finding/def",
			Title:        "CloudTrail is enabled",
			AwsAccountId: "123456789012",
			Severity:     Severity{Label: "informational"}, // lowercase — should still pass
			Compliance:   Compliance{Status: "passed"},     // lowercase — should still pass
		},
	}
	if err := validateASFF(findings); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

// ---- buildSummary tests ----

func TestBuildSummary_Counts(t *testing.T) {
	findings := []Finding{
		{
			Id:           "arn:aws:securityhub:us-east-1:111111111111:finding/1",
			Title:        "Critical failed finding",
			AwsAccountId: "111111111111",
			ProductArn:   "arn:aws:securityhub:us-east-1::product/aws/securityhub",
			Severity:     Severity{Label: "CRITICAL"},
			Compliance:   Compliance{Status: "FAILED"},
			Resources:    []Resource{{Type: "AwsS3Bucket", Id: "arn:aws:s3:::bad-bucket"}},
		},
		{
			Id:           "arn:aws:securityhub:us-east-1:111111111111:finding/2",
			Title:        "High failed finding",
			AwsAccountId: "111111111111",
			Severity:     Severity{Label: "HIGH"},
			Compliance:   Compliance{Status: "FAILED"},
			Resources:    []Resource{{Type: "AwsIamUser", Id: "arn:aws:iam::111111111111:user/bad-user"}},
		},
		{
			Id:           "arn:aws:securityhub:us-east-1:111111111111:finding/3",
			Title:        "Medium passed finding",
			AwsAccountId: "111111111111",
			Severity:     Severity{Label: "MEDIUM"},
			Compliance:   Compliance{Status: "PASSED"},
		},
		{
			Id:           "arn:aws:securityhub:us-east-1:111111111111:finding/4",
			Title:        "Low warning finding",
			AwsAccountId: "111111111111",
			Severity:     Severity{Label: "LOW"},
			Compliance:   Compliance{Status: "WARNING"},
		},
	}

	s := buildSummary(findings)

	if s.AwsAccountId != "111111111111" {
		t.Errorf("expected AwsAccountId=111111111111, got %s", s.AwsAccountId)
	}
	if s.TotalFindings != 4 {
		t.Errorf("expected TotalFindings=4, got %d", s.TotalFindings)
	}
	if s.BySeverity["CRITICAL"].Count != 1 {
		t.Errorf("expected 1 CRITICAL finding, got %d", s.BySeverity["CRITICAL"].Count)
	}
	if s.BySeverity["HIGH"].Count != 1 {
		t.Errorf("expected 1 HIGH finding, got %d", s.BySeverity["HIGH"].Count)
	}
	if s.BySeverity["MEDIUM"].Count != 1 {
		t.Errorf("expected 1 MEDIUM finding, got %d", s.BySeverity["MEDIUM"].Count)
	}
	if s.BySeverity["LOW"].Count != 1 {
		t.Errorf("expected 1 LOW finding, got %d", s.BySeverity["LOW"].Count)
	}
	if s.ByComplianceStatus["FAILED"] != 2 {
		t.Errorf("expected 2 FAILED findings, got %d", s.ByComplianceStatus["FAILED"])
	}
	if s.ByComplianceStatus["PASSED"] != 1 {
		t.Errorf("expected 1 PASSED finding, got %d", s.ByComplianceStatus["PASSED"])
	}
	if s.ByComplianceStatus["WARNING"] != 1 {
		t.Errorf("expected 1 WARNING finding, got %d", s.ByComplianceStatus["WARNING"])
	}
	if len(s.FailedFindings) != 2 {
		t.Errorf("expected 2 FailedFindings, got %d", len(s.FailedFindings))
	}
	// FailedFindings should contain resource details.
	if len(s.FailedFindings[0].Resources) == 0 {
		t.Error("expected first FailedFinding to carry Resource details")
	}
}

// ---- Subjects tests ----

func TestSubjects_AccountAndARNs(t *testing.T) {
	a := &Attestor{
		Summary: Summary{
			AwsAccountId: "123456789012",
			FailedFindings: []FailedFinding{
				{
					FindingArn:   "arn:aws:securityhub:us-east-1:123456789012:finding/crit",
					Severity:     "CRITICAL",
					AwsAccountId: "123456789012",
					Resources:    []Resource{{Type: "AwsS3Bucket", Id: "arn:aws:s3:::bad-bucket"}},
				},
				{
					FindingArn:   "arn:aws:securityhub:us-east-1:123456789012:finding/med",
					Severity:     "MEDIUM", // not CRITICAL/HIGH — finding ARN should NOT be emitted
					AwsAccountId: "123456789012",
					Resources:    []Resource{{Type: "AwsS3Bucket", Id: "arn:aws:s3:::bad-bucket"}}, // deduplicated
				},
			},
		},
	}

	subjects := a.Subjects()

	accountKey := "aws:account:123456789012"
	if _, ok := subjects[accountKey]; !ok {
		t.Errorf("expected subject %q to be present", accountKey)
	}

	findingKey := "aws:finding:arn:aws:securityhub:us-east-1:123456789012:finding/crit"
	if _, ok := subjects[findingKey]; !ok {
		t.Errorf("expected CRITICAL finding ARN subject %q to be present", findingKey)
	}

	medFindingKey := "aws:finding:arn:aws:securityhub:us-east-1:123456789012:finding/med"
	if _, ok := subjects[medFindingKey]; ok {
		t.Errorf("MEDIUM finding ARN should NOT be emitted as a subject, but got %q", medFindingKey)
	}

	arnKey := "aws:arn:arn:aws:s3:::bad-bucket"
	if _, ok := subjects[arnKey]; !ok {
		t.Errorf("expected resource ARN subject %q to be present", arnKey)
	}

	// Deduplicated: the bucket ARN appears in two findings but should be one subject.
	if len(subjects) != 3 { // account + critical finding ARN + one resource ARN
		keys := make([]string, 0, len(subjects))
		for k := range subjects {
			keys = append(keys, k)
		}
		t.Errorf("expected 3 subjects, got %d: %v", len(subjects), keys)
	}
}

// ---- JSON round-trip test (validates struct tags) ----

func TestASFFJSONRoundTrip(t *testing.T) {
	raw := `{
		"Findings": [
			{
				"Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/abc",
				"Title": "S3 general purpose buckets should have block public access settings enabled",
				"AwsAccountId": "123456789012",
				"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
				"Severity": {"Label": "HIGH"},
				"Compliance": {"Status": "FAILED"},
				"Resources": [
					{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::my-sensitive-bucket"}
				]
			}
		]
	}`

	var response asffResponse
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("failed to unmarshal ASFF JSON: %v", err)
	}

	if len(response.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(response.Findings))
	}
	f := response.Findings[0]
	if f.Severity.Label != "HIGH" {
		t.Errorf("expected Severity.Label=HIGH, got %s", f.Severity.Label)
	}
	if f.Compliance.Status != "FAILED" {
		t.Errorf("expected Compliance.Status=FAILED, got %s", f.Compliance.Status)
	}
	if len(f.Resources) != 1 || f.Resources[0].Id != "arn:aws:s3:::my-sensitive-bucket" {
		t.Errorf("unexpected resources: %+v", f.Resources)
	}
}
