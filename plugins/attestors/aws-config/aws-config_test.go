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
	"encoding/json"
	"testing"
)

const sampleAWSConfig = `{
  "EvaluationResults": [
    {
      "EvaluationResultIdentifier": {
        "EvaluationResultQualifier": {
          "ConfigRuleName": "s3-bucket-public-access-prohibited",
          "ResourceType": "AWS::S3::Bucket",
          "ResourceId": "arn:aws:s3:::my-public-bucket"
        }
      },
      "ComplianceType": "NON_COMPLIANT",
      "Annotation": "Bucket has public access enabled"
    },
    {
      "EvaluationResultIdentifier": {
        "EvaluationResultQualifier": {
          "ConfigRuleName": "s3-bucket-public-access-prohibited",
          "ResourceType": "AWS::S3::Bucket",
          "ResourceId": "arn:aws:s3:::my-private-bucket"
        }
      },
      "ComplianceType": "COMPLIANT"
    },
    {
      "EvaluationResultIdentifier": {
        "EvaluationResultQualifier": {
          "ConfigRuleName": "ec2-instance-no-public-ip",
          "ResourceType": "AWS::EC2::Instance",
          "ResourceId": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890"
        }
      },
      "ComplianceType": "NON_COMPLIANT"
    }
  ]
}`

func TestBuildSummaryAndSubjects(t *testing.T) {
	a := New()

	var results evaluationResults
	if err := json.Unmarshal([]byte(sampleAWSConfig), &results); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	a.buildSummaryAndSubjects(results)

	if a.Summary.TotalRules != 2 {
		t.Errorf("expected 2 unique rules, got %d", a.Summary.TotalRules)
	}
	if a.Summary.CompliantCount != 1 {
		t.Errorf("expected 1 compliant, got %d", a.Summary.CompliantCount)
	}
	if a.Summary.NonCompliantCount != 2 {
		t.Errorf("expected 2 non-compliant, got %d", a.Summary.NonCompliantCount)
	}
	if len(a.Summary.NonCompliantResources) != 2 {
		t.Errorf("expected 2 non-compliant resources, got %d", len(a.Summary.NonCompliantResources))
	}

	// Rule subjects.
	if _, ok := a.subjects["aws-config:rule:s3-bucket-public-access-prohibited"]; !ok {
		t.Error("expected subject aws-config:rule:s3-bucket-public-access-prohibited")
	}
	if _, ok := a.subjects["aws-config:rule:ec2-instance-no-public-ip"]; !ok {
		t.Error("expected subject aws-config:rule:ec2-instance-no-public-ip")
	}

	// Resource subjects.
	if _, ok := a.subjects["aws-config:resource:AWS::S3::Bucket/arn:aws:s3:::my-public-bucket"]; !ok {
		t.Error("expected subject for my-public-bucket")
	}
	if _, ok := a.subjects["aws-config:resource:AWS::EC2::Instance/arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890"]; !ok {
		t.Error("expected subject for EC2 instance")
	}

	// Account ID extracted from EC2 ARN (arn:aws:ec2:us-east-1:123456789012:...)
	if _, ok := a.subjects["aws:account:123456789012"]; !ok {
		t.Error("expected subject aws:account:123456789012 extracted from EC2 ARN")
	}
}

func TestMetadata(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("unexpected Name(): %s", a.Name())
	}
	if a.Type() != Type {
		t.Errorf("unexpected Type(): %s", a.Type())
	}
	if a.RunType() != RunType {
		t.Errorf("unexpected RunType(): %s", a.RunType())
	}
}
