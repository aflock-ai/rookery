// jade:ring local

package openvex

import "testing"

func TestCanonicalVulnIDFindings(t *testing.T) {
	ok := map[string]string{
		"prowler:awslambda_function_no_secrets_in_variables": "prowler:awslambda_function_no_secrets_in_variables",
		"Kubescape:C-0017":    "kubescape:c-0017",
		"CVE-2024-12345":      "CVE-2024-12345",
		"ghsa-2f3c-50f2-23e2": "",
	}
	for in, want := range ok {
		got, err := canonicalVulnID(in)
		if want == "" {
			continue
		}
		if err != nil || got != want {
			t.Errorf("canonicalVulnID(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"prowler", ":x", "prowler:", "cve:2024", "ghsa:x", "a b:c", "prowler:../../etc", "x:" + string(make([]byte, 200))} {
		if got, err := canonicalVulnID(bad); err == nil {
			t.Errorf("canonicalVulnID(%q) = %q, want error", bad, got)
		}
	}
}

func TestParseProductARN(t *testing.T) {
	for _, ok := range []string{
		"arn:aws:lambda:us-east-1:178674732984:function:JudgeContainerStack-Judge-SlackNotificationLambda2-DnNrBZaHRHQR",
		"arn:aws:ecs:us-east-1:178674732984:task-definition/PreviewPlatformStackWakeProxyTaskDefB90416AA:10",
		"arn:aws:s3:::judge-bucket",
	} {
		p, key, err := parseProduct(ok)
		if err != nil || key != ok || p.ID != ok {
			t.Errorf("parseProduct(%q) = %+v, %q, %v", ok, p, key, err)
		}
	}
	// A wildcard is IAM policy syntax, not a resource: a not_affected statement
	// about "every bucket" names no product and must not be signable.
	for _, bad := range []string{"arn:", "arn:aws", "arn:aws:lambda", "arn:aws:lambda:us-east-1:12:function:x", "arn:gcp:x:y:123456789012:z",
		"arn:aws:s3:::*", "arn:aws:iam::123456789012:role/*", "arn:aws:lambda:us-east-1:123456789012:function:*"} {
		if _, _, err := parseProduct(bad); err == nil {
			t.Errorf("parseProduct(%q) accepted a malformed ARN", bad)
		}
	}
}
