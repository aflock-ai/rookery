// jade:ring local

package prowler

import "testing"

func TestCanonicalCheck(t *testing.T) {
	cases := []struct {
		f    Finding
		want string
	}{
		{Finding{CheckID: "prowler-aws-config_recorder_all_regions_enabled-178674732984-us-east-1-178674732984", Provider: "aws", AccountId: "178674732984"}, "config_recorder_all_regions_enabled"},
		{Finding{CheckID: "prowler-aws-cloudwatch_log_group_kms_encryption_enabled-178674732984-us-east-1-/aws-glue/jobs/error", Provider: "aws", AccountId: "178674732984"}, "cloudwatch_log_group_kms_encryption_enabled"},
		{Finding{CheckID: "iam_root_mfa_enabled", Provider: "aws"}, "iam_root_mfa_enabled"},
	}
	for _, c := range cases {
		if got := canonicalCheck(c.f); got != c.want {
			t.Errorf("canonicalCheck(%q) = %q, want %q", c.f.CheckID, got, c.want)
		}
	}
}

// A check that ran and passed must appear in ChecksRun; that is what lets a policy
// tell "passed" from "never ran".
func TestChecksRunRecordsPasses(t *testing.T) {
	s := buildSummary([]Finding{
		{CheckID: "prowler-aws-a_check-1-us-east-1-r1", Provider: "aws", AccountId: "1", Status: "PASS", Severity: "low"},
		{CheckID: "prowler-aws-a_check-1-us-east-1-r2", Provider: "aws", AccountId: "1", Status: "FAIL", Severity: "low"},
		{CheckID: "prowler-aws-b_check-1-us-east-1-r1", Provider: "aws", AccountId: "1", Status: "PASS", Severity: "low"},
	})
	want := []CheckRun{{"a_check", 1, 1}, {"b_check", 1, 0}}
	if len(s.ChecksRun) != len(want) {
		t.Fatalf("ChecksRun = %+v, want %+v", s.ChecksRun, want)
	}
	for i := range want {
		if s.ChecksRun[i] != want[i] {
			t.Errorf("ChecksRun[%d] = %+v, want %+v", i, s.ChecksRun[i], want[i])
		}
	}
}
