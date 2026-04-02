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

package inspec

import (
	"testing"
)

func TestControlOutcome(t *testing.T) {
	tests := []struct {
		name    string
		ctrl    inspecControl
		want    string
	}{
		{
			name: "no results → skipped",
			ctrl: inspecControl{ID: "c1", Results: nil},
			want: "skipped",
		},
		{
			name: "all passed → passed",
			ctrl: inspecControl{ID: "c2", Results: []inspecResult{
				{Status: "passed"},
				{Status: "passed"},
			}},
			want: "passed",
		},
		{
			name: "all skipped → skipped",
			ctrl: inspecControl{ID: "c3", Results: []inspecResult{
				{Status: "skipped"},
			}},
			want: "skipped",
		},
		{
			name: "one failed → failed",
			ctrl: inspecControl{ID: "c4", Results: []inspecResult{
				{Status: "passed"},
				{Status: "failed"},
			}},
			want: "failed",
		},
		{
			name: "failed takes precedence over skipped",
			ctrl: inspecControl{ID: "c5", Results: []inspecResult{
				{Status: "skipped"},
				{Status: "failed"},
			}},
			want: "failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := controlOutcome(tc.ctrl)
			if got != tc.want {
				t.Errorf("controlOutcome() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsInSpecReport(t *testing.T) {
	t.Run("empty profiles → false", func(t *testing.T) {
		r := inspecReport{}
		if isInSpecReport(r) {
			t.Error("expected false for report with no profiles")
		}
	})

	t.Run("non-empty profiles → true", func(t *testing.T) {
		r := inspecReport{
			Profiles: []inspecProfile{{Name: "cis-aws-foundations", Controls: nil}},
		}
		if !isInSpecReport(r) {
			t.Error("expected true for report with profiles")
		}
	})
}

func TestBuildSummaryAndSubjects(t *testing.T) {
	report := inspecReport{
		Platform: inspecPlatform{Name: "aws", Release: "current"},
		Profiles: []inspecProfile{
			{
				Name: "cis-aws-foundations",
				Controls: []inspecControl{
					{
						ID:    "cis-aws-1.1",
						Title: "Avoid the use of the root account",
						Results: []inspecResult{
							{Status: "passed", CodeDesc: "root account not used"},
						},
					},
					{
						ID:    "cis-aws-1.2",
						Title: "MFA enabled for all IAM users",
						Results: []inspecResult{
							{Status: "failed", CodeDesc: "user alice has no MFA"},
						},
					},
					{
						ID:    "cis-aws-1.3",
						Title: "Credentials unused for 90 days",
						Results: []inspecResult{
							{Status: "skipped", CodeDesc: "not applicable"},
						},
					},
				},
			},
		},
		Statistics: inspecStatistics{Duration: 3.14},
	}

	a := New()
	a.buildSummaryAndSubjects(report)

	s := a.ScanSummary
	if s.ProfileName != "cis-aws-foundations" {
		t.Errorf("ProfileName = %q, want %q", s.ProfileName, "cis-aws-foundations")
	}
	if s.Platform != "aws-current" {
		t.Errorf("Platform = %q, want %q", s.Platform, "aws-current")
	}
	if s.TotalControls != 3 {
		t.Errorf("TotalControls = %d, want 3", s.TotalControls)
	}
	if s.PassedControls != 1 {
		t.Errorf("PassedControls = %d, want 1", s.PassedControls)
	}
	if s.FailedControls != 1 {
		t.Errorf("FailedControls = %d, want 1", s.FailedControls)
	}
	if s.SkippedControls != 1 {
		t.Errorf("SkippedControls = %d, want 1", s.SkippedControls)
	}
	if len(s.FailedDetails) != 1 || s.FailedDetails[0].ID != "cis-aws-1.2" {
		t.Errorf("FailedDetails = %+v, want single entry with ID cis-aws-1.2", s.FailedDetails)
	}

	// subjects
	subjects := a.Subjects()
	wantSubjects := []string{
		"platform:aws-current",
		"profile:cis-aws-foundations",
		"inspec:control:cis-aws-1.2",
	}
	for _, key := range wantSubjects {
		if _, ok := subjects[key]; !ok {
			t.Errorf("expected subject %q not found in subjects map", key)
		}
	}
	// passed and skipped controls must NOT appear as subjects
	for _, notWanted := range []string{"inspec:control:cis-aws-1.1", "inspec:control:cis-aws-1.3"} {
		if _, ok := subjects[notWanted]; ok {
			t.Errorf("unexpected subject %q found in subjects map", notWanted)
		}
	}
}
