//go:build audit

// Copyright 2025 The Witness Contributors
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

package gcpiit

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// BUG #1: parseJWTProjectInfo swaps project ID and project name semantics
// ============================================================================
// parseJWTProjectInfo returns (projectID, projectName, error).
// But getInstanceData() calls it as:
//   projID, projNum, err := parseJWTProjectInfo(a.JWT)
//   a.ProjectID = projID     // gets last dash-segment (numeric ID in GCP)
//   a.ProjectNumber = projNum // gets everything before last dash (project name)
//
// The return values are:
//   projectID = projectInfoSplit[len-1]     // last segment after dashes
//   projectName = join(projectInfoSplit[:len-1], "-")  // everything before
//
// For email "sa@my-project-123456.iam.gserviceaccount.com":
//   domain = "my-project-123456.iam.gserviceaccount.com"
//   projectInfo = "my-project-123456" (first segment before dots)
//   projectInfoSplit = ["my", "project", "123456"]
//   projectID = "123456" (last)
//   projectName = "my-project" (rest joined)
//
// So getInstanceData sets:
//   a.ProjectID = "123456"     -- this is actually the project NUMBER
//   a.ProjectNumber = "my-project" -- this is actually the project NAME
//
// The field names and the semantics are swapped!

func TestBug_ParseJWTProjectInfoSwapsIDAndName(t *testing.T) {
	jwtAtt := jwt.New()
	jwtAtt.Claims = map[string]interface{}{
		"email": "sa@my-project-123456.iam.gserviceaccount.com",
	}

	projID, projNum, err := parseJWTProjectInfo(jwtAtt)
	require.NoError(t, err)

	// The function returns:
	//   projID = "123456" (the numeric part, extracted as "projectID")
	//   projNum = "my-project" (the name part, extracted as "projectName")
	assert.Equal(t, "123456", projID, "projID is the numeric ID portion")
	assert.Equal(t, "my-project", projNum, "projNum is actually the project name, not number")

	// Now simulate what getInstanceData does:
	a := New()
	a.ProjectID = projID     // "123456" -- looks like a number, not an ID
	a.ProjectNumber = projNum // "my-project" -- this is a NAME, not a number

	t.Logf("BUG: ProjectID is set to %q (numeric ID extracted from email)", a.ProjectID)
	t.Logf("BUG: ProjectNumber is set to %q (project name, NOT a number)", a.ProjectNumber)
	t.Logf("BUG: The second return value from parseJWTProjectInfo is 'projectName' but the caller treats it as 'projectNumber'")
}

// ============================================================================
// BUG #2: parseJWTProjectInfo panics on single-segment domain with no dashes
// ============================================================================
// If email = "sa@nodashes.com", then:
//   domain = "nodashes.com"
//   projectInfo = "nodashes"
//   projectInfoSplit = ["nodashes"]
//   projectID = projectInfoSplit[0] = "nodashes"
//   projectName = join(projectInfoSplit[:0], "-") = ""
//
// This doesn't panic but returns surprising results. Let's verify.

func TestParseJWTProjectInfo_NoDashes(t *testing.T) {
	jwtAtt := jwt.New()
	jwtAtt.Claims = map[string]interface{}{
		"email": "sa@nodashes.com",
	}

	projID, projName, err := parseJWTProjectInfo(jwtAtt)
	require.NoError(t, err)

	// projectInfoSplit = ["nodashes"], so:
	// projectID = "nodashes" (last element)
	// projectName = "" (join of empty slice)
	assert.Equal(t, "nodashes", projID)
	assert.Equal(t, "", projName, "Project name is empty when no dashes present")
}

// ============================================================================
// Adversarial: Type assertions in claim extraction
// ============================================================================

func TestClaimExtraction_AllTypeAssertionsSafe(t *testing.T) {
	testCases := []struct {
		name   string
		claims map[string]interface{}
	}{
		{
			name: "google_claim_is_string",
			claims: map[string]interface{}{
				"google": "not-a-map",
			},
		},
		{
			name: "google_claim_is_int",
			claims: map[string]interface{}{
				"google": 42,
			},
		},
		{
			name: "google_claim_is_bool",
			claims: map[string]interface{}{
				"google": true,
			},
		},
		{
			name: "google_claim_is_float",
			claims: map[string]interface{}{
				"google": 3.14,
			},
		},
		{
			name: "google_claim_is_array",
			claims: map[string]interface{}{
				"google": []interface{}{"a", "b"},
			},
		},
		{
			name: "google_claim_is_nested_map",
			claims: map[string]interface{}{
				"google": map[string]interface{}{
					"nested": map[string]interface{}{
						"deep": "value",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := New()
			a.JWT = jwt.New()
			a.JWT.Claims = tc.claims

			// Simulate the claim extraction logic from Attest()
			// This must not panic regardless of claim types
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Claim extraction panicked: %v", r)
					}
				}()

				if a.JWT.Claims["google"] == nil {
					a.isWorkloadIdentity = true
					return
				}

				googClaim, ok := a.JWT.Claims["google"].(map[string]interface{})
				if !ok {
					// This is the expected path for non-map types
					return
				}

				// These should all use two-value type assertions
				if v, ok := googClaim["project_id"].(string); ok {
					a.ProjectID = v
				}
				if v, ok := googClaim["project_number"].(string); ok {
					a.ProjectNumber = v
				}
				if v, ok := googClaim["zone"].(string); ok {
					a.InstanceZone = v
				}
				if v, ok := googClaim["instance_id"].(string); ok {
					a.InstanceID = v
				}
				if v, ok := googClaim["instance_name"].(string); ok {
					a.InstanceHostname = v
				}
				if v, ok := googClaim["instance_creation_timestamp"].(string); ok {
					a.InstanceCreationTimestamp = v
				}
				if v, ok := googClaim["instance_confidentiality"].(string); ok {
					a.InstanceConfidentiality = v
				}

				switch v := googClaim["licence_id"].(type) {
				case []string:
					a.LicenceID = v
				case []interface{}:
					for _, item := range v {
						if s, ok := item.(string); ok {
							a.LicenceID = append(a.LicenceID, s)
						}
					}
				}
			}()
		})
	}
}

// ============================================================================
// Adversarial: Google claim with all wrong types for nested fields
// ============================================================================

func TestClaimExtraction_WrongTypesInGoogleClaim(t *testing.T) {
	testCases := []struct {
		name       string
		googClaim  map[string]interface{}
		wantFields map[string]string // field name -> expected value
	}{
		{
			name: "all_ints",
			googClaim: map[string]interface{}{
				"project_id":                 42,
				"project_number":             43,
				"zone":                       44,
				"instance_id":                45,
				"instance_name":              46,
				"instance_creation_timestamp": 47,
				"instance_confidentiality":   48,
				"licence_id":                 49,
			},
			wantFields: map[string]string{
				"ProjectID": "", "ProjectNumber": "", "InstanceZone": "",
				"InstanceID": "", "InstanceHostname": "",
			},
		},
		{
			name: "all_nil",
			googClaim: map[string]interface{}{
				"project_id":     nil,
				"project_number": nil,
				"zone":           nil,
				"instance_id":    nil,
				"instance_name":  nil,
				"licence_id":     nil,
			},
			wantFields: map[string]string{
				"ProjectID": "", "ProjectNumber": "", "InstanceZone": "",
				"InstanceID": "", "InstanceHostname": "",
			},
		},
		{
			name: "all_bools",
			googClaim: map[string]interface{}{
				"project_id":     true,
				"project_number": false,
				"zone":           true,
				"instance_id":    false,
				"instance_name":  true,
				"licence_id":     false,
			},
			wantFields: map[string]string{
				"ProjectID": "", "ProjectNumber": "",
			},
		},
		{
			name: "licence_id_as_mixed_array",
			googClaim: map[string]interface{}{
				"project_id": "proj-123",
				"licence_id": []interface{}{"lic1", 42, nil, true, "lic2", 3.14},
			},
			wantFields: map[string]string{
				"ProjectID": "proj-123",
			},
		},
		{
			name: "licence_id_as_string_slice",
			googClaim: map[string]interface{}{
				"licence_id": []string{"lic1", "lic2", "lic3"},
			},
			wantFields: map[string]string{},
		},
		{
			name: "licence_id_as_empty_array",
			googClaim: map[string]interface{}{
				"licence_id": []interface{}{},
			},
			wantFields: map[string]string{},
		},
		{
			name: "missing_fields",
			googClaim: map[string]interface{}{
				"unexpected_field": "value",
			},
			wantFields: map[string]string{
				"ProjectID": "", "ProjectNumber": "",
			},
		},
		{
			name: "empty_strings",
			googClaim: map[string]interface{}{
				"project_id":     "",
				"project_number": "",
				"zone":           "",
				"instance_id":    "",
				"instance_name":  "",
			},
			wantFields: map[string]string{
				"ProjectID": "", "ProjectNumber": "", "InstanceZone": "",
				"InstanceID": "", "InstanceHostname": "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := New()
			a.JWT = jwt.New()
			a.JWT.Claims = map[string]interface{}{
				"google": tc.googClaim,
			}

			// Must not panic
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Claim extraction panicked with %s: %v", tc.name, r)
					}
				}()

				googClaim, ok := a.JWT.Claims["google"].(map[string]interface{})
				require.True(t, ok)

				if v, ok := googClaim["project_id"].(string); ok {
					a.ProjectID = v
				}
				if v, ok := googClaim["project_number"].(string); ok {
					a.ProjectNumber = v
				}
				if v, ok := googClaim["zone"].(string); ok {
					a.InstanceZone = v
				}
				if v, ok := googClaim["instance_id"].(string); ok {
					a.InstanceID = v
				}
				if v, ok := googClaim["instance_name"].(string); ok {
					a.InstanceHostname = v
				}

				switch v := googClaim["licence_id"].(type) {
				case []string:
					a.LicenceID = v
				case []interface{}:
					for _, item := range v {
						if s, ok := item.(string); ok {
							a.LicenceID = append(a.LicenceID, s)
						}
					}
				}
			}()

			// Subjects() must not panic after claim extraction
			subjects := a.Subjects()
			assert.NotNil(t, subjects)
		})
	}
}

// ============================================================================
// Adversarial: licence_id type switch completeness
// ============================================================================
// The type switch handles []string and []interface{} but NOT other types.
// JSON unmarshaling never produces []string (it produces []interface{}),
// so the []string case is only reachable from manually constructed claims.

func TestLicenceIDTypeSwitch(t *testing.T) {
	testCases := []struct {
		name       string
		licenceID  interface{}
		wantLen    int
		wantValues []string
	}{
		{
			name:       "string_slice",
			licenceID:  []string{"lic1", "lic2"},
			wantLen:    2,
			wantValues: []string{"lic1", "lic2"},
		},
		{
			name:       "interface_slice_all_strings",
			licenceID:  []interface{}{"lic1", "lic2", "lic3"},
			wantLen:    3,
			wantValues: []string{"lic1", "lic2", "lic3"},
		},
		{
			name:       "interface_slice_mixed",
			licenceID:  []interface{}{"lic1", 42, nil, "lic2"},
			wantLen:    2,
			wantValues: []string{"lic1", "lic2"},
		},
		{
			name:      "string_not_slice",
			licenceID: "single-licence",
			wantLen:   0, // falls through both cases
		},
		{
			name:      "int",
			licenceID: 42,
			wantLen:   0,
		},
		{
			name:      "nil",
			licenceID: nil,
			wantLen:   0,
		},
		{
			name:      "bool",
			licenceID: true,
			wantLen:   0,
		},
		{
			name:      "float64",
			licenceID: 3.14,
			wantLen:   0,
		},
		{
			name:       "empty_string_slice",
			licenceID:  []string{},
			wantLen:    0,
			wantValues: []string{},
		},
		{
			name:      "empty_interface_slice",
			licenceID: []interface{}{},
			wantLen:   0,
		},
		{
			name:       "interface_slice_with_only_non_strings",
			licenceID:  []interface{}{42, 3.14, true, nil},
			wantLen:    0,
			wantValues: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := New()

			// Must not panic
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("licence_id type switch panicked: %v", r)
					}
				}()

				switch v := tc.licenceID.(type) {
				case []string:
					a.LicenceID = v
				case []interface{}:
					for _, item := range v {
						if s, ok := item.(string); ok {
							a.LicenceID = append(a.LicenceID, s)
						}
					}
				}
			}()

			assert.Len(t, a.LicenceID, tc.wantLen)
			if tc.wantValues != nil {
				assert.Equal(t, tc.wantValues, a.LicenceID)
			}
		})
	}
}

// ============================================================================
// Adversarial: parseJWTProjectInfo edge cases
// ============================================================================

func TestParseJWTProjectInfo_EdgeCases(t *testing.T) {
	testCases := []struct {
		name       string
		email      interface{} // can be string or non-string to test type assertion
		wantErr    bool
		errContain string
		wantID     string
		wantName   string
	}{
		{
			name:    "valid_gcp_email",
			email:   "sa@my-project-123456.iam.gserviceaccount.com",
			wantID:  "123456",
			wantName: "my-project",
		},
		{
			name:    "single_dash",
			email:   "sa@project-123.com",
			wantID:  "123",
			wantName: "project",
		},
		{
			name:    "many_dashes",
			email:   "sa@a-b-c-d-e-f.com",
			wantID:  "f",
			wantName: "a-b-c-d-e",
		},
		{
			name:    "no_dashes",
			email:   "sa@projectname.com",
			wantID:  "projectname",
			wantName: "",
		},
		{
			name:       "no_at_sign",
			email:      "invalid",
			wantErr:    true,
			errContain: "unable to parse email",
		},
		{
			name:       "multiple_at_signs",
			email:      "a@b@c.com",
			wantErr:    true,
			errContain: "unable to parse email",
		},
		{
			name:       "email_is_nil",
			email:      nil,
			wantErr:    true,
			errContain: "unable to find email claim",
		},
		{
			name:       "email_is_int",
			email:      42,
			wantErr:    true,
			errContain: "email claim is not a string",
		},
		{
			name:       "email_is_bool",
			email:      true,
			wantErr:    true,
			errContain: "email claim is not a string",
		},
		{
			name:    "empty_email",
			email:   "",
			wantErr: true,
		},
		{
			name:     "just_at_sign",
			email:    "@",
			// BUG: "@" splits into ["",""] which has len 2, so it passes validation.
			// The code should reject this as an invalid email.
			wantErr:  false,
			wantID:   "",
			wantName: "",
		},
		{
			name:    "at_at_start",
			email:   "@domain.com",
			wantID:  "domain",
			wantName: "",
		},
		{
			name:    "at_at_end",
			email:   "user@",
			wantID:  "",
			wantName: "",
		},
		{
			name:    "unicode_in_domain",
			email:   "sa@proj\u00e9ct-123.com",
			wantID:  "123",
			wantName: "proj\u00e9ct",
		},
		{
			name:    "dots_in_domain_only",
			email:   "sa@...com",
			wantID:  "",
			wantName: "",
		},
		{
			name:    "domain_starts_with_dash",
			email:   "sa@-project-123.com",
			wantID:  "123",
			wantName: "-project",
		},
		{
			name:    "all_dashes_domain",
			email:   "sa@----.com",
			wantID:  "",
			wantName: "---",
		},
		{
			name:    "numeric_only_domain",
			email:   "sa@123456789.com",
			wantID:  "123456789",
			wantName: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtAtt := jwt.New()
			if tc.email != nil {
				jwtAtt.Claims = map[string]interface{}{
					"email": tc.email,
				}
			} else {
				jwtAtt.Claims = map[string]interface{}{
					"email": nil,
				}
			}

			// Must not panic
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("parseJWTProjectInfo panicked: %v", r)
					}
				}()

				projID, projName, err := parseJWTProjectInfo(jwtAtt)
				if tc.wantErr {
					assert.Error(t, err)
					if tc.errContain != "" {
						assert.Contains(t, err.Error(), tc.errContain)
					}
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.wantID, projID)
					assert.Equal(t, tc.wantName, projName)
				}
			}()
		})
	}
}

// ============================================================================
// Adversarial: parseJWTProjectInfo with nil Claims map
// ============================================================================

func TestParseJWTProjectInfo_NilClaims(t *testing.T) {
	jwtAtt := jwt.New()
	jwtAtt.Claims = nil

	// Accessing nil map should not panic in Go (returns zero value)
	// But the code does jwt.Claims["email"] which returns nil for nil map
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseJWTProjectInfo panicked with nil Claims: %v", r)
			}
		}()

		_, _, err := parseJWTProjectInfo(jwtAtt)
		assert.Error(t, err, "Should error when Claims is nil")
	}()
}

// ============================================================================
// Adversarial: Subjects() with edge case field values
// ============================================================================

func TestSubjects_EdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		attestor *Attestor
	}{
		{
			name:     "zero_value_attestor",
			attestor: &Attestor{},
		},
		{
			name: "very_long_values",
			attestor: &Attestor{
				InstanceID:       strings.Repeat("a", 10000),
				InstanceHostname: strings.Repeat("b", 10000),
				ProjectID:        strings.Repeat("c", 10000),
				ProjectNumber:    strings.Repeat("d", 10000),
				ClusterUID:       strings.Repeat("e", 10000),
			},
		},
		{
			name: "special_characters",
			attestor: &Attestor{
				InstanceID:       "id\x00with\nnewlines\ttabs",
				InstanceHostname: "host<>\"'&",
				ProjectID:        "proj/../../etc/passwd",
				ProjectNumber:    "12345%00",
				ClusterUID:       "uid\xff\xfe",
			},
		},
		{
			name: "unicode_values",
			attestor: &Attestor{
				InstanceID:       "\u00e9\u00e8\u00ea",
				InstanceHostname: "\u4e16\u754c",
				ProjectID:        "\U0001f600",
				ProjectNumber:    "\u0000",
				ClusterUID:       "\uffff",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Subjects() panicked: %v", r)
					}
				}()

				subjects := tc.attestor.Subjects()
				assert.NotNil(t, subjects)
				assert.Len(t, subjects, 5, "Should always produce 5 subjects")
			}()
		})
	}
}

// ============================================================================
// Adversarial: identityTokenURL injection
// ============================================================================

func TestIdentityTokenURL_InjectionAttempts(t *testing.T) {
	testCases := []struct {
		name           string
		host           string
		serviceAccount string
	}{
		{
			name:           "host_with_path_traversal",
			host:           "evil.com/../../../etc/passwd",
			serviceAccount: "default",
		},
		{
			name:           "host_with_query_params",
			host:           "evil.com?admin=true",
			serviceAccount: "default",
		},
		{
			name:           "service_account_with_slashes",
			host:           "metadata.google.internal",
			serviceAccount: "../../../etc/passwd",
		},
		{
			name:           "empty_host",
			host:           "",
			serviceAccount: "default",
		},
		{
			name:           "empty_service_account",
			host:           "metadata.google.internal",
			serviceAccount: "",
		},
		{
			name:           "unicode_host",
			host:           "\u00e9vil.com",
			serviceAccount: "default",
		},
		{
			name:           "null_bytes",
			host:           "metadata\x00evil.com",
			serviceAccount: "default\x00admin",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("identityTokenURL panicked: %v", r)
					}
				}()

				url := identityTokenURL(tc.host, tc.serviceAccount)
				assert.NotEmpty(t, url)
				// Verify it always contains the expected query parameters
				assert.Contains(t, url, "audience=witness-node-attestor")
				assert.Contains(t, url, "format=full")
			}()
		})
	}
}

// ============================================================================
// Adversarial: Concurrent access to Subjects()
// ============================================================================

func TestSubjects_ConcurrentAccess(t *testing.T) {
	a := &Attestor{
		InstanceID:       "i-1234567890abcdef0",
		InstanceHostname: "my-instance",
		ProjectID:        "my-project-123",
		ProjectNumber:    "123456789",
		ClusterUID:       "cluster-uid-abc",
	}

	// Multiple goroutines calling Subjects() concurrently should not race
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				subjects := a.Subjects()
				assert.NotNil(t, subjects)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// ============================================================================
// Adversarial: ErrNotGCPIIT error type
// ============================================================================

func TestErrNotGCPIIT_Interface(t *testing.T) {
	err := ErrNotGCPIIT{}
	assert.Equal(t, "not a GCP IIT JWT", err.Error())

	// Verify it satisfies error interface
	var e error = err
	assert.NotNil(t, e)

	// Verify it's a distinct type from other errors
	assert.IsType(t, ErrNotGCPIIT{}, err)
}

// ============================================================================
// Adversarial: workload identity path with missing email
// ============================================================================

func TestWorkloadIdentity_MissingEmail(t *testing.T) {
	a := New()
	a.JWT = jwt.New()
	a.JWT.Claims = map[string]interface{}{
		// No "google" claim -> isWorkloadIdentity = true
		// No "email" claim -> parseJWTProjectInfo should error
	}
	a.isWorkloadIdentity = true

	projID, projNum, err := parseJWTProjectInfo(a.JWT)
	assert.Error(t, err)
	assert.Empty(t, projID)
	assert.Empty(t, projNum)
}
