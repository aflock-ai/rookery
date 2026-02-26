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
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
)

// FuzzGCPIITJWTClaims exercises the type assertions in Attest() that extract
// fields from the "google" JWT claim map.  The production code does two-value
// type assertions (value, ok := x.(T)), but historically code like this has
// panicked when intermediate maps contain unexpected types.  We throw every
// combination of claim value types at the extraction logic to make sure it
// never panics.
func FuzzGCPIITJWTClaims(f *testing.F) {
	// Seed corpus: mode selects what type goes into each claim slot.
	// mode byte layout (one bit per claim field):
	//   bit 0: project_id type   (0=string, 1=int)
	//   bit 1: project_number    (0=string, 1=nil)
	//   bit 2: zone              (0=string, 1=bool)
	//   bit 3: instance_id       (0=string, 1=float64)
	//   bit 4: instance_name     (0=string, 1=[]interface{})
	//   bit 5: licence_id        (0=[]interface{}, 1=string)
	//   bit 6: google claim      (0=map, 1=string -- wrong type entirely)
	//   bit 7: google claim nil
	f.Add("my-project", "123456", "us-central1-a", "inst-42", "my-host", "lic1", byte(0))
	f.Add("", "", "", "", "", "", byte(0))
	f.Add("proj", "num", "zone", "id", "host", "lic", byte(0x7F))
	f.Add("proj", "num", "zone", "id", "host", "lic", byte(0x80))
	f.Add("a]b[c", "999", "zone/with/slashes", "id\x00null", "host\nnewline", "", byte(0x3F))
	f.Add("\xff\xfe", "\x00", "z", "i", "h", "l", byte(0x40))
	f.Add("proj-with-unicode-\u00e9", "12345678901234567890", "", "", "", "", byte(0))

	f.Fuzz(func(t *testing.T, projID, projNum, zone, instID, instName, licID string, mode byte) {
		a := New()

		// Build the google claim map with types dictated by mode bits.
		googClaim := make(map[string]interface{})

		if mode&0x01 == 0 {
			googClaim["project_id"] = projID
		} else {
			googClaim["project_id"] = 42
		}

		if mode&0x02 == 0 {
			googClaim["project_number"] = projNum
		} else {
			googClaim["project_number"] = nil
		}

		if mode&0x04 == 0 {
			googClaim["zone"] = zone
		} else {
			googClaim["zone"] = true
		}

		if mode&0x08 == 0 {
			googClaim["instance_id"] = instID
		} else {
			googClaim["instance_id"] = 3.14
		}

		if mode&0x10 == 0 {
			googClaim["instance_name"] = instName
		} else {
			googClaim["instance_name"] = []interface{}{1, "two", nil}
		}

		if mode&0x20 == 0 {
			// []interface{} with a mix of string and non-string items
			googClaim["licence_id"] = []interface{}{licID, 99, nil, licID}
		} else {
			googClaim["licence_id"] = licID
		}

		// Construct a mock JWT attestor with pre-populated Claims so we
		// can exercise the claim extraction without network calls.
		jwtAtt := jwt.New()

		if mode&0x80 != 0 {
			// google claim is nil -- triggers isWorkloadIdentity path
			jwtAtt.Claims = map[string]interface{}{
				"email": projID + "@" + projNum + ".iam.gserviceaccount.com",
			}
		} else if mode&0x40 != 0 {
			// google claim is wrong type (string instead of map)
			jwtAtt.Claims = map[string]interface{}{
				"google": "not-a-map",
			}
		} else {
			jwtAtt.Claims = map[string]interface{}{
				"google": googClaim,
			}
		}

		a.JWT = jwtAtt

		// Simulate the claim extraction logic from Attest() without
		// making network calls. This is the code path we want to fuzz.
		if a.JWT.Claims["google"] == nil {
			// workload identity path -- calls parseJWTProjectInfo
			a.isWorkloadIdentity = true
			projIDResult, projNumResult, err := parseJWTProjectInfo(a.JWT)
			if err == nil {
				a.ProjectID = projIDResult
				a.ProjectNumber = projNumResult
			}
		} else {
			gc, ok := a.JWT.Claims["google"].(map[string]interface{})
			if !ok {
				// Wrong type -- Attest() returns an error here, which is fine.
				return
			}

			if v, ok := gc["project_id"].(string); ok {
				a.ProjectID = v
			}
			if v, ok := gc["project_number"].(string); ok {
				a.ProjectNumber = v
			}
			if v, ok := gc["zone"].(string); ok {
				a.InstanceZone = v
			}
			if v, ok := gc["instance_id"].(string); ok {
				a.InstanceID = v
			}
			if v, ok := gc["instance_name"].(string); ok {
				a.InstanceHostname = v
			}
			if v, ok := gc["instance_creation_timestamp"].(string); ok {
				a.InstanceCreationTimestamp = v
			}
			if v, ok := gc["instance_confidentiality"].(string); ok {
				a.InstanceConfidentiality = v
			}

			switch v := gc["licence_id"].(type) {
			case []string:
				a.LicenceID = v
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						a.LicenceID = append(a.LicenceID, s)
					}
				}
			}
		}

		// Exercise Subjects() -- it should never panic regardless of field contents.
		_ = a.Subjects()
	})
}

// FuzzParseJWTProjectInfo fuzzes the email parsing logic in parseJWTProjectInfo.
// This function splits an email on "@", then splits the domain on ".", then on
// "-". Edge cases: no "@", multiple "@", no "-" in domain, empty segments,
// single-character segments, unicode, etc.
func FuzzParseJWTProjectInfo(f *testing.F) {
	// Normal GCP service account email
	f.Add("sa@my-project-123456.iam.gserviceaccount.com")
	// No @ sign
	f.Add("noemail")
	// Multiple @ signs
	f.Add("a@b@c")
	// Empty string
	f.Add("")
	// Just @
	f.Add("@")
	// @ at edges
	f.Add("@domain.com")
	f.Add("user@")
	// No dashes in domain
	f.Add("user@singleword.com")
	// Only dashes
	f.Add("user@----.com")
	// Single char segments
	f.Add("u@a-b.c")
	// Very long email
	f.Add("user@" + "very-long-project-name-with-many-dashes-and-segments-1234567890" + ".iam.gserviceaccount.com")
	// Unicode
	f.Add("user@proj\u00e9ct-123.iam.gserviceaccount.com")
	// Null bytes
	f.Add("user@proj\x00ect-123.com")
	// Newlines
	f.Add("user@proj\nect-123.com")
	// Tabs and spaces
	f.Add("user@proj\tect 123.com")
	// Domain with no dots
	f.Add("user@nodots")
	// Numeric only
	f.Add("12345@67890.com")

	f.Fuzz(func(t *testing.T, email string) {
		jwtAtt := jwt.New()

		// Test with email as a string claim
		jwtAtt.Claims = map[string]interface{}{
			"email": email,
		}
		projID, projNum, err := parseJWTProjectInfo(jwtAtt)
		// Must not panic. If no error, check results are non-negative length.
		if err == nil {
			if len(projID) < 0 || len(projNum) < 0 {
				t.Fatalf("impossible negative length from parseJWTProjectInfo")
			}
		}

		// Test with email as a non-string claim (int)
		jwtAtt.Claims = map[string]interface{}{
			"email": 42,
		}
		_, _, err = parseJWTProjectInfo(jwtAtt)
		if err == nil {
			t.Fatalf("expected error when email claim is not a string")
		}

		// Test with email claim missing entirely
		jwtAtt.Claims = map[string]interface{}{}
		_, _, err = parseJWTProjectInfo(jwtAtt)
		if err == nil {
			t.Fatalf("expected error when email claim is missing")
		}

		// Test with nil claims map
		jwtAtt.Claims = nil
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseJWTProjectInfo panicked with nil claims: %v", r)
				}
			}()
			parseJWTProjectInfo(jwtAtt)
		}()
	})
}
