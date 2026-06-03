// Copyright 2025 The Aflock Authors
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
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

func findCheck(r *DoctorReport, name string) *DoctorCheck {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			return &r.Checks[i]
		}
	}
	return nil
}

// TestCheckUploadAuth_SameOriginPasses proves a live session whose platform
// origin matches the Archivista target is reported as upload-authorized.
func TestCheckUploadAuth_SameOriginPasses(t *testing.T) {
	r := &DoctorReport{OK: true}
	cred := &auth.Credential{Token: "abc", TenantName: "acme"}
	checkUploadAuth(r, cred, "https://platform.example.com/archivista", "https://platform.example.com/archivista")
	c := findCheck(r, "upload-auth")
	if c == nil || c.Status != doctorPass {
		t.Fatalf("expected upload-auth pass, got %#v", c)
	}
}

// TestCheckUploadAuth_CrossOriginWarns proves the silent sameOrigin footgun is
// surfaced: a session bound to one origin will be withheld from a different
// Archivista origin.
func TestCheckUploadAuth_CrossOriginWarns(t *testing.T) {
	r := &DoctorReport{OK: true}
	cred := &auth.Credential{Token: "abc", TenantName: "acme"}
	checkUploadAuth(r, cred, "https://other.example.com/archivista", "https://platform.example.com/archivista")
	c := findCheck(r, "upload-auth")
	if c == nil || c.Status != doctorWarn {
		t.Fatalf("expected upload-auth warn on cross-origin, got %#v", c)
	}
	if !strings.Contains(c.Detail, "WITHHELD") {
		t.Errorf("cross-origin detail should warn the bearer is withheld, got %q", c.Detail)
	}
}

// TestCheckUploadAuth_NoSessionWarns proves the two-token trap is named: with
// no session bearer, the upload would 401, and the hint points at cilock login.
func TestCheckUploadAuth_NoSessionWarns(t *testing.T) {
	r := &DoctorReport{OK: true}
	checkUploadAuth(r, nil, "https://platform.example.com/archivista", "https://platform.example.com/archivista")
	c := findCheck(r, "upload-auth")
	if c == nil || c.Status != doctorWarn {
		t.Fatalf("expected upload-auth warn with no session, got %#v", c)
	}
	if !strings.Contains(c.Hint, "cilock login") {
		t.Errorf("hint should point at cilock login, got %q", c.Hint)
	}
}

// TestCheckLoggedIn_ExpiredFails proves an expired session is a hard fail (a
// run would 401), flipping the report rollup.
func TestCheckLoggedIn_ExpiredFails(t *testing.T) {
	r := &DoctorReport{OK: true}
	cred := &auth.Credential{Token: "abc", ExpiresAt: time.Now().Add(-time.Hour)}
	checkLoggedIn(r, "https://platform.example.com", cred, nil)
	c := findCheck(r, "logged-in")
	if c == nil || c.Status != doctorFail {
		t.Fatalf("expected logged-in fail on expired session, got %#v", c)
	}
	if r.OK {
		t.Errorf("report rollup should be NOT ok after a failed check")
	}
}

// TestCheckUploadAuth_ExpiredWarns proves an expired session bearer is NOT
// reported as upload-authorized. An expired token 401s at /archivista/upload
// exactly like a missing one, so checkUploadAuth must not fall through to pass
// just because cred != nil && cred.Token != "".
func TestCheckUploadAuth_ExpiredWarns(t *testing.T) {
	r := &DoctorReport{OK: true}
	cred := &auth.Credential{Token: "abc", TenantName: "acme", ExpiresAt: time.Now().Add(-time.Hour)}
	checkUploadAuth(r, cred, "https://platform.example.com/archivista", "https://platform.example.com/archivista")
	c := findCheck(r, "upload-auth")
	if c == nil || c.Status != doctorWarn {
		t.Fatalf("expected upload-auth warn on expired session, got %#v", c)
	}
	if !strings.Contains(c.Hint, "cilock login") {
		t.Errorf("hint should point at cilock login, got %q", c.Hint)
	}
}

// TestReportAdd_FailFlipsRollup proves the OK rollup an agent gates on flips
// false on any fail and stays true otherwise.
func TestReportAdd_FailFlipsRollup(t *testing.T) {
	r := &DoctorReport{OK: true}
	r.add(DoctorCheck{Name: "a", Status: doctorPass})
	r.add(DoctorCheck{Name: "b", Status: doctorWarn})
	if !r.OK {
		t.Errorf("warn must not flip the rollup")
	}
	r.add(DoctorCheck{Name: "c", Status: doctorFail})
	if r.OK {
		t.Errorf("fail must flip the rollup to false")
	}
}

// TestWriteDoctorJSON_WellFormed proves the JSON report is a single object an
// agent can gate on via report.ok.
func TestWriteDoctorJSON_WellFormed(t *testing.T) {
	r := &DoctorReport{PlatformURL: "https://p.example.com", OK: true}
	r.add(DoctorCheck{Name: "logged-in", Status: doctorPass, Detail: "ok"})
	var buf bytes.Buffer
	if err := writeDoctorJSON(&buf, r); err != nil {
		t.Fatalf("writeDoctorJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	if _, ok := got["ok"]; !ok {
		t.Errorf("report must carry an 'ok' rollup key")
	}
	if _, ok := got["checks"]; !ok {
		t.Errorf("report must carry a 'checks' array")
	}
}
