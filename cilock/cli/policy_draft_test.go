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

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// draftReqWire mirrors the platform hydration request on the wire. It is
// declared in the test (rather than reusing the implementation's type) so a
// rename in the implementation cannot silently change what the contract test
// asserts.
type draftReqWire struct {
	Version     string `json:"version"`
	PayloadType string `json:"payload_type"`
	Source      string `json:"source"`
}

// draftRespWire mirrors the platform hydration response on the wire.
type draftRespWire struct {
	Version             string            `json:"version"`
	TenantID            string            `json:"tenant_id"`
	SourceSHA256        string            `json:"source_sha256"`
	HydratedSource      string            `json:"hydrated_source,omitempty"`
	HydratedSHA256      string            `json:"hydrated_sha256,omitempty"`
	Valid               bool              `json:"valid"`
	Errors              []string          `json:"errors"`
	EnforcementEligible bool              `json:"enforcement_eligible"`
	Summary             *draftSummaryWire `json:"summary,omitempty"`
}

// draftSummaryWire mirrors the platform's authoring-feedback summary.
type draftSummaryWire struct {
	Requirements []draftRequirementWire `json:"requirements"`
	Expires      string                 `json:"expires,omitempty"`
	Identity     []string               `json:"identity"`
	Trust        []string               `json:"trust"`
	Gaps         []string               `json:"gaps"`
}

type draftRequirementWire struct {
	Kind            string `json:"kind"`
	Step            string `json:"step"`
	AttestationType string `json:"attestation_type"`
	RegoPolicyCount int    `json:"rego_policy_count"`
	AIPolicyCount   int    `json:"ai_policy_count"`
}

// draftFake is an httptest stand-in for the platform's hydration endpoint. It
// records what the CLI sent and replies with whatever the test wired up.
type draftFake struct {
	*httptest.Server
	hits    int
	gotAuth string
	gotPath string
	gotReq  draftReqWire
}

// newDraftFake serves POST /api/pushgate/policies/hydrate. reply is handed the
// decoded request and returns the status + body to send back.
func newDraftFake(t *testing.T, reply func(req draftReqWire) (int, draftRespWire)) *draftFake {
	t.Helper()
	f := &draftFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/pushgate/policies/hydrate", func(w http.ResponseWriter, r *http.Request) {
		f.hits++
		f.gotAuth = r.Header.Get("Authorization")
		f.gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&f.gotReq); err != nil {
			t.Errorf("decode hydration request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		status, body := reply(f.gotReq)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// draftSHA256 is the digest the platform is contractually supposed to return
// for hydrated_source — and the one the CLI must recompute for itself.
func draftSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// writeDraftSource writes a hand-authored (unsigned, trust-root-free) policy
// source and returns its path.
func writeDraftSource(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.json")
	src := `{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build"}}}`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return path
}

// okHydration builds the success response for a given hydrated document.
func okHydration(req draftReqWire, hydrated string) draftRespWire {
	return draftRespWire{
		Version:        "pushgate.policy-hydration.v1",
		TenantID:       "tenant-9",
		SourceSHA256:   draftSHA256(req.Source),
		HydratedSource: hydrated,
		HydratedSHA256: draftSHA256(hydrated),
		Valid:          true,
		Errors:         []string{},
	}
}

func TestPolicyDraft_WritesHydratedPolicyByteExact(t *testing.T) {
	const hydrated = `{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build"}},"roots":{"platform":{"certificate":"BASE64"}},"timestampauthorities":{"tsa":{"certificate":"BASE64"}}}`

	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated)
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	source := writeDraftSource(t, dir)
	out := filepath.Join(dir, "hydrated.json")
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("precondition: output %s must not exist, stat err = %v", out, err)
	}

	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", source, "-o", out, "--platform-url", fake.URL)
	if err != nil {
		t.Fatalf("draft: %v\noutput:\n%s", err, stdout)
	}

	got, err := os.ReadFile(out) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read hydrated output: %v", err)
	}
	if string(got) != hydrated {
		t.Errorf("hydrated output not byte-exact:\n got %q\nwant %q", got, hydrated)
	}

	// The command must never sign: the artifact it writes is the raw hydrated
	// document, not a DSSE envelope.
	if strings.Contains(string(got), `"signatures"`) || strings.Contains(string(got), `"payloadType"`) {
		t.Errorf("draft wrote something that looks signed; signing is human-only:\n%s", got)
	}

	// Request contract.
	if fake.hits != 1 {
		t.Errorf("hydration endpoint hits = %d, want 1", fake.hits)
	}
	if fake.gotAuth != "Bearer test-session-token" {
		t.Errorf("Authorization = %q, want the login-session bearer", fake.gotAuth)
	}
	if fake.gotPath != "/api/pushgate/policies/hydrate" {
		t.Errorf("path = %q, want /api/pushgate/policies/hydrate", fake.gotPath)
	}
	if fake.gotReq.Version != "pushgate.policy-hydration.v1" {
		t.Errorf("request version = %q", fake.gotReq.Version)
	}
	if fake.gotReq.PayloadType != policy.PolicyPredicate {
		t.Errorf("request payload_type = %q, want %q", fake.gotReq.PayloadType, policy.PolicyPredicate)
	}
	srcBytes, err := os.ReadFile(source) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if fake.gotReq.Source != string(srcBytes) {
		t.Errorf("request source = %q, want the file contents %q", fake.gotReq.Source, srcBytes)
	}

	// Next steps: exactly the human-only sign, then push. Never a signature.
	// Shell-quoted, because these lines are advertised as the exact commands to
	// paste. An unquoted path with a space becomes two arguments.
	wantSign := "cilock sign -f " + shellQuote(out) +
		" -o " + shellQuote(strings.TrimSuffix(out, ".json")+".signed.json") +
		" -t " + shellQuote(policy.PolicyPredicate)
	if !strings.Contains(stdout, wantSign) {
		t.Errorf("missing sign next-step %q in:\n%s", wantSign, stdout)
	}
	if !strings.Contains(stdout, "cilock policy push -f ") {
		t.Errorf("missing push next-step in:\n%s", stdout)
	}
	if !strings.Contains(stdout, "-d <definition>") || !strings.Contains(stdout, "-t <tag>") {
		t.Errorf("push next-step must name -d <definition> and -t <tag>; got:\n%s", stdout)
	}
	if !strings.Contains(strings.ToLower(stdout), "sign") ||
		!strings.Contains(strings.ToLower(stdout), "you") {
		t.Errorf("next steps must say signing is left to the human; got:\n%s", stdout)
	}
}

func TestPolicyDraft_DefaultsOutputNextToSource(t *testing.T) {
	const hydrated = `{"hydrated":true}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated)
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	source := writeDraftSource(t, dir) // <dir>/policy.json
	want := filepath.Join(dir, "policy.hydrated.json")

	if _, err := runCmd(t, PolicyDraftCmd(), "-f", source, "--platform-url", fake.URL); err != nil {
		t.Fatalf("draft: %v", err)
	}
	got, err := os.ReadFile(want) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("default output %s not written: %v", want, err)
	}
	if string(got) != hydrated {
		t.Errorf("default output = %q, want %q", got, hydrated)
	}
}

func TestPolicyDraft_RefusalPrintsErrorsAndWritesNothing(t *testing.T) {
	fake := newDraftFake(t, func(_ draftReqWire) (int, draftRespWire) {
		return http.StatusOK, draftRespWire{
			Version:      "pushgate.policy-hydration.v1",
			TenantID:     "tenant-9",
			SourceSHA256: "deadbeef",
			Valid:        false,
			Errors: []string{
				"step \"build\": no functionaries",
				"expires: must be in the future",
			},
		}
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	source := writeDraftSource(t, dir)
	out := filepath.Join(dir, "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", source, "-o", out, "--platform-url", fake.URL)
	if err == nil {
		t.Fatalf("want nonzero exit on valid:false; got nil error. output:\n%s", stdout)
	}
	combined := stdout + "\n" + err.Error()
	for _, want := range []string{`step "build": no functionaries`, "expires: must be in the future"} {
		if !strings.Contains(combined, want) {
			t.Errorf("server error %q not surfaced; got:\n%s", want, combined)
		}
	}
	// Each error on its own line.
	for _, line := range strings.Split(combined, "\n") {
		if strings.Contains(line, "no functionaries") && strings.Contains(line, "must be in the future") {
			t.Errorf("server errors were collapsed onto one line: %q", line)
		}
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("refused hydration must write nothing, but %s exists (stat err %v)", out, statErr)
	}
}

func TestPolicyDraft_DigestMismatchRefusesAndWritesNothing(t *testing.T) {
	const hydrated = `{"hydrated":"tampered"}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		resp := okHydration(req, hydrated)
		// The platform claims a digest that is NOT sha256(hydrated_source) —
		// the body was swapped in flight, or the server is lying.
		resp.HydratedSHA256 = draftSHA256("something else entirely")
		return http.StatusOK, resp
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	source := writeDraftSource(t, dir)
	out := filepath.Join(dir, "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", source, "-o", out, "--platform-url", fake.URL)
	if err == nil {
		t.Fatalf("want refusal on hydrated_sha256 mismatch; got nil. output:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "sha256") && !strings.Contains(err.Error(), "digest") {
		t.Errorf("error should name the digest mismatch; got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("digest mismatch must write nothing, but %s exists", out)
	}
}

func TestPolicyDraft_ExistingOutputRequiresForce(t *testing.T) {
	const hydrated = `{"hydrated":true}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated)
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	source := writeDraftSource(t, dir)
	out := filepath.Join(dir, "hydrated.json")
	const existing = "DO NOT CLOBBER ME"
	if err := os.WriteFile(out, []byte(existing), 0o600); err != nil {
		t.Fatalf("seed existing output: %v", err)
	}

	_, err := runCmd(t, PolicyDraftCmd(), "-f", source, "-o", out, "--platform-url", fake.URL)
	if err == nil {
		t.Fatal("want refusal when --output already exists without --force")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error should name --force as the remedy; got %v", err)
	}
	got, readErr := os.ReadFile(out) //nolint:gosec // test temp path
	if readErr != nil {
		t.Fatalf("read output: %v", readErr)
	}
	if string(got) != existing {
		t.Errorf("existing output was clobbered: %q", got)
	}

	// With --force the same invocation succeeds and overwrites.
	if _, err := runCmd(t, PolicyDraftCmd(),
		"-f", source, "-o", out, "--platform-url", fake.URL, "--force"); err != nil {
		t.Fatalf("--force should overwrite: %v", err)
	}
	got, readErr = os.ReadFile(out) //nolint:gosec // test temp path
	if readErr != nil {
		t.Fatalf("read output after --force: %v", readErr)
	}
	if string(got) != hydrated {
		t.Errorf("--force output = %q, want %q", got, hydrated)
	}
}

func TestPolicyDraft_NotLoggedInNamesCilockLogin(t *testing.T) {
	// Isolated empty store → no session for the platform.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))

	source := writeDraftSource(t, dir)
	out := filepath.Join(dir, "hydrated.json")

	_, err := runCmd(t, PolicyDraftCmd(),
		"-f", source, "-o", out, "--platform-url", "https://platform.example.test")
	if err == nil {
		t.Fatal("want an error when there is no session")
	}
	if !strings.Contains(err.Error(), "cilock login") {
		t.Errorf("error must name `cilock login`; got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("no-session run must write nothing, but %s exists", out)
	}
}

func TestPolicyDraft_MissingSourceFileErrors(t *testing.T) {
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, `{}`)
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	_, err := runCmd(t, PolicyDraftCmd(),
		"-f", filepath.Join(dir, "nope.json"), "--platform-url", fake.URL)
	if err == nil {
		t.Fatal("want an error for a missing source file")
	}
	if fake.hits != 0 {
		t.Errorf("must not call the platform when the source is unreadable; hits = %d", fake.hits)
	}
}

func TestPolicyDraft_RegisteredUnderPolicy(t *testing.T) {
	var found bool
	for _, c := range PolicyCmd().Commands() {
		if c.Name() == "draft" {
			found = true
		}
	}
	if !found {
		t.Error("`draft` is not registered under `cilock policy`")
	}
}

// The draft loop's whole point is feedback: `errors` says what the author got
// wrong, the summary says what the policy they wrote actually DOES. Both must
// reach the operator, and the gaps must be prominent — they are the actionable
// half an agent iterates against.
func TestPolicyDraft_RendersWhatThePolicyDoes(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z","roots":{"fulcio-root":{}}}`

	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		resp := okHydration(req, hydrated)
		resp.Summary = &draftSummaryWire{
			Requirements: []draftRequirementWire{{
				Kind:            "step_attestation",
				Step:            "push-tests",
				AttestationType: "https://aflock.ai/attestations/git/v0.1",
				RegoPolicyCount: 2,
			}},
			Expires:  "2027-01-01T00:00:00Z",
			Identity: []string{`step "push-tests" functionary 0: certificate under root fulcio-root; UNCONSTRAINED emails`},
			Trust:    []string{`root "fulcio-root": platform-injected`},
			Gaps:     []string{`step "push-tests" functionary 0 accepts any emails — anyone the root will vouch for satisfies it`},
		}
		return http.StatusOK, resp
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", filepath.Join(dir, "h.json"), "--platform-url", fake.URL)
	if err != nil {
		t.Fatalf("draft: %v\noutput:\n%s", err, stdout)
	}

	for _, want := range []string{
		"What this policy does:",
		"push-tests",
		"https://aflock.ai/attestations/git/v0.1",
		"2 rego rule(s)",
		"expires: 2027-01-01T00:00:00Z",
		"UNCONSTRAINED emails",
		"platform-injected",
		"Gaps",
		"anyone the root will vouch for",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("summary output is missing %q; a draft loop that hides this cannot be iterated against\n%s", want, stdout)
		}
	}
}

// An older platform sends no summary. That is not an error, and it must not
// render an empty or fabricated section.
func TestPolicyDraft_ToleratesAPlatformWithNoSummary(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`

	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated) // no Summary
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", filepath.Join(dir, "h.json"), "--platform-url", fake.URL)
	if err != nil {
		t.Fatalf("draft: %v\noutput:\n%s", err, stdout)
	}
	if strings.Contains(stdout, "What this policy does:") {
		t.Errorf("rendered a summary section with no summary in the response:\n%s", stdout)
	}
	if !strings.Contains(stdout, "hydrated") {
		t.Errorf("the success path must still report normally:\n%s", stdout)
	}
}

// THE NEXT-STEP LINES ARE ADVERTISED AS COMMANDS TO PASTE, so every value
// interpolated into them is attacker-influenced whenever the filename is —
// --output is caller-chosen and the signed path is derived from it.
//
// Unquoted, a path containing a space silently becomes two arguments, and one
// containing $(...), a backtick or a semicolon EXECUTES when the operator does
// what the output tells them to do.
func TestPolicyDraft_NextStepCommandsQuoteHostileFilenames(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated)
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	hostile := filepath.Join(dir, "a b; touch $(whoami)`id`.json")

	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", hostile, "--platform-url", fake.URL)
	if err != nil {
		t.Fatalf("draft: %v\n%s", err, stdout)
	}

	// The whole path arrives inside one single-quoted literal, which is the only
	// POSIX form with no escapes inside it.
	if !strings.Contains(stdout, shellQuote(hostile)) {
		t.Errorf("the output path is not shell-quoted in the next steps:\n%s", stdout)
	}
	// And no metacharacter is left bare for the shell to act on.
	for _, line := range strings.Split(stdout, "\n") {
		if !strings.Contains(line, "cilock sign") && !strings.Contains(line, "cilock policy push") {
			continue
		}
		for _, bad := range []string{"$(", "`"} {
			if idx := strings.Index(line, bad); idx >= 0 {
				before := line[:idx]
				if strings.Count(before, "'")%2 == 0 {
					t.Errorf("%q appears OUTSIDE quotes in a copyable command: %s", bad, line)
				}
			}
		}
	}
}

// A VERSION THIS BUILD CANNOT INTERPRET MUST STOP THE WRITE, not warn about it.
//
// The command goes on to write a document FOR SIGNING from fields whose meaning
// the contract defines. A warning on stderr does not stop that, so under a
// changed contract the operator is handed a policy to sign that this build read
// wrongly, with one line of stderr as the only clue. Absence is refused for the
// same reason: no version is not agreement.
func TestPolicyDraft_RefusesAContractVersionItCannotInterpret(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`
	for name, version := range map[string]string{
		"unknown version": "pushgate.policy-hydration.v2",
		"absent version":  "",
	} {
		t.Run(name, func(t *testing.T) {
			fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
				resp := okHydration(req, hydrated)
				resp.Version = version
				return http.StatusOK, resp
			})
			stubSession(t, fake.URL)

			dir := t.TempDir()
			out := filepath.Join(dir, "h.json")
			stdout, err := runCmd(t, PolicyDraftCmd(),
				"-f", writeDraftSource(t, dir), "-o", out, "--platform-url", fake.URL)
			if err == nil {
				t.Fatalf("a hydration contract this build cannot interpret must be refused:\n%s", stdout)
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Error("a refused hydration must write nothing at all")
			}
		})
	}
}

// The hydrated digest only proves the response agrees with ITSELF. A stale or
// misrouted answer carrying its own matching pair passes that check while
// describing a DIFFERENT policy — which is then written for a human to sign.
// Recomputing the SOURCE hash binds the answer to the question asked.
func TestPolicyDraft_RefusesAResponseAboutADifferentSource(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		resp := okHydration(req, hydrated)
		// Self-consistent, but about somebody else's source.
		resp.SourceSHA256 = draftSHA256("a completely different policy document")
		return http.StatusOK, resp
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	out := filepath.Join(dir, "h.json")
	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", out, "--platform-url", fake.URL)
	if err == nil {
		t.Fatalf("a response echoing a different source digest must be refused:\n%s", stdout)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Error("a refused hydration must write nothing at all")
	}
}

// Without --force the create is EXCLUSIVE: a stat followed by WriteFile is a
// race, and a file — or a symlink pointing elsewhere — created in the gap gets
// truncated, breaking the no-clobber promise exactly when something is
// competing for the path.
func TestPolicyDraft_NoClobberDoesNotFollowASymlink(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated)
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.json")
	if err := os.WriteFile(victim, []byte("PRECIOUS"), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", link, "--platform-url", fake.URL)
	if err == nil {
		t.Fatalf("writing through an existing symlink without --force must be refused:\n%s", stdout)
	}
	got, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("read victim: %v", readErr)
	}
	if string(got) != "PRECIOUS" {
		t.Errorf("the symlink target was clobbered: %q", got)
	}
}

// The digest checks are about the policy BYTES. Hydration is the step that
// injects a TENANT's roots, timestamp authorities and Fulcio chain, so the same
// source hydrated for a different tenant yields a response that satisfies both
// digests while carrying somebody else's trust into a document a human signs.
// The trust set is the one part of a hydrated policy a reviewer cannot check
// against their own source file, which is why this has to be refused here.
func TestPolicyDraft_RefusesAResponseHydratedForAnotherTenant(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		resp := okHydration(req, hydrated)
		// Same source, both digests correct — only the tenant differs.
		resp.TenantID = "tenant-attacker"
		return http.StatusOK, resp
	})
	stubSession(t, fake.URL) // session is authenticated for tenant-9

	dir := t.TempDir()
	out := filepath.Join(dir, "h.json")
	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", out, "--platform-url", fake.URL)
	if err == nil {
		t.Fatalf("a policy hydrated for another tenant must be refused:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "tenant-attacker") || !strings.Contains(err.Error(), "tenant-9") {
		t.Errorf("the refusal must name both tenants so an operator can tell what happened: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Error("a refused hydration must write nothing at all")
	}
}

// Absence is not agreement. A response that declines to say which tenant it
// belongs to cannot be attributed, and unattributed trust material is exactly
// what the check above exists to stop — so an empty tenant is refused rather
// than waved through.
func TestPolicyDraft_RefusesAResponseWithNoTenant(t *testing.T) {
	const hydrated = `{"expires":"2027-01-01T00:00:00Z"}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		resp := okHydration(req, hydrated)
		resp.TenantID = ""
		return http.StatusOK, resp
	})
	stubSession(t, fake.URL)

	dir := t.TempDir()
	out := filepath.Join(dir, "h.json")
	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", out, "--platform-url", fake.URL)
	if err == nil {
		t.Fatalf("a hydration response naming no tenant must be refused:\n%s", stdout)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Error("a refused hydration must write nothing at all")
	}
}

// The hydration request carries the login-session bearer, and Go's DEFAULT
// client follows 30x while re-sending the Authorization header to wherever the
// redirect points. A cross-origin hop — another host, a sibling subdomain, a
// different port, or an HTTPS-to-HTTP downgrade — would hand the session to
// whoever answers there, along with the policy source in the request body.
//
// The assertion that matters is not merely "the command failed": it is that the
// redirect TARGET never saw a credential.
func TestPolicyDraft_RefusesARedirectAndLeaksNoBearer(t *testing.T) {
	var targetAuth string
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		targetAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(target.Close)

	// A different origin than the session platform, which is what makes this a
	// bearer-leaking hop rather than a benign same-host path change.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/pushgate/policies/hydrate", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	stubSession(t, redirector.URL)

	dir := t.TempDir()
	out := filepath.Join(dir, "h.json")
	stdout, err := runCmd(t, PolicyDraftCmd(),
		"-f", writeDraftSource(t, dir), "-o", out, "--platform-url", redirector.URL)
	if err == nil {
		t.Fatalf("a cross-origin redirect must be refused, not followed:\n%s", stdout)
	}
	if targetHits != 0 {
		t.Errorf("the redirect target was contacted %d time(s); it must never be reached", targetHits)
	}
	if targetAuth != "" {
		t.Errorf("the redirect target received an Authorization header (%q) — the session bearer leaked", targetAuth)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Error("a refused hydration must write nothing at all")
	}
}

// The CheckRedirect the hydration client installs, exercised directly against
// the exact vectors that leak a bearer. The end-to-end test above proves the
// wiring; this proves the POLICY, including the two cases an httptest pair
// cannot reach — a real subdomain and an HTTPS-to-HTTP downgrade.
//
// Each case is a redirect Go would otherwise follow while re-sending
// Authorization, because Go strips that header only on a cross-HOST redirect
// and treats a scheme downgrade or a port change as same-host.
func TestPolicyDraftRedirectPolicyRefusesBearerLeakingHops(t *testing.T) {
	const origin = "https://platform.testifysec.com/api/pushgate/policies/hydrate"

	refused := []struct {
		name string
		to   string
	}{
		{"https-to-http downgrade on the same host", "http://platform.testifysec.com/x"},
		{"a sibling subdomain", "https://evil.testifysec.com/x"},
		{"a different port on the same host", "https://platform.testifysec.com:8443/x"},
		{"an unrelated host", "https://attacker.example/x"},
		{"cloud metadata by IP literal", "https://169.254.169.254/latest/meta-data/"},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			via, err := http.NewRequest(http.MethodPost, origin, nil)
			if err != nil {
				t.Fatalf("build original request: %v", err)
			}
			next, err := http.NewRequest(http.MethodGet, tc.to, nil)
			if err != nil {
				t.Fatalf("build redirect request: %v", err)
			}
			if err := config.SameOriginRedirect(next, []*http.Request{via}); err == nil {
				t.Fatalf("redirect to %s must be refused — the session bearer would follow it", tc.to)
			}
		})
	}

	// The control. A same-origin hop is not a leak, and refusing it would break
	// a platform that legitimately redirects between its own paths.
	t.Run("allows a same-origin path change", func(t *testing.T) {
		via, err := http.NewRequest(http.MethodPost, origin, nil)
		if err != nil {
			t.Fatalf("build original request: %v", err)
		}
		next, err := http.NewRequest(http.MethodGet, "https://platform.testifysec.com/api/v2/hydrate", nil)
		if err != nil {
			t.Fatalf("build redirect request: %v", err)
		}
		if err := config.SameOriginRedirect(next, []*http.Request{via}); err != nil {
			t.Errorf("a same-origin redirect must be allowed: %v", err)
		}
	})
}
