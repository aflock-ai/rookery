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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	attpolicy "github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/canonicaljson"
	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// A policy draft is handled as decoded JSON (maps, slices, json.Number), never
// through the typed policy struct: template and prove must leave every field
// they do not own byte-for-byte as the agent wrote it, including fields a
// newer cilock knows and this one does not. Only the blocks each command owns
// (a new step, the trust placeholders, a filled slot) are rewritten.

type draftDoc = map[string]any

// Draft keys template writes more than once.
const (
	draftKeyName = "name"
	draftKeyType = "type"
)

func loadDraft(path string) (draftDoc, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the agent names its own draft
	if err != nil {
		return nil, err
	}
	// The decoder keeps a repeated key's last value, so an edit would drop
	// what the first one held and the save would hide that it ever existed.
	if err := canonicaljson.RejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("%s: %w. Next: keep one of the two members, then retry", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc draftDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s is not a JSON policy object: %w", path, err)
	}
	if doc == nil {
		return nil, fmt.Errorf("%s is not a JSON policy object", path)
	}
	// Every edit reads and rewrites steps as an object; anything else there
	// is the author's, and an edit would replace it.
	if v, ok := doc["steps"]; ok {
		if _, isObject := v.(map[string]any); !isObject {
			return nil, fmt.Errorf("%s: steps is not an object (a JSON map of step name to step); nothing was changed", path)
		}
	}
	// The draft is read untyped, so a value of the wrong kind (a rego module
	// written as a bare string) would otherwise read as "no rule" here and
	// fail only later, in the verifier's typed decode. Name it now.
	if shape := attpolicy.ShapeErrors(raw); len(shape) > 0 {
		return nil, fmt.Errorf("%s: %s", path, strings.Join(shape, "; "))
	}
	return doc, nil
}

func encodeDraft(doc draftDoc) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// saveDraft writes the draft at path in one step. Replacing: the bytes go
// to a temporary file beside it and are renamed over it only once fully
// written, so a write that cannot complete (a full disk, a lost mount)
// leaves the draft the agent had, never a truncated one. Creating
// (exclusive): the file is created at the filesystem only if nothing is
// there, so two creators racing past an existence check cannot replace
// each other's draft; a write that cannot complete removes what it began.
func saveDraft(path string, doc draftDoc, exclusive bool) error {
	raw, err := encodeDraft(doc)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if exclusive {
		return createDraft(path, raw)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("save %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after a rename; cleans up after a failure
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("save %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("save %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("save %s: %w", path, err)
	}
	return nil
}

// createDraft writes raw to a file that must not exist yet. The exclusive
// create is the filesystem's; a write that cannot complete removes the file
// it began, which was nobody's draft.
func createDraft(path string, raw []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the agent names its own draft
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			err = fmt.Errorf("create %s: %w", path, err)
		}
	}()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func draftSteps(doc draftDoc) map[string]any {
	steps, _ := doc["steps"].(map[string]any)
	return steps
}

func sortedStepNames(doc draftDoc) []string {
	steps := draftSteps(doc)
	names := make([]string, 0, len(steps))
	for n := range steps {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// stepAttestationTypes returns the predicate types a step requires, in order.
func stepAttestationTypes(step map[string]any) []string {
	var out []string
	for _, a := range asList(step["attestations"]) {
		if t, ok := asMap(a)[draftKeyType].(string); ok {
			out = append(out, t)
		}
	}
	return out
}

// stepModules decodes every rego module of one attestation type in a step.
// A module that is still a fill slot or not base64 is skipped: prove refuses
// slots before it reads modules, and validate names bad base64.
func stepModules(step map[string]any, predicateType string) []string {
	var out []string
	for _, a := range asList(step["attestations"]) {
		att := asMap(a)
		if att[draftKeyType] != predicateType {
			continue
		}
		for _, r := range asList(att["regopolicies"]) {
			mod, _ := asMap(r)["module"].(string)
			if mod == "" || strings.HasPrefix(mod, fillMarker) {
				continue
			}
			src, err := base64.StdEncoding.DecodeString(mod)
			if err != nil {
				continue
			}
			out = append(out, string(src))
		}
	}
	return out
}

// pinnedArgvRE reads the argv a command-pin module pins. It matches the shape
// the seeded rule writes; a hand-written rule in the same shape is read the
// same way, because nothing else marks where a rule came from.
var pinnedArgvRE = regexp.MustCompile(`(?m)^expected\s*:=\s*(\[.*\])\s*$`)

// pinnedArgv returns the argv a step's command-run rules pin, if exactly one
// is pinned.
func pinnedArgv(step map[string]any) ([]string, bool) {
	var found [][]string
	for _, src := range stepModules(step, typeCommandRun) {
		if !strings.Contains(src, "package commandrun_pinned") {
			continue
		}
		m := pinnedArgvRE.FindStringSubmatch(src)
		if m == nil {
			continue
		}
		var argv []string
		if err := json.Unmarshal([]byte(m[1]), &argv); err != nil || len(argv) == 0 {
			continue
		}
		found = append(found, argv)
	}
	if len(found) != 1 {
		return nil, false
	}
	return found[0], true
}

// enrolledIdentity is the part of the enrolled agent a policy names.
type enrolledIdentity struct {
	platformURL string
	trustDomain string
	tenantID    string
	expired     bool
}

var errNotEnrolled = errors.New("no enrolled agent principal")

// lookupEnrolledIdentity reads the redeemed agent credential for a platform.
// The functionary pins the SPIFFE trust domain and tenant; only a credential
// the platform has redeemed carries the trust domain, so a pending or
// unredeemed one is "not enrolled" here.
func lookupEnrolledIdentity(platformURL string) (enrolledIdentity, error) {
	url := platformURL
	if url == "" {
		url = config.DefaultPlatformURL
	}
	cred, err := auth.LookupAgent(url)
	if err != nil {
		return enrolledIdentity{}, err
	}
	if cred == nil || cred.TrustDomain == "" || cred.TenantID == "" {
		return enrolledIdentity{}, fmt.Errorf("%w for %s: the functionary pins the tenant of the agent that signs your evidence. "+
			"Next: run `cilock enroll agent --repo <owner/repo>` and have your human approve it in the browser, "+
			"then check `cilock agent status`", errNotEnrolled, auth.NormalizeURL(url))
	}
	return enrolledIdentity{
		platformURL: url,
		trustDomain: cred.TrustDomain,
		tenantID:    cred.TenantID,
		expired:     cred.CheckSigningEligibility(time.Now()) != nil,
	}, nil
}

// oneYearFromToday is the brief's expiry: one year out, at midnight UTC.
func oneYearFromToday(now time.Time) string {
	d := now.UTC().AddDate(1, 0, 0)
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
}
