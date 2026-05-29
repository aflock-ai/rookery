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

package catalogtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestFixturesNoSecrets is a SECRET-SCAN gate over the attestor fixtures.
//
// Why this exists: the rookery subtree two-way-syncs to a PUBLIC repo
// (aflock-ai/rookery). A real developer token, an absolute home path, or a
// PEM private key that slips into a recorded fixture would become permanent
// public git history the moment the sync runs. Until now scrubbing recordings
// was by-eye only; this test makes the scrub a hermetic, no-build-tag gate that
// runs in `make catalog-verify` alongside the rest of the catalogtest suite.
//
// It walks every file under plugins/attestors/*/testdata/ (fixture.yaml,
// *.json, attestation.json, recording-input/*, record.sh, fuzz corpora, …) and
// fails — naming the file and the matched pattern — on any leak signature.
//
// Tuning note (the hard part): several fixtures legitimately CONTAIN
// secret-shaped strings because that is their subject under test —
//   - secretscan/testdata is the secret-DETECTOR's own corpus of fake secrets,
//   - trivy/testdata/trivy-secrets.json is a recorded scan that REPORTS a
//     planted fake secret,
//   - DSSE attestation.json carries a base64 `payload`/`sig`/`keyid` (a signed
//     envelope, not a credential),
//   - go.sum files carry `h1:` module hashes.
//
// We do NOT carve out whole directories (that would be a blind spot a real
// future leak could hide behind). Instead we allowlist by *documented-fake
// sentinel value* for tokens, and for PEM blocks we only pass a BEGIN marker
// that is NOT backed by a real key body — so a genuine leaked key (marker +
// hundreds of base64 chars) still fails even inside the detector corpora.
func TestFixturesNoSecrets(t *testing.T) {
	pluginsRootDir, err := filepath.Abs(filepath.Join("..", "..", "..", "plugins", "attestors"))
	if err != nil {
		t.Fatalf("resolve plugins dir: %v", err)
	}
	examplesDir, err := filepath.Abs(filepath.Join("..", "..", "..", "examples"))
	if err != nil {
		t.Fatalf("resolve examples dir: %v", err)
	}

	scanned := 0
	scan := func(root string, restrict func(string) bool) {
		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if restrict != nil && !restrict(path) {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Errorf("read %s: %v", path, rerr)
				return nil
			}
			scanned++
			scanFile(t, path, data)
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", root, walkErr)
		}
	}

	// Plugin fixtures live under each attestor's testdata/ tree.
	scan(pluginsRootDir, underTestdata)
	// Every file under examples/ (live-only attestors' real reproductions:
	// reproduce.sh + recorded attestation.json) two-way-syncs to the public
	// mirror, so it must be as secret-clean as a fixture. Scan all of it.
	if _, statErr := os.Stat(examplesDir); statErr == nil {
		scan(examplesDir, nil)
	}

	// A broken walk (layout change, wrong relative path) that finds nothing
	// would otherwise make this gate pass vacuously. We KNOW there are recorded
	// fixtures on disk, so zero scanned files is a hard failure, never a green.
	if scanned == 0 {
		t.Fatalf("scanned 0 files under %s — the fixture walk is broken (expected committed fixtures); a skip here would be a false green", pluginsRootDir)
	}
	t.Logf("secret-scanned %d file(s) under %s and %s", scanned, pluginsRootDir, examplesDir)
}

func underTestdata(path string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg == "testdata" {
			return true
		}
	}
	return false
}

// --- Leak signatures -------------------------------------------------------

// Absolute home / temp paths: require a real path SEGMENT after the prefix so
// the explanatory comment "/private/var/folders," (no trailing segment) in the
// sbom record.sh files does not trip. A genuine leak is
// /Users/<name>/…, /home/<name>/…, or /private/var/folders/<seg>/….
var homePathRE = regexp.MustCompile(`(/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|/private/var/folders/[A-Za-z0-9._-]+)`)

// PEM private-key BEGIN marker.
var pemBeginRE = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

// A real PEM key body: BEGIN marker … large base64 blob … END marker. We allow
// detector-corpus markers that lack such a body; this still fails a genuine
// leaked key (marker + hundreds of base64 chars) anywhere, including the
// secretscan/trivy corpora.
var pemRealKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.{0,40}[A-Za-z0-9+/]{100,}`)

// Credential token signatures.
var tokenREs = []struct {
	name string
	re   *regexp.Regexp
}{
	{"github-token (gh[pso]_…)", regexp.MustCompile(`gh[pso]_[A-Za-z0-9]{20,}`)},
	{"aws-access-key-id (AKIA…)", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google-api-key (AIza…)", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{30,}`)},
	{"slack-token (xox[bps]-…)", regexp.MustCompile(`xox[bps]-[A-Za-z0-9-]+`)},
}

// AWS secret-access-key heuristic: a key-ish field assigned an EXACTLY-40-char
// base64 value (real AWS secret length). Anchored to a closing quote/EOL so the
// longer (48/52/64/72-char) base64 demo tokens in test_secrets.go and DSSE
// payloads do not match. Field name must look secret-ish AND aws-ish to keep it
// tight.
var awsSecretRE = regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)["' ]*[:=][ "']*[A-Za-z0-9/+]{40}["'\n\r]`)

// Documented-fake sentinel token values. A match equal to one of these is a
// well-known public placeholder (AWS's canonical example key, sequential 0123…
// placeholders, the slack/google demo keys). Any OTHER token-shaped string
// fails — so a real token dropped into the very same corpus file still trips
// the gate; there is no whole-file allowlist.
var sentinelTokens = map[string]bool{
	"ghp_012345678901234567890123456789":             true,
	"ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ":       true,
	"AKIAIOSFODNN7EXAMPLE":                           true,
	"AIzaSyDdoASSAD90YgOUNWXQLTIZTZ0oh13zU10":        true,
	"xoxp-TEST1234-TEST1234-TEST1234-1234abcdeftest": true,
}

func scanFile(t *testing.T, path string, data []byte) {
	t.Helper()
	rel := relForReport(path)
	text := string(data)

	// 1. Absolute home / temp paths.
	for _, m := range homePathRE.FindAllString(text, -1) {
		t.Errorf("%s: leaked absolute path %q (matched home/temp-path pattern)", rel, m)
	}

	// 2. PEM private key — only a marker backed by a real key body fails.
	if pemRealKeyRE.MatchString(text) {
		t.Errorf("%s: contains a PEM PRIVATE KEY block with a real key body (matched %q)", rel, pemBeginRE.FindString(text))
	}

	// 3. Credential tokens (allowlisting documented-fake sentinels).
	for _, tr := range tokenREs {
		for _, m := range tr.re.FindAllString(text, -1) {
			if sentinelTokens[m] {
				continue
			}
			t.Errorf("%s: leaked credential %q (matched %s)", rel, m, tr.name)
		}
	}

	// 4. AWS secret-access-key heuristic (40-char base64 on an aws-secret field).
	for _, m := range awsSecretRE.FindAllString(text, -1) {
		t.Errorf("%s: looks like a leaked AWS secret access key %q (40-char base64 on a secret-ish field)", rel, strings.TrimSpace(m))
	}
}

// relForReport trims the absolute prefix up to and including plugins/attestors/
// so failures name the fixture by its in-tree path.
func relForReport(path string) string {
	const marker = "plugins/attestors/"
	s := filepath.ToSlash(path)
	if i := strings.Index(s, marker); i >= 0 {
		return s[i:]
	}
	return s
}
