// jade:ring local

// Copyright 2026 The Rookery Contributors
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

package secretscan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// TestOlderReleasedDefaultConfigCopiesExemptNothingByName: operators vendor
// .gitleaks.toml from whatever gitleaks release they had. testdata holds the
// default configs of gitleaks v8.18.4 and v8.21.2 verbatim (git show
// <tag>:config/gitleaks.toml); their path exceptions differ in text from the
// linked release's, so matching only the linked text let a pusher exempt a
// file by naming it node_modules/..., package-lock.json, go.sum or vendor/...
// (measured 2/8 reported, against 8/8 on main before the path fix). The drop
// set now includes every released v8 default config's path texts
// (gitleaks_path_patterns.go).
func TestOlderReleasedDefaultConfigCopiesExemptNothingByName(t *testing.T) {
	for _, v := range []string{"v8.18.4", "v8.21.2"} {
		t.Run(v, func(t *testing.T) {
			requireCopyExemptsNothingByName(t, v, builtinNamedFiles, allBuiltinNamedLocations)
		})
	}
}

// untaggedNamedFiles adds two script names to builtinNamedFiles: between
// releases, gitleaks master shipped three global path exceptions for
// jquery, swagger-ui, angular and plotly bundles that no tag carries.
var untaggedNamedFiles = func() map[string]string {
	m := map[string]string{
		"static/jquery-leak.js":     "token " + scopePAT + "\n",
		"static/swagger-ui-leak.js": "token " + scopePAT + "\n",
	}
	for k, v := range builtinNamedFiles {
		m[k] = v
	}
	return m
}()

var allUntaggedNamedLocations = func() []string {
	out := append([]string{"file:static/jquery-leak.js", "file:static/swagger-ui-leak.js"}, allBuiltinNamedLocations...)
	sort.Strings(out)
	return out
}()

// TestUntaggedMasterDefaultConfigCopiesExemptNothingByName: an operator can
// copy config/gitleaks.toml from the gitleaks master branch (the raw master
// URL) at any commit, not only at a release. From 2024-10-23 to 2024-10-31
// master carried three global path texts that no v8 tag has; testdata holds
// the default config verbatim at the last commit of each (git show
// <sha>:config/gitleaks.toml). With a tags-only list a pusher exempted a file
// by naming it static/jquery-*.js or static/swagger-ui-*.js (measured 8/10
// and 9/10 reported, against 10/10 on main). The generator now reads every
// master commit that touched the default config.
func TestUntaggedMasterDefaultConfigCopiesExemptNothingByName(t *testing.T) {
	for _, sha := range []string{"4181ad647a", "722e7d8e73", "e97695b852"} {
		t.Run(sha, func(t *testing.T) {
			requireCopyExemptsNothingByName(t, "master-"+sha, untaggedNamedFiles, allUntaggedNamedLocations)
		})
	}
}

func requireCopyExemptsNothingByName(t *testing.T, name string, files map[string]string, want []string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "gitleaks-defaults", name+".toml"))
	require.NoError(t, err)
	dir := t.TempDir()
	writeFiles(t, dir, files)
	cfgPath := writeGitleaksConfig(t, string(body))
	require.Equal(t, want, scanTree(t, dir, WithConfigPath(cfgPath)),
		"a verbatim copy of the gitleaks %s default config", name)

	// The names above sample the exceptions; the copy's own config says
	// whether any of them survived, so read it too.
	det, err := New(WithConfigPath(cfgPath)).initGitleaksDetector()
	require.NoError(t, err)
	for _, a := range det.Config.Allowlists {
		require.Empty(t, patterns(a.Paths), "global allowlist %q of the %s copy still exempts by path", a.Description, name)
	}
	for id, rule := range det.Config.Rules {
		for _, a := range rule.Allowlists {
			require.Empty(t, patterns(a.Paths), "rule %q of the %s copy still exempts by path", id, name)
		}
	}
}

// TestLinkedGitleaksDefaultPathsArePinned: every path pattern in the linked
// gitleaks release's default config is in the pinned list. The drop set is
// the linked config's paths plus that list, so a bump opens no hole while the
// new release stays linked; but after the bump that follows it, operator
// copies of that release are older copies, and only the pinned list still
// names their paths. A gitleaks bump that adds a path text fails here until
// plugins/attestors/secretscan/gen_gitleaks_path_patterns.py is rerun.
func TestLinkedGitleaksDefaultPathsArePinned(t *testing.T) {
	linked, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)
	pinned := map[string]struct{}{}
	for _, p := range gitleaksReleasedPathPatterns {
		pinned[p] = struct{}{}
	}
	var seen int
	check := func(where string, lists []*config.Allowlist) {
		for _, a := range lists {
			for _, p := range a.Paths {
				seen++
				_, ok := pinned[p.String()]
				require.True(t, ok, "%s path %q in the linked gitleaks default config is not in gitleaksReleasedPathPatterns; rerun plugins/attestors/secretscan/gen_gitleaks_path_patterns.py", where, p.String())
			}
		}
	}
	check("global", linked.Config.Allowlists)
	for id, rule := range linked.Config.Rules {
		check("rule "+id, rule.Allowlists)
	}
	require.Positive(t, seen, "the linked default config yielded no path patterns, so this check checked nothing")
}
