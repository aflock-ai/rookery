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

package pipinstall

import (
	"os"
	"path/filepath"
	"testing"
)

// mkdistinfo builds a <name>-<version>.dist-info directory under location with
// the given INSTALLER token and direct_url.json body (either may be "" to skip
// writing that file). It returns the dist-info path.
func mkdistinfo(t *testing.T, location, distName, version, installer, directURL string) string {
	t.Helper()
	di := filepath.Join(location, distName+"-"+version+".dist-info")
	if err := os.MkdirAll(di, 0o755); err != nil {
		t.Fatalf("mkdir dist-info: %v", err)
	}
	if installer != "" {
		if err := os.WriteFile(filepath.Join(di, "INSTALLER"), []byte(installer+"\n"), 0o644); err != nil { //nolint:gosec
			t.Fatalf("write INSTALLER: %v", err)
		}
	}
	if directURL != "" {
		if err := os.WriteFile(filepath.Join(di, "direct_url.json"), []byte(directURL), 0o644); err != nil { //nolint:gosec
			t.Fatalf("write direct_url.json: %v", err)
		}
	}
	return di
}

// TestCanonicalizeName covers PEP 503 normalization: lowercase, runs of -_.
// collapse to a single dash.
func TestCanonicalizeName(t *testing.T) {
	cases := map[string]string{
		"Requests":             "requests",
		"charset_normalizer":   "charset-normalizer",
		"charset---normalizer": "charset-normalizer",
		"Foo.Bar_Baz":          "foo-bar-baz",
		"a..b__c--d":           "a-b-c-d",
		"already-canon":        "already-canon",
	}
	for in, want := range cases {
		if got := canonicalizeName(in); got != want {
			t.Errorf("canonicalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInstallTypeWheel: a dist-info with a direct_url.json pointing at a .whl
// must classify as "wheel", read the INSTALLER token, and report no setup.py.
func TestInstallTypeWheel(t *testing.T) {
	loc := t.TempDir()
	mkdistinfo(t, loc, "requests", "2.32.3", "pip",
		`{"url": "https://files.pythonhosted.org/.../requests-2.32.3-py3-none-any.whl", "archive_info": {"hash": "sha256=abc"}}`)

	pkg := PackageInfo{Name: "requests", Version: "2.32.3", Location: loc}
	pkg = populateDiskMarkers(pkg)

	if pkg.InstallType != "wheel" {
		t.Errorf("InstallType = %q, want wheel", pkg.InstallType)
	}
	if pkg.Installer != "pip" {
		t.Errorf("Installer = %q, want pip", pkg.Installer)
	}
}

// TestInstallTypeWheelArchiveInfoURL: direct_url.json may carry the URL under
// archive_info.url rather than top-level url. Still a wheel.
func TestInstallTypeWheelArchiveInfoURL(t *testing.T) {
	loc := t.TempDir()
	mkdistinfo(t, loc, "certifi", "2026.5.20", "pip",
		`{"archive_info": {"url": "https://example.com/certifi-2026.5.20-py3-none-any.whl"}}`)

	pkg := PackageInfo{Name: "certifi", Version: "2026.5.20", Location: loc}
	pkg = populateDiskMarkers(pkg)

	if pkg.InstallType != "wheel" {
		t.Errorf("InstallType = %q, want wheel", pkg.InstallType)
	}
}

// TestInstallTypeSdistFromDirectURL: a .tar.gz / .zip url means built from sdist.
func TestInstallTypeSdistFromDirectURL(t *testing.T) {
	for _, url := range []string{
		`{"url": "https://files.pythonhosted.org/.../some-pkg-1.0.tar.gz"}`,
		`{"url": "https://files.pythonhosted.org/.../some-pkg-1.0.zip"}`,
	} {
		loc := t.TempDir()
		mkdistinfo(t, loc, "some_pkg", "1.0", "pip", url)
		pkg := PackageInfo{Name: "some-pkg", Version: "1.0", Location: loc}
		pkg = populateDiskMarkers(pkg)
		if pkg.InstallType != "sdist" {
			t.Errorf("InstallType for %s = %q, want sdist", url, pkg.InstallType)
		}
	}
}

// TestInstallTypeEditableEggLink: an <canonical>.egg-link under Location ⇒ editable.
func TestInstallTypeEditableEggLink(t *testing.T) {
	loc := t.TempDir()
	if err := os.WriteFile(filepath.Join(loc, "mypkg.egg-link"), []byte("/src/mypkg\n."), 0o644); err != nil { //nolint:gosec
		t.Fatalf("write egg-link: %v", err)
	}
	pkg := PackageInfo{Name: "MyPkg", Version: "0.1", Location: loc}
	pkg = populateDiskMarkers(pkg)
	if pkg.InstallType != "editable" {
		t.Errorf("InstallType = %q, want editable", pkg.InstallType)
	}
}

// TestInstallTypeEditableEggInfo: an <canonical>*.egg-info dir under Location ⇒ editable.
func TestInstallTypeEditableEggInfo(t *testing.T) {
	loc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(loc, "mypkg.egg-info"), 0o755); err != nil {
		t.Fatalf("mkdir egg-info: %v", err)
	}
	pkg := PackageInfo{Name: "mypkg", Version: "0.1", Location: loc}
	pkg = populateDiskMarkers(pkg)
	if pkg.InstallType != "editable" {
		t.Errorf("InstallType = %q, want editable", pkg.InstallType)
	}
}

// TestInstallTypeFallbackToBuildEvidence: no direct_url.json, no egg markers.
// HasSetupPy true ⇒ sdist (pip ran a setup.py); false ⇒ wheel (prebuilt drop).
func TestInstallTypeFallbackToBuildEvidence(t *testing.T) {
	t.Run("hasSetupPy true ⇒ sdist", func(t *testing.T) {
		loc := t.TempDir()
		mkdistinfo(t, loc, "buildme", "1.0", "pip", "")
		pkg := PackageInfo{Name: "buildme", Version: "1.0", Location: loc, HasSetupPy: true}
		pkg = populateDiskMarkers(pkg)
		if pkg.InstallType != "sdist" {
			t.Errorf("InstallType = %q, want sdist (build evidence)", pkg.InstallType)
		}
		if pkg.Installer != "pip" {
			t.Errorf("Installer = %q, want pip", pkg.Installer)
		}
	})
	t.Run("hasSetupPy false ⇒ wheel", func(t *testing.T) {
		loc := t.TempDir()
		mkdistinfo(t, loc, "dropped", "1.0", "pip", "")
		pkg := PackageInfo{Name: "dropped", Version: "1.0", Location: loc, HasSetupPy: false}
		pkg = populateDiskMarkers(pkg)
		if pkg.InstallType != "wheel" {
			t.Errorf("InstallType = %q, want wheel (no build step)", pkg.InstallType)
		}
	})
}

// TestInstallTypeEmptyLocation: empty/unreadable Location ⇒ InstallType stays "".
func TestInstallTypeEmptyLocation(t *testing.T) {
	pkg := PackageInfo{Name: "x", Version: "1.0", Location: ""}
	pkg = populateDiskMarkers(pkg)
	if pkg.InstallType != "" {
		t.Errorf("InstallType = %q, want empty for empty Location", pkg.InstallType)
	}
	if pkg.Installer != "" {
		t.Errorf("Installer = %q, want empty for empty Location", pkg.Installer)
	}
}

// TestDistInfoUnderscoreJoiner: dist-info dirs may use the underscore-joined
// distribution name (PEP 427) e.g. charset_normalizer-3.4.7.dist-info while
// pip reports the dashed name. We must find it via either joiner.
func TestDistInfoUnderscoreJoiner(t *testing.T) {
	loc := t.TempDir()
	mkdistinfo(t, loc, "charset_normalizer", "3.4.7", "pip",
		`{"url": "https://example.com/charset_normalizer-3.4.7-py3-none-any.whl"}`)
	pkg := PackageInfo{Name: "charset-normalizer", Version: "3.4.7", Location: loc}
	pkg = populateDiskMarkers(pkg)
	if pkg.Installer != "pip" {
		t.Errorf("Installer = %q, want pip (underscore-joined dist-info not found)", pkg.Installer)
	}
	if pkg.InstallType != "wheel" {
		t.Errorf("InstallType = %q, want wheel", pkg.InstallType)
	}
}

// TestCorrelateSetupPy: HasSetupPy/HasCmdClass are set per-package by matching a
// found setup.py whose path contains the canonical name AND whose parent dir is
// <name>-<version> or <name>. cmdclass presence comes from SuspiciousCalls.
func TestCorrelateSetupPy(t *testing.T) {
	root := t.TempDir()
	// Build cache: pkg-1.0/setup.py with cmdclass.
	withCmd := filepath.Join(root, "pkg-1.0", "setup.py")
	if err := os.MkdirAll(filepath.Dir(withCmd), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Another package, no cmdclass, parent dir is bare <name>.
	noCmd := filepath.Join(root, "Other_Pkg", "setup.py")
	if err := os.MkdirAll(filepath.Dir(noCmd), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	analyses := []SetupPyAnalysis{
		{Path: withCmd, SuspiciousCalls: []string{"exec(", "cmdclass{}"}},
		{Path: noCmd},
	}

	pkgWithCmd := PackageInfo{Name: "pkg", Version: "1.0"}
	pkgWithCmd = correlateSetupPy(pkgWithCmd, analyses)
	if !pkgWithCmd.HasSetupPy {
		t.Errorf("pkg: HasSetupPy = false, want true")
	}
	if !pkgWithCmd.HasCmdClass {
		t.Errorf("pkg: HasCmdClass = false, want true")
	}

	pkgNoCmd := PackageInfo{Name: "Other-Pkg", Version: "2.0"}
	pkgNoCmd = correlateSetupPy(pkgNoCmd, analyses)
	if !pkgNoCmd.HasSetupPy {
		t.Errorf("Other-Pkg: HasSetupPy = false, want true (parent dir = bare canonical name)")
	}
	if pkgNoCmd.HasCmdClass {
		t.Errorf("Other-Pkg: HasCmdClass = true, want false")
	}

	// A package with no matching setup.py stays false (pure wheel install).
	pkgWheel := PackageInfo{Name: "requests", Version: "2.32.3"}
	pkgWheel = correlateSetupPy(pkgWheel, analyses)
	if pkgWheel.HasSetupPy {
		t.Errorf("requests: HasSetupPy = true, want false (no matching setup.py)")
	}
}

// TestCorrelateSetupPyRejectsForeignParent: a setup.py whose parent dir does not
// match the package's name/version must NOT be attributed to that package even
// if the path coincidentally contains the canonical name somewhere.
func TestCorrelateSetupPyRejectsForeignParent(t *testing.T) {
	root := t.TempDir()
	// path contains "requests" as a substring of the project dir but the parent
	// dir of setup.py is "totally-different-3.0", not requests-*.
	p := filepath.Join(root, "requests-cache-build", "totally-different-3.0", "setup.py")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	analyses := []SetupPyAnalysis{{Path: p}}

	pkg := PackageInfo{Name: "requests", Version: "2.32.3"}
	pkg = correlateSetupPy(pkg, analyses)
	if pkg.HasSetupPy {
		t.Errorf("requests: HasSetupPy = true, want false (parent dir is not requests-<version>)")
	}
}

// TestEndToEndPopulation exercises the full per-package population the way
// Attest() does: correlate setup.py THEN read disk markers (order matters
// because the disk-marker fallback consults HasSetupPy).
func TestEndToEndPopulation(t *testing.T) {
	// SDIST package: build cache has its setup.py (with cmdclass), and on disk
	// there is a dist-info with no direct_url.json so it falls back to build
	// evidence.
	root := t.TempDir()
	buildDir := filepath.Join(root, "build")
	loc := filepath.Join(root, "site-packages")
	if err := os.MkdirAll(loc, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sp := filepath.Join(buildDir, "buildpkg-1.2.3", "setup.py")
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mkdistinfo(t, loc, "buildpkg", "1.2.3", "pip", "")

	analyses := []SetupPyAnalysis{{Path: sp, SuspiciousCalls: []string{"cmdclass{}"}}}

	pkg := PackageInfo{Name: "buildpkg", Version: "1.2.3", Location: loc}
	pkg = correlateSetupPy(pkg, analyses)
	pkg = populateDiskMarkers(pkg)

	if !pkg.HasSetupPy {
		t.Errorf("HasSetupPy = false, want true")
	}
	if !pkg.HasCmdClass {
		t.Errorf("HasCmdClass = false, want true")
	}
	if pkg.InstallType != "sdist" {
		t.Errorf("InstallType = %q, want sdist", pkg.InstallType)
	}
	if pkg.Installer != "pip" {
		t.Errorf("Installer = %q, want pip", pkg.Installer)
	}
}
