// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// jade:ring local
package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rejectedOpenTargets are values OpenURL could be handed that an opener would
// act on locally: paths and app bundles (open, xdg-open, rundll32 all launch
// them), file: URLs, option-shaped arguments, and shapes with no host.
var rejectedOpenTargets = []string{
	"",
	`C:\Windows\System32\calc.exe`,
	`\\host\share\payload.exe`,
	"/Applications/Calculator.app",
	"/usr/bin/id",
	"./relative/script.sh",
	"file:///C:/Windows/System32/calc.exe",
	"file:///etc/passwd",
	"--help",
	"-a Calculator",
	"https:///no-host",
	"https://",
	"http:path-only",
	"javascript:alert(1)",
	"ms-msdt:/id PCWDiagnostic",
	"ftp://files.example/x",
	"//host/path",
	"example.com/auth/cli",
	"https://host/\x00",
	"https://host/\n--flag",
}

// TestOpenableURLAdmitsOnlyHTTPWithAHost covers the value space the guard has
// to refuse, and the shapes the real ceremony and review URLs take, including
// metacharacters that must stay data (& ^ | % and a space).
func TestOpenableURLAdmitsOnlyHTTPWithAHost(t *testing.T) {
	for _, bad := range rejectedOpenTargets {
		if openableURL(bad) {
			t.Errorf("openableURL(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{
		"https://platform.example/auth/cli?port=4242&state=abc&tenant=t1",
		"HTTPS://platform.example/x",
		"http://127.0.0.1:8080/x?a=1&b=2",
		"https://judge.example/auth/cli?state=a&port=1^2&x=%26|y z",
	} {
		if !openableURL(good) {
			t.Errorf("openableURL(%q) = false, want true", good)
		}
	}
}

// TestOpenURLNeverStartsAnOpenerForANonWebTarget drives the real entry points
// with stand-in openers first on PATH and asserts none ran. The stand-ins
// cover all three platforms' opener names, so whichever GOOS runs this, an
// opener that starts leaves a marker.
func TestOpenURLNeverStartsAnOpenerForANonWebTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stand-in openers are shell scripts")
	}
	t.Setenv("BROWSER", "")
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	script := "#!/bin/sh\necho \"$@\" >> '" + marker + "'\n"
	for _, name := range []string{"xdg-open", "open", "rundll32"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil { //nolint:gosec // G306: test stand-in must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, bad := range rejectedOpenTargets {
		if OpenURL(bad) {
			t.Errorf("OpenURL(%q) reported an opener started", bad)
		}
		if openBrowserURL(bad) {
			t.Errorf("openBrowserURL(%q) reported an opener started", bad)
		}
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("an opener was launched for a non-web target: %q", b)
	}

	if !OpenURL("https://platform.example/auth/cli?state=a&port=1") {
		t.Fatal("a plain https URL no longer starts the opener")
	}
}
