// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// jade:ring local
package auth

import (
	"reflect"
	"testing"
)

// TestOpenerCommandPerGOOS pins the argv each platform launches for the
// ceremony page (#11530). Before this, windows fell into the default branch and
// tried `open`, which does not exist there, so the login printed the
// "no browser came up" fallback on every Windows machine.
//
// The URL deliberately carries `&`: on windows it must reach the opener as ONE
// argv element, untouched. `cmd /c start` would hand it to cmd.exe, which
// splits the command line at `&` and drops every query parameter after the
// first, so the ceremony would open without its verifier.
func TestOpenerCommandPerGOOS(t *testing.T) {
	const u = "https://platform.example/auth/cli?port=4242&state=abc&tenant=t1"
	cases := []struct {
		goos     string
		wantName string
		wantArgs []string
	}{
		{"linux", "xdg-open", []string{u}},
		{"darwin", "open", []string{u}},
		{"windows", "rundll32", []string{"url.dll,FileProtocolHandler", u}},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			name, args := openerCommand(tc.goos, u)
			if name != tc.wantName || !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("openerCommand(%q) = %q %q, want %q %q", tc.goos, name, args, tc.wantName, tc.wantArgs)
			}
		})
	}
}

// TestOpenBrowserURLHonoursBrowserNone keeps the suppression contract: with
// BROWSER=none nothing is launched and the caller is told nothing opened, so
// the ceremony URL is printed instead.
func TestOpenBrowserURLHonoursBrowserNone(t *testing.T) {
	t.Setenv("BROWSER", "none")
	if openBrowserURL("https://platform.example/auth/cli?state=abc") {
		t.Fatal("openBrowserURL reported an opener started under BROWSER=none")
	}
}
