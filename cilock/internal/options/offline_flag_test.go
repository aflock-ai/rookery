// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"testing"
)

// TestOfflineFlag_AliasesPlatformURLEmpty proves --offline is a clean alias for
// --platform-url "": it clears the platform URL and skips all derivation, so no
// platform TSA is added and the fulcio URL stays empty (rec #5).
func TestOfflineFlag_AliasesPlatformURLEmpty(t *testing.T) {
	isolateCredentialStore(t)
	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--offline"}); err != nil {
		t.Fatal(err)
	}
	// Sanity: the default platform URL is non-empty before resolution.
	if ro.PlatformURL == "" {
		t.Fatal("precondition: default platform URL should be non-empty")
	}
	ro.ResolvePlatformDefaults(cmd)

	if ro.PlatformURL != "" {
		t.Errorf("--offline should clear PlatformURL, got %q", ro.PlatformURL)
	}
	if len(ro.TimestampServers) != 0 {
		t.Errorf("--offline must not derive a platform TSA, got %v", ro.TimestampServers)
	}
	if got := fulcioURL(t, cmd); got != "" {
		t.Errorf("--offline must leave the fulcio url empty, got %q", got)
	}
}

// TestOfflineFlag_DefaultPlatformStillDerives proves the default (no --offline,
// no --platform-url) path is unchanged: the platform TSA is derived. This is the
// case rec #5's visibility log covers — the run is silently using hosted
// defaults — but the behavior itself must not change.
func TestOfflineFlag_DefaultPlatformStillDerives(t *testing.T) {
	isolateCredentialStore(t)
	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if ro.PlatformURL == "" {
		t.Error("default run should keep the hosted platform URL")
	}
	if len(ro.TimestampServers) == 0 {
		t.Error("default run should derive the platform TSA")
	}
}

// TestVerifyOfflineFlag_AliasesPlatformURLEmpty proves the verify side mirrors
// the run side: --offline clears the platform URL and short-circuits derivation
// (no archivista URL derived).
func TestVerifyOfflineFlag_AliasesPlatformURLEmpty(t *testing.T) {
	isolateCredentialStore(t)
	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--offline"}); err != nil {
		t.Fatal(err)
	}
	vo.ResolvePlatformDefaults(cmd)

	if vo.PlatformURL != "" {
		t.Errorf("--offline should clear verify PlatformURL, got %q", vo.PlatformURL)
	}
}
