// jade:ring local

// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import "testing"

const testPlatformFulcio = "https://platform.example/fulcio"

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// On GitLab.com, Buildkite and CircleCI a bare `cilock run --platform-url X`
// must select the platform Fulcio, so the signer fetches the job's ambient
// OIDC token itself (#9839), the way GitHub Actions already works.
func TestSelectAmbientCIFulcioSelectsThePlatformFulcioOnSupportedCIs(t *testing.T) {
	for _, env := range []map[string]string{{"GITLAB_CI": "true"}, {"BUILDKITE": "true"}, {"CIRCLECI": "true"}} {
		cmd, _ := newRunCmd(t)
		if !selectAmbientCIFulcio(cmd, testPlatformFulcio, envOf(env)) {
			t.Fatalf("%v: fulcio signer not selected", env)
		}
		if got := fulcioURL(t, cmd); got != testPlatformFulcio {
			t.Fatalf("%v: signer-fulcio-url = %q, want the platform Fulcio", env, got)
		}
		if !fulcioSignerSelected(cmd) {
			t.Fatalf("%v: the URL must mark the fulcio signer as selected", env)
		}
	}
}

func TestSelectAmbientCIFulcioLeavesOtherChoicesAlone(t *testing.T) {
	onGitLab := envOf(map[string]string{"GITLAB_CI": "true"})

	// Not on a supported CI: nothing happens (local runs keep their key).
	cmd, _ := newRunCmd(t)
	if selectAmbientCIFulcio(cmd, testPlatformFulcio, envOf(map[string]string{"JENKINS_URL": "x"})) || fulcioURL(t, cmd) != "" {
		t.Fatal("must not select fulcio outside a supported CI")
	}

	// An explicit non-fulcio signer wins: cilock accepts exactly one signer.
	cmd, _ = newRunCmd(t)
	if err := cmd.Flags().Set("signer-file-key-path", "key.pem"); err != nil {
		t.Skipf("file signer not registered in this build: %v", err)
	}
	if selectAmbientCIFulcio(cmd, testPlatformFulcio, onGitLab) || fulcioURL(t, cmd) != "" {
		t.Fatal("must not add a second signer next to an explicit file key")
	}

	// A user-chosen Fulcio URL is kept.
	cmd, _ = newRunCmd(t)
	if err := cmd.Flags().Set("signer-fulcio-url", "https://fulcio.sigstore.dev"); err != nil {
		t.Fatal(err)
	}
	selectAmbientCIFulcio(cmd, testPlatformFulcio, onGitLab)
	if got := fulcioURL(t, cmd); got != "https://fulcio.sigstore.dev" {
		t.Fatalf("user's --signer-fulcio-url overwritten: %q", got)
	}

	// No platform Fulcio to point at: nothing to select.
	cmd, _ = newRunCmd(t)
	if selectAmbientCIFulcio(cmd, "", onGitLab) {
		t.Fatal("must not select fulcio without a Fulcio URL")
	}
}
