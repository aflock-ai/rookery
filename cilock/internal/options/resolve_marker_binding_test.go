// jade:ring local

// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"os"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
)

// TestResolvePlatformDefaults_WorkflowMarkerBindsPlatform: `cilock login` in CI
// stores a workflow-identity marker (no bearer), and the following `cilock
// run` uploads with the CI job's own token. The platform attestor must be
// allowed to bind that run to the platform, exactly as the no-login ambient
// path does. Before, the marker path never set the in-process trust mark and
// every such run recorded "untrusted CILOCK_PLATFORM_URL ... skipping platform
// binding" (GitLab CE 19.4.1, pipeline 8 job 24). GitHub and GitLab alike.
func TestResolvePlatformDefaults_WorkflowMarkerBindsPlatform(t *testing.T) {
	const platform = "https://platform.example.com"
	for name, setup := range map[string]func(t *testing.T){
		"github": func(t *testing.T) {
			t.Setenv("GITLAB_CI", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		},
		"gitlab": func(t *testing.T) {
			setGitLabJob(t)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
			t.Setenv("CILOCK_ARCHIVISTA_ID_TOKEN", testGitLabJWT(platform+"/archivista", "10"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			isolateCredentialStore(t)
			setup(t)
			_ = os.Unsetenv(platformURLEnv)
			t.Cleanup(func() { _ = os.Unsetenv(platformURLEnv) })
			platformconfig.MarkTrustedPlatformBinding("")
			t.Cleanup(func() { platformconfig.MarkTrustedPlatformBinding("") })
			if err := auth.Save(auth.Credential{PlatformURL: platform, AuthMode: auth.AuthModeWorkflowOIDC}); err != nil {
				t.Fatal(err)
			}

			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags([]string{"--platform-url", platform, "-k", "key.pem"}); err != nil {
				t.Fatal(err)
			}
			ro.ResolvePlatformDefaults(cmd)

			if !ro.ArchivistaOptions.OIDC {
				t.Fatal("the upload must authenticate with the CI job's token")
			}
			trusted, ok := platformconfig.TrustedPlatformBinding()
			if !ok || trusted != platform {
				t.Fatalf("a workflow-identity marker run must mark the platform binding trusted, got %q ok=%v", trusted, ok)
			}
		})
	}
}

// TestResolvePlatformDefaults_GitLabAmbientUploadIsEnabled is pipeline 21 job
// 81 (s8) on appliance build 3: a GitLab job with no `cilock login` that
// declared id_tokens for sigstore and for the platform Archivista signed
// keyless, logged that it would authenticate the upload with its Archivista
// token, and then stored nothing ("NO evidence stored for the collection"),
// exit 0. Declaring the Archivista-audience token is the request to upload, so
// the upload is on; an explicit --enable-archivista=false still wins, and a
// job with no such token is not switched on.
func TestResolvePlatformDefaults_GitLabAmbientUploadIsEnabled(t *testing.T) {
	const platform = "https://platform.example.com"
	for name, c := range map[string]struct {
		archivistaToken bool
		args            []string
		want            bool
	}{
		"archivista token declared":          {true, nil, true},
		"explicit --enable-archivista=false": {true, []string{"--enable-archivista=false"}, false},
		"no archivista token":                {false, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			isolateCredentialStore(t)
			setGitLabJob(t)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
			t.Setenv("SIGSTORE_ID_TOKEN", testGitLabJWT("sigstore", "10"))
			t.Setenv("CILOCK_ARCHIVISTA_ID_TOKEN", "")
			if c.archivistaToken {
				t.Setenv("CILOCK_ARCHIVISTA_ID_TOKEN", testGitLabJWT(platform+"/archivista", "10"))
			}
			_ = os.Unsetenv(platformURLEnv)
			t.Cleanup(func() { _ = os.Unsetenv(platformURLEnv) })
			platformconfig.MarkTrustedPlatformBinding("")
			t.Cleanup(func() { platformconfig.MarkTrustedPlatformBinding("") })

			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags(append([]string{"--platform-url", platform}, c.args...)); err != nil {
				t.Fatal(err)
			}
			ro.ResolvePlatformDefaults(cmd)
			if ro.ArchivistaOptions.Enable != c.want {
				t.Fatalf("upload enabled %v, want %v (oidc %v)", ro.ArchivistaOptions.Enable, c.want, ro.ArchivistaOptions.OIDC)
			}
			// A job with the token is a principal the evidence gate holds: it
			// stores its evidence or the run is refused, as on GitHub (#10621).
			if gated := ro.platformPrincipal != nil && ro.platformPrincipal.Kind == "workflow identity"; gated != c.archivistaToken {
				t.Fatalf("gated by the evidence gate = %v, want %v", gated, c.archivistaToken)
			}
		})
	}
}
