// jade:ring local
// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// stubPushgateDiscovery replaces platform discovery for one test and records
// which platform the command asked about.
func stubPushgateDiscovery(t *testing.T, origin string, err error) *[]string {
	t.Helper()
	asked := &[]string{}
	orig := discoverPushgateOrigin
	discoverPushgateOrigin = func(platformURL string) (string, error) {
		*asked = append(*asked, platformURL)
		return origin, err
	}
	t.Cleanup(func() { discoverPushgateOrigin = orig })
	return asked
}

func publishResultText(platformURL string) string {
	var buf bytes.Buffer
	printPublishResult(&buf, &policyPublishResult{Definition: "judge-gates", Tag: "v1", ReleaseID: "rel-1", ACR: "aal2"}, platformURL)
	return buf.String()
}

// The human's next step names the Pushgate origin the platform advertises in
// discovery. Production advertises https://pushgate.dev, which no string
// substitution on https://platform.testifysec.com can produce.
func TestPolicyPublish_NextStepUsesDiscoveredPushgateOrigin(t *testing.T) {
	asked := stubPushgateDiscovery(t, "https://pushgate.dev", nil)

	out := publishResultText("https://platform.testifysec.com")

	if !strings.Contains(out, "Next: your human turns it on for a repository at https://pushgate.dev/policy (Warn first).") {
		t.Fatalf("next step does not name the discovered Pushgate origin; got:\n%s", out)
	}
	if strings.Contains(out, "pushgate.testifysec.com") {
		t.Fatalf("next step names a host derived by substitution; got:\n%s", out)
	}
	if len(*asked) != 1 || (*asked)[0] != "https://platform.testifysec.com" {
		t.Fatalf("discovery asked about %v, want the session's platform", *asked)
	}
}

// A trailing slash on the advertised origin does not produce a double slash.
func TestPolicyPublish_NextStepTrimsDiscoveredTrailingSlash(t *testing.T) {
	stubPushgateDiscovery(t, "https://pushgate.dev/", nil)
	out := publishResultText("https://platform.testifysec.com")
	if !strings.Contains(out, " https://pushgate.dev/policy ") {
		t.Fatalf("got:\n%s", out)
	}
}

// When the platform does not advertise Pushgate, or discovery fails, there is
// no Pushgate to send the human to. The command says nothing rather than
// inventing a host.
func TestPolicyPublish_NoNextStepWhenPushgateIsNotAdvertised(t *testing.T) {
	for name, tc := range map[string]struct {
		origin string
		err    error
	}{
		"not advertised":   {"", errors.New("platform discovery does not advertise Pushgate")},
		"discovery failed": {"", errors.New("fetch discovery: connection refused")},
		"empty origin":     {"", nil},
		"plaintext origin": {"http://pushgate.example.com", nil},
		"not an origin":    {"pushgate.dev", nil},
		"userinfo origin":  {"https://user:pw@pushgate.dev", nil},
		"origin with path": {"https://pushgate.dev/elsewhere", nil},
	} {
		t.Run(name, func(t *testing.T) {
			stubPushgateDiscovery(t, tc.origin, tc.err)
			out := publishResultText("https://platform.testifysec.com")
			if strings.Contains(out, "Next:") {
				t.Fatalf("printed a next step with no trustworthy Pushgate origin; got:\n%s", out)
			}
			if strings.Contains(out, "pushgate.testifysec.com") || strings.Contains(out, "pw@") {
				t.Fatalf("printed an invented or credentialed host; got:\n%s", out)
			}
			if !strings.Contains(out, "published judge-gates v1") {
				t.Fatalf("the completion block itself must still print; got:\n%s", out)
			}
		})
	}
}

// Local standalone serves Pushgate over loopback http; that is still a real,
// advertised origin and gets the next step.
func TestPolicyPublish_NextStepAcceptsLoopbackPushgate(t *testing.T) {
	stubPushgateDiscovery(t, "http://localhost:8081", nil)
	out := publishResultText("http://localhost:8080")
	if !strings.Contains(out, " http://localhost:8081/policy ") {
		t.Fatalf("got:\n%s", out)
	}
}
