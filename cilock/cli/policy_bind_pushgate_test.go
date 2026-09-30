// jade:ring local
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
	"net/url"
	"strings"
	"testing"
)

const bindTestRelease = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

func stubReviewOpener(t *testing.T) *[]string {
	t.Helper()
	opened := &[]string{}
	prev := openReviewURL
	openReviewURL = func(u string) bool { *opened = append(*opened, u); return true }
	t.Cleanup(func() { openReviewURL = prev })
	return opened
}

func TestBindPushgateOpensTheExactReviewAndChangesNothing(t *testing.T) {
	stubPushgateDiscovery(t, "https://pushgate.dev", nil)
	opened := stubReviewOpener(t)
	var out bytes.Buffer
	err := runBindPushgate(&out, bindPushgateOpts{release: bindTestRelease, repo: "github.com/testifysec/judge",
		mode: "warn", reason: "one-day side by side", platformURL: "https://platform.testifysec.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(*opened) != 1 {
		t.Fatalf("opened %v, want exactly the review", *opened)
	}
	u, err := url.Parse((*opened)[0])
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host != "https://pushgate.dev" || u.Path != "/gates" ||
		q.Get("view") != "policies" || q.Get("assign") != bindTestRelease || q.Get("repo") != "github.com/testifysec/judge" {
		t.Fatalf("review URL = %s", u)
	}
	text := out.String()
	for _, want := range []string{bindTestRelease, "github.com/testifysec/judge", "mode:       warn", "Nothing has changed yet", (*opened)[0]} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "assigned") || strings.Contains(text, "✓") {
		t.Errorf("output claims a result the command cannot see:\n%s", text)
	}
}

func TestBindPushgateRefusesInexactInput(t *testing.T) {
	stubPushgateDiscovery(t, "https://pushgate.dev", nil)
	opened := stubReviewOpener(t)
	good := bindPushgateOpts{release: bindTestRelease, repo: "github.com/testifysec/judge", mode: "warn"}
	cases := map[string]func(o *bindPushgateOpts){
		"latest":          func(o *bindPushgateOpts) { o.release = "latest" },
		"tag":             func(o *bindPushgateOpts) { o.release = "v1" },
		"upper uuid":      func(o *bindPushgateOpts) { o.release = strings.ToUpper(bindTestRelease) },
		"uuid plus query": func(o *bindPushgateOpts) { o.release = bindTestRelease + "&repo=evil" },
		"repo url":        func(o *bindPushgateOpts) { o.repo = "https://github.com/testifysec/judge" },
		"repo upper":      func(o *bindPushgateOpts) { o.repo = "github.com/TestifySec/judge" },
		"repo traversal":  func(o *bindPushgateOpts) { o.repo = "github.com/testifysec/../x" },
		"repo other host": func(o *bindPushgateOpts) { o.repo = "evil.example/testifysec/judge" },
		"mode":            func(o *bindPushgateOpts) { o.mode = "off" },
		"reason too long": func(o *bindPushgateOpts) { o.reason = strings.Repeat("x", 1001) },
	}
	for name, mut := range cases {
		o := good
		mut(&o)
		if err := runBindPushgate(&bytes.Buffer{}, o); err == nil {
			t.Errorf("%s: accepted %+v", name, o)
		}
	}
	if len(*opened) != 0 {
		t.Fatalf("a refused input still opened %v", *opened)
	}
}

func TestBindPushgateNeedsAnAdvertisedOrigin(t *testing.T) {
	stubPushgateDiscovery(t, "", nil)
	opened := stubReviewOpener(t)
	err := runBindPushgate(&bytes.Buffer{}, bindPushgateOpts{release: bindTestRelease, repo: "github.com/testifysec/judge",
		mode: "warn", platformURL: "https://platform.testifysec.com"})
	if err == nil || len(*opened) != 0 {
		t.Fatalf("with no advertised Pushgate it must refuse and open nothing; err=%v opened=%v", err, *opened)
	}
}

func TestBindPushgateIsABindSubcommand(t *testing.T) {
	for _, c := range PolicyBindCmd().Commands() {
		if c.Name() == "pushgate" {
			return
		}
	}
	t.Fatal("cilock policy bind has no pushgate subcommand")
}
