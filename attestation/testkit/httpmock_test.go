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

package testkit

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// TestStartMetadataMockServesRecordedIMDS proves the http-mock driver's metadata
// server replays the committed recorded IMDS responses to a REAL AWS SDK IMDS
// client — the exact client construction (config.LoadDefaultConfig +
// imds.NewFromConfig) the aws-iid attestor uses. It is the failing-first test
// for the http-mock driver: without startMetadataMock + the endpoint env wiring,
// the SDK client has no endpoint to reach and the dynamic-data fetch fails.
func TestStartMetadataMockServesRecordedIMDS(t *testing.T) {
	dir := t.TempDir()
	wantDoc := []byte(`{"instanceId":"i-0test","region":"us-east-1","accountId":"111122223333"}`)
	wantSig := []byte("ZHVtbXktc2lnbmF0dXJl")
	mustWrite(t, filepath.Join(dir, "doc.json"), wantDoc)
	mustWrite(t, filepath.Join(dir, "sig.txt"), wantSig)

	fx := &Fixture{
		Name: "imds",
		Dir:  dir,
		Mode: ModeHTTPMock,
		Options: map[string]any{
			optIMDSDocument:  "doc.json",
			optIMDSSignature: "sig.txt",
		},
	}

	srv := startMetadataMock(t, fx)
	t.Setenv(metadataEndpointEnv, srv.URL)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"))
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	client := imds.NewFromConfig(cfg)

	gotDoc := fetchDynamic(t, client, "instance-identity/document")
	if string(gotDoc) != string(wantDoc) {
		t.Errorf("document = %q, want %q", gotDoc, wantDoc)
	}
	gotSig := fetchDynamic(t, client, "instance-identity/signature")
	if string(gotSig) != string(wantSig) {
		t.Errorf("signature = %q, want %q", gotSig, wantSig)
	}
}

// TestStartHTTPMockOptionEndpointBinding proves the generalized `option:`
// endpoint kind: the driver serves each committed file at its declared path AND
// returns the attestor-option name bound to the stub BASE URL (no path
// appended), so a flag/option-configured base URL — github-review's api-url,
// which is NOT an env var — can be pointed at the replay server. Without this
// seam an option-base attestor would still hit the live api.github.com under
// http-mock, defeating hermeticity. The base URL + the attestor's own appended
// path must reach the served content.
func TestStartHTTPMockOptionEndpointBinding(t *testing.T) {
	dir := t.TempDir()
	prBody := []byte(`{"number":1}`)
	reviewsBody := []byte(`[{"state":"COMMENTED"}]`)
	mustWrite(t, filepath.Join(dir, "pull.json"), prBody)
	mustWrite(t, filepath.Join(dir, "reviews.json"), reviewsBody)

	fx := &Fixture{
		Name: "opt-endpoints",
		Dir:  dir,
		Mode: ModeHTTPMock,
		Options: map[string]any{
			optEndpoints: []any{
				map[string]any{"option": "api-url", "file": "pull.json", "path": "/repos/o/r/pulls/1"},
				map[string]any{"option": "api-url", "file": "reviews.json", "path": "/repos/o/r/pulls/1/reviews"},
			},
		},
	}

	bindings := startHTTPMock(t, fx)
	base, ok := bindings["api-url"].(string)
	if !ok || base == "" {
		t.Fatalf("expected api-url option bound to stub base URL, got %v", bindings)
	}

	// The base URL must NOT include a path (the attestor appends its own).
	if got := mustGet(t, base+"/repos/o/r/pulls/1"); got != string(prBody) {
		t.Errorf("PR endpoint = %q, want %q", got, prBody)
	}
	if got := mustGet(t, base+"/repos/o/r/pulls/1/reviews"); got != string(reviewsBody) {
		t.Errorf("reviews endpoint = %q, want %q", got, reviewsBody)
	}
}

// TestDecodeEndpointsRejectsBadBinding proves the env/option XOR (and the
// file-required rule) are enforced: an endpoint with neither binding, with both,
// or with no file is a malformed fixture and must error (a silent accept would
// let an unbound stub ride green). A valid option endpoint must decode cleanly.
func TestDecodeEndpointsRejectsBadBinding(t *testing.T) {
	bad := map[string]map[string]any{
		"neither-env-nor-option": {"file": "x.json", "path": "/x"},
		"both-env-and-option":    {"env": "X_URL", "option": "api-url", "file": "x.json", "path": "/x"},
		"missing-file":           {"option": "api-url", "path": "/x"},
	}
	for name, ep := range bad {
		t.Run(name, func(t *testing.T) {
			fx := &Fixture{Name: name, Options: map[string]any{optEndpoints: []any{ep}}}
			if _, err := decodeEndpoints(fx); err == nil {
				t.Fatalf("expected decodeEndpoints to reject %q, got nil error", name)
			}
		})
	}

	t.Run("valid-option-endpoint", func(t *testing.T) {
		fx := &Fixture{Name: "ok", Options: map[string]any{
			optEndpoints: []any{map[string]any{"option": "api-url", "file": "pull.json", "path": "/p"}},
		}}
		eps, err := decodeEndpoints(fx)
		if err != nil {
			t.Fatalf("valid option endpoint errored: %v", err)
		}
		if len(eps) != 1 || eps[0].Option != "api-url" || eps[0].Env != "" || eps[0].File != "pull.json" {
			t.Fatalf("decoded endpoint = %+v, want {Option:api-url File:pull.json}", eps[0])
		}
	})
}

func mustGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // test-only request to the in-process stub
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(b)
}

func fetchDynamic(t *testing.T, c *imds.Client, path string) []byte {
	t.Helper()
	out, err := c.GetDynamicData(context.Background(), &imds.GetDynamicDataInput{Path: path})
	if err != nil {
		t.Fatalf("GetDynamicData(%s): %v", path, err)
	}
	b, err := io.ReadAll(out.Content)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}
