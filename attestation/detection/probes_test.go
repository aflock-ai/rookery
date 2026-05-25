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

package detection

import (
	"context"
	"net"
	"strconv"
	"testing"
)

// TestSocketListeningProbe exercises the socket_listening probe against
// a real listener on a local random port. Verifies both the matching
// case (listener present) and the miss case (port closed). Verifies
// that ResetProbeCache lets us re-probe; the cache itself is exercised
// implicitly across the two calls.
func TestSocketListeningProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi: %v", err)
	}

	ResetProbeCache()

	ctx := NewEvalContext(GatePre)
	if r := evalSocketListening(port, ctx); r.State != StateMatch {
		t.Errorf("expected listener on %d to match: %v", port, r)
	}

	// Cache should hold the answer; close the listener and confirm a
	// second probe call (same name) still returns true without dialing.
	ln.Close()
	if r := evalSocketListening(port, ctx); r.State != StateMatch {
		t.Errorf("cached probe should still report listener: %v", r)
	}

	// Reset cache → fresh probe → should now miss.
	ResetProbeCache()
	if r := evalSocketListening(port, ctx); r.State != StateNoMatch {
		t.Errorf("closed listener after cache reset should miss: %v", r)
	}
}

// TestCloudMetadataProbesWithInjection covers the matcher logic for
// each cloud-metadata probe via InjectProbeResult, so we don't need
// EC2/GCP/Azure runners to validate the predicate path.
//
// Real probe behavior (the actual HTTP request to the metadata
// endpoint) is integration-test territory and must run on the cloud
// platform in question — see docs/detection-integration-tests.md.
func TestCloudMetadataProbesWithInjection(t *testing.T) {
	cases := []struct {
		name      string
		probeName string
		eval      func(want bool, ctx *EvalContext) EvalResult
	}{
		{"imds_reachable", "imds_reachable", evalIMDSReachable},
		{"gcp_metadata_reachable", "gcp_metadata_reachable", evalGCPMetadataReachable},
		{"azure_metadata_reachable", "azure_metadata_reachable", evalAzureMetadataReachable},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_true", func(t *testing.T) {
			ResetProbeCache()
			InjectProbeResult(tc.probeName, true)
			ctx := NewEvalContext(GatePre)
			if r := tc.eval(true, ctx); r.State != StateMatch {
				t.Errorf("expected match when probe=true and want=true: %v", r)
			}
			if r := tc.eval(false, ctx); r.State != StateNoMatch {
				t.Errorf("expected no-match when probe=true and want=false: %v", r)
			}
		})
		t.Run(tc.name+"_false", func(t *testing.T) {
			ResetProbeCache()
			InjectProbeResult(tc.probeName, false)
			ctx := NewEvalContext(GatePre)
			if r := tc.eval(false, ctx); r.State != StateMatch {
				t.Errorf("expected match when probe=false and want=false: %v", r)
			}
			if r := tc.eval(true, ctx); r.State != StateNoMatch {
				t.Errorf("expected no-match when probe=false and want=true: %v", r)
			}
		})
	}
}

// TestProbeCacheOnce verifies cachedProbe runs its function exactly
// once per name; subsequent calls return the memoized value regardless
// of what a re-run of the function would say.
func TestProbeCacheOnce(t *testing.T) {
	ResetProbeCache()
	runs := 0
	fn := func(_ context.Context) (bool, error) {
		runs++
		return true, nil
	}
	if !cachedProbe("test_once", fn) {
		t.Errorf("first call should return true")
	}
	// Second call with a function that would return false; cache wins.
	if !cachedProbe("test_once", func(_ context.Context) (bool, error) { return false, nil }) {
		t.Errorf("second call should return cached true")
	}
	if runs != 1 {
		t.Errorf("expected exactly 1 fn invocation, got %d", runs)
	}
}
