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
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// DefaultProbeTimeout caps how long a single named probe may block.
// A non-reachable IMDS endpoint or unbound socket should return false
// in well under this — the timeout is the failsafe, not the expected
// path. Tuned conservatively because every cilock run pays this cost
// at least once if a probe is consulted.
const DefaultProbeTimeout = 500 * time.Millisecond

// probeFn is the signature for named-probe implementations. Each returns
// the boolean answer to the predicate and any diagnostic error (errors
// are advisory; the boolean is authoritative).
type probeFn func(ctx context.Context) (bool, error)

// imdsURL is the AWS Instance Metadata Service endpoint v2's token
// route. We use this for the imds_reachable probe — a HEAD against the
// token endpoint completes very fast on EC2 and times out on anything
// else. v2 is preferred over v1 because SSRF-mitigation hardening
// schedules tend to block v1.
const imdsURL = "http://169.254.169.254/latest/api/token"

// gcpMetadataURL is the GCP metadata server's compute identity route.
// Requires a "Metadata-Flavor: Google" header and is routed on the
// link-local 169.254.169.254 address (same as AWS — they share the
// reserved address). The header is what disambiguates clouds.
const gcpMetadataURL = "http://metadata.google.internal/computeMetadata/v1/"

// azureMetadataURL is the Azure Instance Metadata Service endpoint.
// Requires "Metadata: true" header and an api-version query param.
const azureMetadataURL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

// probeOnce caches the result of named probes across multiple predicate
// evaluations within the same process. The cache is keyed by probe name;
// once a probe returns, every subsequent call within the same process
// returns the cached value instantly.
//
// The cache lives at package scope (not per-EvalContext) because IMDS
// reachability and socket bindings do not change within a cilock run.
// Tests that need a fresh probe state use ResetProbeCache.
var (
	probeOnceMu sync.Mutex
	probeOnce   = make(map[string]bool)
	probeDone   = make(map[string]struct{})
)

// ResetProbeCache clears the package-level probe cache. Test-only.
func ResetProbeCache() {
	probeOnceMu.Lock()
	defer probeOnceMu.Unlock()
	probeOnce = make(map[string]bool)
	probeDone = make(map[string]struct{})
}

// InjectProbeResult sets a fixed result for the named probe, marking
// it "done" so cachedProbe returns the injected value without ever
// calling the underlying probe function. Test-only — production code
// must not call this.
//
// This is how unit tests cover named-probe paths (imds_reachable,
// gcp_metadata_reachable, etc.) without making real network calls.
// Integration tests against actual cloud metadata still validate the
// real probe functions — they belong in a separate suite that's only
// run on EC2/GCP/Azure runners.
func InjectProbeResult(name string, result bool) {
	probeOnceMu.Lock()
	defer probeOnceMu.Unlock()
	probeOnce[name] = result
	probeDone[name] = struct{}{}
}

func cachedProbe(name string, fn probeFn) bool {
	probeOnceMu.Lock()
	if _, done := probeDone[name]; done {
		v := probeOnce[name]
		probeOnceMu.Unlock()
		return v
	}
	probeOnceMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
	defer cancel()
	ok, _ := fn(ctx)

	probeOnceMu.Lock()
	probeOnce[name] = ok
	probeDone[name] = struct{}{}
	probeOnceMu.Unlock()
	return ok
}

// probeIMDSReachable performs a HEAD against the IMDSv2 token URL.
// Returns true if any HTTP response (regardless of status code) arrived
// within the timeout — even a 401 means the endpoint is alive. Returns
// false on network errors or timeout.
func probeIMDSReachable(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, imdsURL, nil)
	if err != nil {
		return false, err
	}
	client := &http.Client{
		Timeout: DefaultProbeTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	return true, nil
}

// probeGCPMetadataReachable performs a HEAD against the GCP metadata
// server with the required "Metadata-Flavor: Google" header. Any
// HTTP response within the timeout counts as reachable. Returns
// false on network errors / timeout.
//
// GCP uses metadata.google.internal which resolves to 169.254.169.254
// (the same link-local address as AWS), but the required header
// disambiguates: AWS IMDS rejects requests with Metadata-Flavor,
// GCP requires it. This means on a host configured for both, both
// probes can return true honestly.
func probeGCPMetadataReachable(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, gcpMetadataURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: DefaultProbeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	return true, nil
}

// probeAzureMetadataReachable performs a HEAD against the Azure IMDS
// endpoint with the required "Metadata: true" header. Same shape as
// the GCP probe — any response means reachable.
func probeAzureMetadataReachable(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, azureMetadataURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Metadata", "true")
	client := &http.Client{Timeout: DefaultProbeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	return true, nil
}

// probeSocketListening checks whether anything is bound to localhost
// on the given TCP port. Used by detectors that want to fire when a
// well-known dev server is up (e.g. a Vault dev server on 8200). The
// probe attempts a non-blocking dial; success means a listener exists.
func probeSocketListening(ctx context.Context, port int) (bool, error) {
	d := net.Dialer{Timeout: DefaultProbeTimeout}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

// evalIMDSReachable runs the IMDS probe (cached) and matches on the
// declared expected value. Plugins that want "on AWS" write
// `imds_reachable: true`; those that want "off AWS" write `false`.
func evalIMDSReachable(want bool, ctx *EvalContext) EvalResult {
	return evalNamedBoolProbe("imds_reachable", want, ctx, probeIMDSReachable)
}

// evalGCPMetadataReachable runs the GCP metadata probe (cached). Same
// shape as imds_reachable.
func evalGCPMetadataReachable(want bool, ctx *EvalContext) EvalResult {
	return evalNamedBoolProbe("gcp_metadata_reachable", want, ctx, probeGCPMetadataReachable)
}

// evalAzureMetadataReachable runs the Azure IMDS probe (cached).
func evalAzureMetadataReachable(want bool, ctx *EvalContext) EvalResult {
	return evalNamedBoolProbe("azure_metadata_reachable", want, ctx, probeAzureMetadataReachable)
}

// evalNamedBoolProbe is the shared body for cloud-metadata-style
// probes that match an expected boolean against a cached probe result.
func evalNamedBoolProbe(name string, want bool, ctx *EvalContext, fn probeFn) EvalResult {
	ctx.observedProbes[name] = true
	got := cachedProbe(name, fn)
	ctx.probeCache[name] = got
	if got == want {
		return EvalResult{State: StateMatch, Rule: fmt.Sprintf("%s:%v", name, got)}
	}
	return EvalResult{State: StateNoMatch, Rule: fmt.Sprintf("%s:miss:%v!=%v", name, got, want)}
}

// evalSocketListening runs the socket-listening probe (cached) and
// matches if the port has a listener.
func evalSocketListening(port int, ctx *EvalContext) EvalResult {
	name := fmt.Sprintf("socket_listening:%d", port)
	ctx.observedProbes[name] = true
	got := cachedProbe(name, func(c context.Context) (bool, error) {
		return probeSocketListening(c, port)
	})
	ctx.probeCache[name] = got
	if got {
		return EvalResult{State: StateMatch, Rule: name}
	}
	return EvalResult{State: StateNoMatch, Rule: name + ":miss"}
}
