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

package detection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Onbsim 2026-09-25: a plain `cilock run` with no -a list failed on
// "attestor gcp-iit failed: unable to retrieve valid identity token" in 4 runs
// that were nowhere near GCP. The probe went through HTTP_PROXY, and the
// proxy's own reply to metadata.google.internal counted as "reachable". A
// corporate proxy does the same to a real user's first run.

func withGCPMetadataURL(t *testing.T, url string) {
	t.Helper()
	old := gcpMetadataURL
	gcpMetadataURL = url
	t.Cleanup(func() { gcpMetadataURL = old })
}

func TestGCPProbeBelievesOnlyAGoogleMetadataServer(t *testing.T) {
	notGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // a proxy or captive resolver answering anything
	}))
	defer notGoogle.Close()
	withGCPMetadataURL(t, notGoogle.URL+"/computeMetadata/v1/")
	if ok, _ := probeGCPMetadataReachable(context.Background()); ok {
		t.Fatal("a response without Metadata-Flavor: Google is not the GCP metadata server")
	}

	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		w.WriteHeader(http.StatusOK)
	}))
	defer google.Close()
	withGCPMetadataURL(t, google.URL+"/computeMetadata/v1/")
	if ok, err := probeGCPMetadataReachable(context.Background()); !ok {
		t.Fatalf("a Google metadata server must be detected: %v", err)
	}
}

func TestMetadataProbesNeverUseAProxyOrFollowRedirects(t *testing.T) {
	c := metadataProbeClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("metadata probes need their own transport, got %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("a link-local metadata probe must never be routed through HTTP_PROXY")
	}
	if !tr.DisableKeepAlives {
		t.Fatal("a one-shot probe transport must not pool idle connections")
	}
}

func TestGCPProbeDoesNotFollowARedirectToAGoogleLookalike(t *testing.T) {
	var followed bool
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true
		w.Header().Set("Metadata-Flavor", "Google")
		w.WriteHeader(http.StatusOK)
	}))
	defer google.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, google.URL+"/computeMetadata/v1/", http.StatusFound)
	}))
	defer redirector.Close()
	withGCPMetadataURL(t, redirector.URL+"/computeMetadata/v1/")
	if ok, _ := probeGCPMetadataReachable(context.Background()); ok {
		t.Fatal("a redirect to something that answers like Google is not the metadata server")
	}
	if followed {
		t.Fatal("the probe followed a redirect")
	}
}
