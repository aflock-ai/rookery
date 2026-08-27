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

package options

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// archivistaOptionsFromFlags builds ArchivistaOptions exactly the way `cilock
// run` does — by registering the flags on a cobra command and parsing argv.
//
// This matters. Reading the struct's zero value, or hand-constructing it in a
// test, would prove nothing about the shipped binary: the retry defaults live
// in the flag registrations, so only a flag-parsed struct answers the question
// "does a real `cilock run` retry".
func archivistaOptionsFromFlags(t *testing.T, argv ...string) *ArchivistaOptions {
	t.Helper()
	o := &ArchivistaOptions{}
	cmd := &cobra.Command{Use: "run", RunE: func(*cobra.Command, []string) error { return nil }}
	o.AddFlags(cmd)
	cmd.SetArgs(argv)
	cmd.SetOut(nil)
	require.NoError(t, cmd.Execute())
	return o
}

// TestArchivistaClient_RetriesByDefault is the anti-inertness test.
//
// Every retry unit test in attestation/archivista passes against a client the
// TEST constructed with WithRetry. None of them would notice if cilock forgot
// to pass the option — the feature would be perfectly implemented and never
// reached in production. This drives the product's own construction path with
// nothing but default flags.
func TestArchivistaClient_RetriesByDefault(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"gitoid-after-retry"}`))
	}))
	t.Cleanup(srv.Close)

	o := archivistaOptionsFromFlags(t)
	require.Greater(t, o.UploadRetries, 0, "the shipped default must allow at least one retry")
	require.Greater(t, o.UploadRetryBudget, time.Duration(0), "the shipped default must bound the retry budget")

	o.Enable = true
	o.Url = srv.URL
	client, err := o.Client()
	require.NoError(t, err)
	require.NotNil(t, client)

	gitoid, err := client.Store(context.Background(), dsse.Envelope{
		Payload: []byte(`{}`), PayloadType: "test",
	})
	require.NoError(t, err, "two transient 504s must not destroy a cilock run's upload")
	require.Equal(t, "gitoid-after-retry", gitoid)
	require.EqualValues(t, 3, calls.Load())
}

// A terminal status must still fail on the first attempt through the product
// path — no retry storm against an already-saturated backend, and no turning a
// permission error into a slow permission error.
func TestArchivistaClient_StillFailsFastOnForbidden(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Invalid API credential"))
	}))
	t.Cleanup(srv.Close)

	o := archivistaOptionsFromFlags(t)
	o.Enable = true
	o.Url = srv.URL
	client, err := o.Client()
	require.NoError(t, err)

	_, err = client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load(), "403 must be attempted exactly once")

	var se *archivista.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, http.StatusForbidden, se.StatusCode)
}

// The escape hatch has to actually work — an operator who needs the old
// single-attempt behaviour (or a test harness that cannot tolerate sleeps)
// must be able to turn retry off.
func TestArchivistaClient_RetriesDisabledByFlag(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	o := archivistaOptionsFromFlags(t, "--archivista-upload-retries=0")
	o.Enable = true
	o.Url = srv.URL
	client, err := o.Client()
	require.NoError(t, err)

	_, err = client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load())
}

func TestArchivistaClient_RetryFlagsAreParsed(t *testing.T) {
	o := archivistaOptionsFromFlags(t,
		"--archivista-upload-retries=2",
		"--archivista-upload-retry-budget=7s",
	)
	require.Equal(t, 2, o.UploadRetries)
	require.Equal(t, 7*time.Second, o.UploadRetryBudget)
}
