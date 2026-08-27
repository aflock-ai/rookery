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
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/stretchr/testify/require"
)

const testPlatform = "https://platform.example.com"

func storeStatus(code int, body string) error {
	return fmt.Errorf("archivista store: %w",
		&archivista.StatusError{Op: "store", StatusCode: code, Body: body})
}

// An auth rejection must still surface the one-time `cilock trust` fix rather
// than a raw "Invalid API credential".
func TestUploadError_AuthStatusSuggestsTrust(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			err := uploadError(testPlatform, storeStatus(code, "Invalid API credential"))
			require.ErrorContains(t, err, "cilock trust")
			require.ErrorContains(t, err, testPlatform)
		})
	}
}

// TestUploadError_ClassifiesOnStatusNotMessageText is the regression this
// change fixes. uploadError used to run strings.Contains over the error text,
// and the error text embeds up to 500 bytes of server response body — so a
// saturated-backend 503 whose body happened to quote "401" was reported to the
// operator as an identity/trust problem, sending them to `cilock trust` for a
// failure that had nothing to do with credentials.
func TestUploadError_ClassifiesOnStatusNotMessageText(t *testing.T) {
	err := uploadError(testPlatform, storeStatus(http.StatusServiceUnavailable,
		"upstream returned 401 Invalid API credential while proxying"))
	require.NotContains(t, err.Error(), "cilock trust",
		"a 503 is not an auth failure however its body reads")
	require.ErrorContains(t, err, "re-run `cilock run`")
}

// The mirror image: a genuine 403 whose body quotes transient-sounding text
// must still be reported as the auth problem it is.
func TestUploadError_AuthStatusWithTransientLookingBody(t *testing.T) {
	err := uploadError(testPlatform, storeStatus(http.StatusForbidden,
		"503 gateway timeout connection reset"))
	require.ErrorContains(t, err, "cilock trust")
}

// A non-auth failure must name the recovery. There is deliberately no command
// that uploads a previously-signed bundle — an attestation is evidence of an
// execution, so re-running the gate IS the recovery — and the message has to
// say that rather than leave an operator hunting for an upload subcommand.
func TestUploadError_NonAuthNamesTheRecovery(t *testing.T) {
	err := uploadError(testPlatform, storeStatus(http.StatusGatewayTimeout, "upstream timed out"))
	require.ErrorContains(t, err, "re-run `cilock run`")
	require.ErrorContains(t, err, "--archivista-upload-retries")
	require.NotContains(t, err.Error(), "cilock trust")
}

// A terminal status that never entered the retry loop must not be described as
// having been retried.
func TestUploadError_DoesNotClaimRetriesThatNeverHappened(t *testing.T) {
	err := uploadError(testPlatform, storeStatus(http.StatusBadRequest, "malformed envelope"))
	require.NotContains(t, err.Error(), "after retrying")
	require.NotContains(t, err.Error(), "gave up after")
}

// When retries DID run, the client's own wrapped message carries the count, so
// the operator still learns how hard it tried.
func TestUploadError_PreservesExhaustedRetryDetail(t *testing.T) {
	inner := fmt.Errorf("%w (gave up after 5 attempts in 7.5s)",
		&archivista.StatusError{Op: "store", StatusCode: http.StatusGatewayTimeout, Body: "timeout"})
	err := uploadError(testPlatform, inner)
	require.ErrorContains(t, err, "gave up after 5 attempts")
}

// An error with no status at all (a transport failure) must not be mistaken
// for an auth rejection.
func TestUploadError_UntypedErrorIsNotTreatedAsAuth(t *testing.T) {
	err := uploadError(testPlatform, errors.New("dial tcp: connection reset by peer 403"))
	require.NotContains(t, err.Error(), "cilock trust")
	require.ErrorContains(t, err, "re-run `cilock run`")
}

// Without a platform URL there is no `cilock trust` target to recommend.
func TestUploadError_NoPlatformURLSkipsTrustAdvice(t *testing.T) {
	err := uploadError("", storeStatus(http.StatusForbidden, "denied"))
	require.NotContains(t, err.Error(), "cilock trust")
}
