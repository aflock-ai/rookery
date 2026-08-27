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

package archivista

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/stretchr/testify/require"
)

// testEnvelope is the throwaway payload every retry test uploads. Content is
// irrelevant to retry behaviour; only the request COUNT and the classification
// of the failure matter.
func testEnvelope() dsse.Envelope {
	return dsse.Envelope{Payload: []byte(`{"_type":"test"}`), PayloadType: "test"}
}

// fastRetry is a policy with the real classification but no wall-clock cost.
// Delays are recorded by installFakeClock instead of slept.
func fastRetry(maxAttempts int) RetryPolicy {
	return RetryPolicy{
		MaxAttempts: maxAttempts,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    2 * time.Second,
		Budget:      time.Hour,
	}
}

// installFakeClock swaps the retry sleep/now seams so backoff is instant and
// the requested delays are observable. Returns a pointer to the recorded
// delays. A fake clock is what makes the budget assertion deterministic:
// virtual time advances by exactly the delay each sleep would have taken.
func installFakeClock(t *testing.T) *[]time.Duration {
	t.Helper()
	var delays []time.Duration
	virtual := time.Unix(0, 0)

	origSleep, origNow := retrySleep, retryNow
	retrySleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		delays = append(delays, d)
		virtual = virtual.Add(d)
		return nil
	}
	retryNow = func() time.Time { return virtual }
	t.Cleanup(func() { retrySleep, retryNow = origSleep, origNow })
	return &delays
}

// countingServer returns a test server plus a live request counter. handler is
// invoked with the 1-based attempt number so a test can script a failure
// sequence.
func countingServer(t *testing.T, handler func(attempt int, w http.ResponseWriter, r *http.Request)) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(int(calls.Add(1)), w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// --- acceptance criterion: retries a transient 5xx ---------------------------

func TestStore_Retries504ThenSucceeds(t *testing.T) {
	installFakeClock(t)
	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
		if attempt <= 3 {
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte("upstream timed out"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"gitoid":"abc123"}`))
	})

	c := New(srv.URL, WithRetry(fastRetry(5)))
	gitoid, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err, "three transient 504s must not destroy the upload")
	require.Equal(t, "abc123", gitoid)
	require.EqualValues(t, 4, calls.Load(), "expected 3 failed attempts + 1 success")
}

func TestStore_RetriesEveryServerErrorClass(t *testing.T) {
	for _, code := range []int{500, 502, 503, 504, 507, 599} {
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			installFakeClock(t)
			srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
				if attempt == 1 {
					w.WriteHeader(code)
					return
				}
				_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
			})
			c := New(srv.URL, WithRetry(fastRetry(3)))
			_, err := c.Store(context.Background(), testEnvelope())
			require.NoError(t, err)
			require.EqualValues(t, 2, calls.Load(), "any 5xx is a server-side failure and must be retried")
		})
	}
}

func TestStore_RetriesTransportLevelCodes(t *testing.T) {
	// 408 Request Timeout and 425 Too Early are transient by definition even
	// though they are 4xx. Pinned so a future "4xx == terminal" simplification
	// cannot silently make them fatal.
	for _, code := range []int{408, 425} {
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			installFakeClock(t)
			srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
				if attempt == 1 {
					w.WriteHeader(code)
					return
				}
				_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
			})
			c := New(srv.URL, WithRetry(fastRetry(3)))
			_, err := c.Store(context.Background(), testEnvelope())
			require.NoError(t, err)
			require.EqualValues(t, 2, calls.Load())
		})
	}
}

// --- acceptance criterion: terminal failures fail FAST -----------------------

func TestStore_FailsFastOnTerminalStatus(t *testing.T) {
	// A permission error must not become a SLOW permission error, and must not
	// contribute to a retry storm against an already-saturated backend.
	for _, code := range []int{400, 401, 403, 404, 409, 422} {
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			installFakeClock(t)
			srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
				_, _ = w.Write([]byte("nope"))
			})
			c := New(srv.URL, WithRetry(fastRetry(5)))
			_, err := c.Store(context.Background(), testEnvelope())
			require.Error(t, err)
			require.EqualValues(t, 1, calls.Load(), "terminal status must be attempted exactly once")

			var se *StatusError
			require.True(t, errors.As(err, &se), "error must carry the status code as a TYPE, not only as text")
			require.Equal(t, code, se.StatusCode)
		})
	}
}

// TestStore_ClassificationIsNotStringMatching is the guard against the shape
// this bug would most plausibly be "fixed" with: sniffing strings.Contains on
// the error text. A 503 whose BODY happens to mention 403 must still retry, and
// a 403 whose body mentions 503 must still fail fast.
func TestStore_ClassificationIsNotStringMatching(t *testing.T) {
	t.Run("retryable status with terminal-looking body", func(t *testing.T) {
		installFakeClock(t)
		srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
			if attempt == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("upstream said 403 Invalid API credential"))
				return
			}
			_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
		})
		c := New(srv.URL, WithRetry(fastRetry(3)))
		_, err := c.Store(context.Background(), testEnvelope())
		require.NoError(t, err)
		require.EqualValues(t, 2, calls.Load())
	})

	t.Run("terminal status with retryable-looking body", func(t *testing.T) {
		installFakeClock(t)
		srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("503 gateway timeout connection reset"))
		})
		c := New(srv.URL, WithRetry(fastRetry(5)))
		_, err := c.Store(context.Background(), testEnvelope())
		require.Error(t, err)
		require.EqualValues(t, 1, calls.Load())
	})
}

// --- acceptance criterion: 429 honours Retry-After ---------------------------

func TestStore_Honours429RetryAfterSeconds(t *testing.T) {
	delays := installFakeClock(t)
	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
		if attempt == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithRetry(fastRetry(3)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
	require.Equal(t, []time.Duration{7 * time.Second}, *delays,
		"Retry-After must override the computed backoff exactly, with no jitter applied")
}

func TestStore_Honours429RetryAfterHTTPDate(t *testing.T) {
	delays := installFakeClock(t)
	// retryNow is pinned at the Unix epoch by the fake clock, so an HTTP-date
	// 30s past the epoch must resolve to a 30s delay.
	when := time.Unix(30, 0).UTC().Format(http.TimeFormat)
	srv, _ := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
		if attempt == 1 {
			w.Header().Set("Retry-After", when)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithRetry(fastRetry(3)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)
	require.Equal(t, []time.Duration{30 * time.Second}, *delays)
}

func TestStore_429WithoutRetryAfterStillRetries(t *testing.T) {
	installFakeClock(t)
	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
		if attempt == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithRetry(fastRetry(3)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
}

// TestStore_RetryAfterLongerThanBudgetGivesUpImmediately stops a hostile or
// misconfigured server from parking CI for hours with `Retry-After: 86400`.
// Giving up is the honest response: sleeping a clamped 10s when the server
// asked for a day just burns the budget and fails anyway.
func TestStore_RetryAfterLongerThanBudgetGivesUpImmediately(t *testing.T) {
	delays := installFakeClock(t)
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	p := fastRetry(3)
	p.Budget = 10 * time.Second
	c := New(srv.URL, WithRetry(p))
	_, err := c.Store(context.Background(), testEnvelope())
	require.Error(t, err)
	require.Empty(t, *delays, "a Retry-After longer than the whole budget must never be slept")
	require.EqualValues(t, 1, calls.Load(), "and must not drive further attempts")
}

// --- THE DEFAULT for an unrecognised failure ---------------------------------

// TestStore_UnrecognisedErrorDefaultsToRetryable pins the deliberate default.
//
// The dangerous outcome is not a wasted retry; it is a feature that is inert in
// production because the real 504 arrived wrapped in a shape the classifier did
// not enumerate. So the terminal set is a closed ALLOWLIST (caller-context done,
// or a StatusError with a non-retryable code) and EVERYTHING ELSE RETRIES,
// bounded by MaxAttempts and Budget. If this test ever flips, the retry feature
// has quietly become opt-in-by-luck.
func TestStore_UnrecognisedErrorDefaultsToRetryable(t *testing.T) {
	t.Run("connection reset mid-response", func(t *testing.T) {
		installFakeClock(t)
		srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
			if attempt <= 2 {
				// Hijack and slam the connection: the client sees a transport
				// error (*url.Error / io.ErrUnexpectedEOF), never a status code.
				hj, ok := w.(http.Hijacker)
				require.True(t, ok)
				conn, _, err := hj.Hijack()
				require.NoError(t, err)
				_ = conn.Close()
				return
			}
			_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
		})
		c := New(srv.URL, WithRetry(fastRetry(5)))
		_, err := c.Store(context.Background(), testEnvelope())
		require.NoError(t, err, "a reset connection is the canonical transient failure")
		require.EqualValues(t, 3, calls.Load())
	})

	t.Run("200 with an undecodable body", func(t *testing.T) {
		installFakeClock(t)
		srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
			if attempt == 1 {
				// A proxy interposing an HTML error page under a 200. Not a
				// StatusError, not a transport error — the unrecognised case.
				_, _ = w.Write([]byte(`<html>502 Bad Gateway</html>`))
				return
			}
			_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
		})
		c := New(srv.URL, WithRetry(fastRetry(3)))
		_, err := c.Store(context.Background(), testEnvelope())
		require.NoError(t, err)
		require.EqualValues(t, 2, calls.Load(), "an unrecognised failure must take the retryable path")
	})

	t.Run("IsRetryable says yes for a bare unknown error", func(t *testing.T) {
		require.True(t, IsRetryable(context.Background(), errors.New("something nobody enumerated")),
			"the default for an unclassified error is RETRYABLE — see the comment on this test")
	})
}

// --- the caller's context is the one terminal non-status case ----------------

func TestStore_CallerContextCancelledIsTerminal(t *testing.T) {
	installFakeClock(t)
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(srv.URL, WithRetry(fastRetry(5)))
	_, err := c.Store(ctx, testEnvelope())
	require.Error(t, err)
	require.LessOrEqual(t, calls.Load(), int64(1), "a cancelled caller context must not drive a retry loop")
}

// TestStore_ClientTimeoutIsRetryableNotTerminal is the sharp edge called out in
// review: the client's OWN http.Client.Timeout surfaces as an error that
// satisfies errors.Is(err, context.DeadlineExceeded). If the classifier treats
// every DeadlineExceeded as terminal, the single most common saturation symptom
// — a stalled upload — gets zero retries while every status-code test passes.
func TestStore_ClientTimeoutIsRetryableNotTerminal(t *testing.T) {
	installFakeClock(t)
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })

	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, r *http.Request) {
		if attempt == 1 {
			select {
			case <-stall:
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})

	// A per-request timeout far below the server's stall, with a caller context
	// that is NOT cancelled. This is exactly the production shape.
	hc := &http.Client{Timeout: 150 * time.Millisecond}
	c := New(srv.URL, WithHTTPClient(hc), WithRetry(fastRetry(4)))

	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err, "the client's own request timeout is transient and must be retried")
	require.EqualValues(t, 2, calls.Load())
}

// --- bounded budget ----------------------------------------------------------

func TestStore_RetryBudgetBoundsTotalTime(t *testing.T) {
	delays := installFakeClock(t)
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	p := RetryPolicy{MaxAttempts: 100, BaseDelay: time.Second, MaxDelay: time.Minute, Budget: 5 * time.Second}
	c := New(srv.URL, WithRetry(p))
	_, err := c.Store(context.Background(), testEnvelope())
	require.Error(t, err)

	var total time.Duration
	for _, d := range *delays {
		total += d
	}
	require.LessOrEqual(t, total, 5*time.Second, "the retry budget must bound total sleep")
	require.Less(t, calls.Load(), int64(100), "the budget, not MaxAttempts, must be what stops this")
	require.Greater(t, calls.Load(), int64(1), "the budget must still permit at least one retry")
}

func TestStore_MaxAttemptsBoundsRetries(t *testing.T) {
	installFakeClock(t)
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	c := New(srv.URL, WithRetry(fastRetry(3)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.Error(t, err)
	require.EqualValues(t, 3, calls.Load())
	require.Contains(t, err.Error(), "3 attempts", "the exhausted-retry error must say how hard it tried")
}

func TestStore_ExhaustedRetryErrorUnwrapsToStatusError(t *testing.T) {
	installFakeClock(t)
	srv, _ := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	})
	c := New(srv.URL, WithRetry(fastRetry(2)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.Error(t, err)
	var se *StatusError
	require.True(t, errors.As(err, &se), "callers must still be able to inspect the final status")
	require.Equal(t, http.StatusGatewayTimeout, se.StatusCode)
}

// --- retry stays OPT-IN for every other consumer of this client --------------

// judge-api and the policy-publish path construct this client too. Turning
// retry on by default inside New() would silently change their timing and
// failure semantics, so New() must keep the historical single-attempt
// behaviour and cilock must opt in explicitly.
func TestStore_NoRetryUnlessRequested(t *testing.T) {
	installFakeClock(t)
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := New(srv.URL)
	_, err := c.Store(context.Background(), testEnvelope())
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load())
}

func TestDefaultRetryPolicy_IsBoundedAndSane(t *testing.T) {
	p := DefaultRetryPolicy()
	require.Greater(t, p.MaxAttempts, 1, "a default of 1 attempt would make the whole feature inert")
	require.LessOrEqual(t, p.MaxAttempts, 10)
	require.Greater(t, p.Budget, time.Duration(0), "an unbounded budget can hang CI forever")
	require.LessOrEqual(t, p.Budget, 10*time.Minute)
	require.Greater(t, p.BaseDelay, time.Duration(0))
	require.LessOrEqual(t, p.BaseDelay, p.MaxDelay)
}

// --- a retried attempt must replay the FULL body -----------------------------

// The body is an io.Reader consumed by the first attempt. If the retry loop
// reuses the spent reader, attempt 2 uploads zero bytes and Archivista happily
// content-addresses the empty envelope. That failure is invisible to a test
// that only asserts "no error", so assert the bytes on the wire.
func TestStore_RetriesReplayTheCompleteBody(t *testing.T) {
	installFakeClock(t)
	var digests []string
	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		digests = append(digests, sha256Hex(b))
		if attempt <= 2 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithRetry(fastRetry(5)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)
	require.EqualValues(t, 3, calls.Load())
	require.Len(t, digests, 3)
	require.NotEqual(t, sha256Hex(nil), digests[0], "sanity: attempt 1 sent a non-empty body")
	for i, d := range digests {
		require.Equal(t, digests[0], d, "retry attempt %d replayed a truncated or empty body", i+1)
	}
}

// --- logging: the classification decision must be observable -----------------

// captureLogger records every formatted line at each level so a test can assert
// on what an operator would actually see.
type captureLogger struct {
	mu    sync.Mutex
	lines map[string][]string
}

func newCaptureLogger(t *testing.T) *captureLogger {
	t.Helper()
	c := &captureLogger{lines: map[string][]string{}}
	orig := log.GetLogger()
	log.SetLogger(c)
	t.Cleanup(func() { log.SetLogger(orig) })
	return c
}

func (c *captureLogger) add(level, s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines[level] = append(c.lines[level], s)
}

func (c *captureLogger) at(level string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines[level]...)
}

func (c *captureLogger) joined(level string) string { return strings.Join(c.at(level), "\n") }

func (c *captureLogger) Errorf(f string, a ...interface{}) { c.add("error", fmt.Sprintf(f, a...)) }
func (c *captureLogger) Error(a ...interface{})            { c.add("error", fmt.Sprint(a...)) }
func (c *captureLogger) Warnf(f string, a ...interface{})  { c.add("warn", fmt.Sprintf(f, a...)) }
func (c *captureLogger) Warn(a ...interface{})             { c.add("warn", fmt.Sprint(a...)) }
func (c *captureLogger) Debugf(f string, a ...interface{}) { c.add("debug", fmt.Sprintf(f, a...)) }
func (c *captureLogger) Debug(a ...interface{})            { c.add("debug", fmt.Sprint(a...)) }
func (c *captureLogger) Infof(f string, a ...interface{})  { c.add("info", fmt.Sprintf(f, a...)) }
func (c *captureLogger) Info(a ...interface{})             { c.add("info", fmt.Sprint(a...)) }

func TestStore_LogsClassificationOnRetryableFailure(t *testing.T) {
	installFakeClock(t)
	cl := newCaptureLogger(t)
	srv, _ := countingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
		if attempt == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithRetry(fastRetry(3)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)

	warn := cl.joined("warn")
	require.Contains(t, warn, "classification=retryable", "the classifier's DECISION is the field we will need in production")
	require.Contains(t, warn, "reason=", "the decision must say WHY it chose that bucket")
	require.Contains(t, warn, "status=504", "the observed HTTP status must be logged")
	require.Contains(t, warn, "attempt=1", "attempt N of M must be logged")
	require.Contains(t, warn, "backoff=", "the sleep it is about to take must be logged")

	// Success after a retry must be visible — a silent success hides that we
	// are riding on retries, which is the signal for whether the DB work helps.
	info := cl.joined("info")
	require.Contains(t, info, "attempts=2")
	require.Contains(t, info, "elapsed=")
}

func TestStore_LogsTerminalClassification(t *testing.T) {
	installFakeClock(t)
	cl := newCaptureLogger(t)
	srv, _ := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c := New(srv.URL, WithRetry(fastRetry(5)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.Error(t, err)

	errLines := cl.joined("error")
	require.Contains(t, errLines, "classification=terminal")
	require.Contains(t, errLines, "status=403")
	require.Contains(t, errLines, "attempts=1")
	require.Contains(t, errLines, "elapsed=")
}

// TestStore_LogsTheActualErrorShapeNotASummary is the one that matters when the
// classifier misfires. A 504 that reaches us as a client-timeout does NOT carry
// a status code, so the log has to name the concrete error type it saw —
// otherwise the production question "what did the classifier think this was"
// has no answer.
func TestStore_LogsTheActualErrorShapeNotASummary(t *testing.T) {
	installFakeClock(t)
	cl := newCaptureLogger(t)
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	srv, _ := countingServer(t, func(attempt int, w http.ResponseWriter, r *http.Request) {
		if attempt == 1 {
			select {
			case <-stall:
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithHTTPClient(&http.Client{Timeout: 150 * time.Millisecond}), WithRetry(fastRetry(4)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)

	warn := cl.joined("warn")
	require.Contains(t, warn, "classification=retryable")
	require.Contains(t, warn, "errtype=*url.Error", "the concrete Go error type the classifier received must be logged")
	require.Contains(t, warn, "deadline_exceeded=true",
		"a client-timeout that unwraps to context.DeadlineExceeded is exactly the case that silently breaks — log it explicitly")
}

// Credentials must never reach the log, even though the request carries them.
func TestStore_LogsNeverLeakCredentialsOrEnvelopeBody(t *testing.T) {
	installFakeClock(t)
	cl := newCaptureLogger(t)
	const secret = "super-secret-bearer-token"
	srv, _ := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("saturated"))
	})
	h := http.Header{}
	h.Set("Authorization", "Bearer "+secret)
	c := New(srv.URL, WithHeaders(h), WithRetry(fastRetry(2)))
	_, err := c.Store(context.Background(), dsse.Envelope{
		Payload: []byte(`{"sensitive":"envelope-payload-content"}`), PayloadType: "test",
	})
	require.Error(t, err)

	for _, level := range []string{"debug", "info", "warn", "error"} {
		joined := cl.joined(level)
		require.NotContains(t, joined, secret, "%s log leaked the bearer token", level)
		require.NotContains(t, joined, "envelope-payload-content", "%s log leaked the envelope body", level)
	}
}

func TestStore_LogsAttemptDetailAtDebug(t *testing.T) {
	installFakeClock(t)
	cl := newCaptureLogger(t)
	srv, _ := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})
	c := New(srv.URL, WithRetry(fastRetry(3)))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)

	dbg := cl.joined("debug")
	require.Contains(t, dbg, "attempt=1")
	require.Contains(t, dbg, "bytes=", "envelope size must be logged")
	require.Contains(t, dbg, "elapsed=", "per-attempt latency must be logged")
	require.Contains(t, dbg, "host=", "the endpoint host must be logged")

	// Host only — a full URL can carry query-string credentials.
	require.NotContains(t, dbg, "/upload?")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- the budget/timeout interaction that silently disables retry ------------

// TestDefaultRetryPolicy_BudgetExceedsOneRequestTimeout pins a relationship
// between two constants that is easy to break and impossible to see.
//
// The budget is wall-clock from the first attempt, so time spent WAITING ON A
// REQUEST is charged against it, not just time spent sleeping. That is the
// correct semantics — it is what bounds total run time — but it means a
// default Budget below defaultHTTPTimeout makes retry inert for the single
// most important case: an upload that stalls until the client's own timeout
// fires has already burnt the entire budget by the time it fails, so it gets
// zero retries and the operator loses the gate run anyway.
//
// Every fake-clock test in this file passes either way, because virtual time
// does not advance during a request. This assertion is the guard.
func TestDefaultRetryPolicy_BudgetExceedsOneRequestTimeout(t *testing.T) {
	p := DefaultRetryPolicy()
	require.Greater(t, p.Budget, defaultHTTPTimeout,
		"a retry budget below one request timeout gives a STALLED upload zero retries — "+
			"the exact failure this retry exists to absorb")
}

// TestStore_StalledRequestStillRetriesOnRealClock proves the mechanism on the
// real clock rather than the virtual one, at miniature scale: a request that
// stalls past the client timeout must still be retried when the budget leaves
// room for it.
func TestStore_StalledRequestStillRetriesOnRealClock(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, r *http.Request) {
		if attempt == 1 {
			select {
			case <-release:
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"ok"}`))
	})

	const requestTimeout = 200 * time.Millisecond
	p := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		// Mirrors the production invariant: budget > one request timeout.
		Budget: 4 * requestTimeout,
	}
	c := New(srv.URL, WithHTTPClient(&http.Client{Timeout: requestTimeout}), WithRetry(p))

	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err, "a stalled first attempt must still be retried")
	require.EqualValues(t, 2, calls.Load())
}

// The inverse, documenting the trap explicitly: when the budget is smaller than
// a single request timeout, the first stall consumes it and no retry happens.
func TestStore_BudgetBelowRequestTimeoutYieldsNoRetry(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})

	const requestTimeout = 200 * time.Millisecond
	p := RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		Budget:      requestTimeout / 4,
	}
	c := New(srv.URL, WithHTTPClient(&http.Client{Timeout: requestTimeout}), WithRetry(p))

	start := time.Now()
	_, err := c.Store(context.Background(), testEnvelope())
	elapsed := time.Since(start)
	require.Error(t, err)
	require.ErrorContains(t, err, "retry budget")
	require.EqualValues(t, 1, calls.Load(),
		"documents WHY DefaultRetryPolicy.Budget must exceed defaultHTTPTimeout")
	// The same property as TestStore_BudgetBoundsASlowFinalAttempt, from the
	// other side: the stalled attempt is cut at the budget rather than being
	// left to run out the 200ms request timeout it started under.
	require.Less(t, elapsed, requestTimeout,
		"the budget must cut the in-flight attempt, not wait for its request timeout (measured %s)", elapsed)
}

// --- the budget bounds TOTAL runtime, not just the sleeps --------------------

// TestStore_BudgetBoundsASlowFinalAttempt is the test the budget arithmetic
// could not pass on its own.
//
// Raising Budget above defaultHTTPTimeout fixed the numbers but not the
// mechanism: while the deadline was only consulted BEFORE a sleep, an attempt
// that began a millisecond under it still got a whole fresh http.Client.Timeout
// to itself, so total runtime overshot the budget by up to one request timeout
// for ANY value of the budget. Here attempt 1 burns most of the budget and then
// attempt 2 hangs; before the attempts ran under the budget's own deadline this
// measured 4.7s against a 1s budget.
//
// It uses the REAL clock deliberately. Every fake-clock test in this file would
// pass either way, because virtual time does not advance while a request is in
// flight — which is precisely how the bug survived the original suite.
func TestStore_BudgetBoundsASlowFinalAttempt(t *testing.T) {
	const budget = 1 * time.Second
	const requestTimeout = 2 * time.Second

	release := make(chan struct{})
	srv, calls := countingServer(t, func(attempt int, w http.ResponseWriter, r *http.Request) {
		if attempt == 1 {
			// Consume most of the budget, so attempt 2 starts just under it.
			time.Sleep(700 * time.Millisecond)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(requestTimeout + time.Second):
		}
	})
	// Registered AFTER countingServer so cleanup LIFO releases the hung handler
	// before httptest.Server.Close waits on it.
	t.Cleanup(func() { close(release) })

	p := RetryPolicy{
		MaxAttempts: 50, // high, so MaxAttempts cannot be what stops this
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		Budget:      budget,
	}
	c := New(srv.URL, WithHTTPClient(&http.Client{Timeout: requestTimeout}), WithRetry(p))

	start := time.Now()
	_, err := c.Store(context.Background(), testEnvelope())
	elapsed := time.Since(start)

	require.Error(t, err)
	require.EqualValues(t, 2, calls.Load(), "attempt 2 must have started, so it is a stalled attempt being cut")
	require.LessOrEqual(t, elapsed, budget+600*time.Millisecond,
		"the retry budget must bound TOTAL runtime; an attempt in flight when it expires is cut, "+
			"not allowed to run out its own request timeout (measured %s against a %s budget)", elapsed, budget)
	require.ErrorIs(t, err, ErrRetryBudgetExhausted)
}

// --- budget expiry is TERMINAL, and is not a user cancellation ---------------

// TestClassify_BudgetExpiryIsTerminalNotARetryableTimeout pins the one
// distinction the whole loop rests on.
//
// A budget-expired attempt and the client's own http.Client.Timeout produce the
// SAME error shape, so nothing in the error can separate them; only which
// context is done can. Get it wrong towards retryable and the loop spins
// against a deadline that is already gone; get it wrong towards terminal and a
// bare stalled upload — the exact symptom this retry exists for — gets zero
// retries and the feature is inert while every status-code test still passes.
func TestClassify_BudgetExpiryIsTerminalNotARetryableTimeout(t *testing.T) {
	caller := context.Background()
	expired, cancel := retryBudgetContext(caller, -time.Second)
	defer cancel()
	require.Error(t, expired.Err(), "precondition: the budget context must already be done")

	// Exactly what the client's own request timeout produces.
	timeoutErr := &url.Error{Op: "Post", URL: "http://archivista.invalid/upload", Err: context.DeadlineExceeded}

	bucket, reason := classify(caller, expired, timeoutErr)
	require.Equal(t, classTerminal, bucket, "a spent budget cannot be spent again")
	require.Equal(t, reasonBudgetExhausted, reason)

	// The very same error, with budget left, must still retry.
	bucket, reason = classify(caller, caller, timeoutErr)
	require.Equal(t, classRetryable, bucket, "a bare client timeout is the saturation symptom, not a verdict")
	require.Equal(t, reasonTransport, reason)

	// And the caller's own cancellation outranks both.
	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	bucket, reason = classify(cancelled, cancelled, timeoutErr)
	require.Equal(t, classTerminal, bucket)
	require.Equal(t, reasonCallerDone, reason)
}

// TestStore_BudgetExpiryDoesNotLookLikeACancellation is the same property
// end-to-end. Budget exhaustion means the server never came back; a Canceled
// identity would tell the caller a human abandoned the run, and an operator
// triaging a real outage would dismiss it.
func TestStore_BudgetExpiryDoesNotLookLikeACancellation(t *testing.T) {
	release := make(chan struct{})
	srv, calls := countingServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})
	// See the note in TestStore_BudgetBoundsASlowFinalAttempt: cleanup is LIFO.
	t.Cleanup(func() { close(release) })

	p := RetryPolicy{
		MaxAttempts: 50, // the budget, not MaxAttempts, must be what stops this
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Budget:      400 * time.Millisecond,
	}
	c := New(srv.URL, WithHTTPClient(&http.Client{Timeout: 3 * time.Second}), WithRetry(p))

	start := time.Now()
	_, err := c.Store(context.Background(), testEnvelope())
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrRetryBudgetExhausted, "the caller must be able to tell a spent budget from anything else")
	require.NotErrorIs(t, err, context.Canceled, "budget exhaustion is not the user abandoning the upload")
	require.LessOrEqual(t, elapsed, time.Second, "measured %s", elapsed)
	require.Less(t, calls.Load(), int64(50), "the loop must stop at the budget, not spin to MaxAttempts")
}

// --- cancellation identity survives the backoff ------------------------------

// TestStore_CancellationDuringBackoffKeepsItsIdentity covers the review
// finding: the abort error used to format the cancellation with %v, so
// errors.Is(err, context.Canceled) — the normal way a caller tells "the user hit
// Ctrl-C" from "the server is broken" — answered false whenever the
// cancellation landed during a backoff sleep.
//
// The cancellation is driven from inside the sleep seam so that it happens
// DURING backoff by construction rather than by racing a timer against the
// first attempt.
func TestStore_CancellationDuringBackoffKeepsItsIdentity(t *testing.T) {
	slowBackoff := RetryPolicy{MaxAttempts: 5, BaseDelay: time.Second, MaxDelay: time.Second, Budget: time.Minute}

	t.Run("caller cancelled", func(t *testing.T) {
		srv, _ := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		origSleep := retrySleep
		retrySleep = func(c context.Context, d time.Duration) error {
			cancel() // we are now inside the backoff, by construction
			return origSleep(c, d)
		}
		t.Cleanup(func() { retrySleep = origSleep })

		_, err := New(srv.URL, WithRetry(slowBackoff)).Store(ctx, testEnvelope())
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled,
			"a caller checking for Ctrl-C must get the right answer even when it lands mid-backoff")
		var se *StatusError
		require.ErrorAs(t, err, &se, "and the failure that put us in backoff must stay reachable")
		require.Equal(t, http.StatusServiceUnavailable, se.StatusCode)
		require.NotErrorIs(t, err, ErrRetryBudgetExhausted, "the budget was untouched")
	})

	t.Run("caller deadline exceeded", func(t *testing.T) {
		srv, _ := countingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})

		origSleep := retrySleep
		retrySleep = func(c context.Context, d time.Duration) error {
			<-c.Done() // the caller's deadline fires while we are asleep
			return origSleep(c, d)
		}
		t.Cleanup(func() { retrySleep = origSleep })

		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		t.Cleanup(cancel)

		_, err := New(srv.URL, WithRetry(slowBackoff)).Store(ctx, testEnvelope())
		require.Error(t, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		var se *StatusError
		require.ErrorAs(t, err, &se)
		require.Equal(t, http.StatusServiceUnavailable, se.StatusCode)
	})
}

// --- New() must not narrow the caller's context ------------------------------

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestStore_WithoutRetryImposesNoDeadlineOfItsOwn guards the blast radius of
// enforcing the budget with a context deadline.
//
// judge-api and the policy-publish path build this client through plain New(),
// which promises them the historical single-attempt behaviour. The retry policy
// still carries DefaultRetryPolicy's Budget in that case, and once the budget
// became a real context deadline rather than a number consulted between
// attempts, honouring it here would have quietly capped every one of their
// uploads at 4 minutes — a timing change they never opted into, invisible until
// something slow hit it in production. There are no retries to bound without
// WithRetry, so there must be no deadline either.
func TestStore_WithoutRetryImposesNoDeadlineOfItsOwn(t *testing.T) {
	var sawDeadline bool
	var calls int
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		_, sawDeadline = r.Context().Deadline()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"gitoid":"ok"}`)),
			Header:     http.Header{},
		}, nil
	})

	c := New("http://archivista.invalid", WithHTTPClient(&http.Client{Transport: rt}))
	_, err := c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.False(t, sawDeadline,
		"New() must not narrow the caller's context; judge-api and policy-publish share this client")

	// With WithRetry the deadline is exactly what the caller asked for.
	sawDeadline = false
	c = New("http://archivista.invalid",
		WithHTTPClient(&http.Client{Transport: rt}),
		WithRetry(RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond, Budget: time.Minute}))
	_, err = c.Store(context.Background(), testEnvelope())
	require.NoError(t, err)
	require.True(t, sawDeadline, "opting in to a retry budget must actually bound the attempts")
}
