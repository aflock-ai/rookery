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
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aflock-ai/rookery/attestation/log"
)

// StatusError is a non-2xx response from Archivista, carrying the status code
// as DATA rather than as text baked into an error string.
//
// This type exists because the alternative — deciding whether a failure is
// worth retrying by running strings.Contains over the error message — is
// unsound in both directions. Archivista includes up to 500 bytes of the
// response body in the error, so a 503 whose body reads "upstream said 403"
// would be classified terminal, and a 403 whose body mentions "gateway
// timeout" would be retried against a permission wall. The status code is the
// only trustworthy signal, so it travels as a field.
type StatusError struct {
	// Op is the client operation ("store", "download", "graphql"). It is part
	// of Error() so the historical message text is unchanged.
	Op string
	// StatusCode is the HTTP status Archivista returned.
	StatusCode int
	// Body is the truncated response body, for diagnostics.
	Body string
	// RetryAfter is the raw Retry-After response header, empty when absent.
	RetryAfter string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("archivista %s returned %d: %s", e.Op, e.StatusCode, e.Body)
}

// Retryable reports whether this status is worth another attempt.
//
// Every 5xx is retryable: the request was well-formed enough to reach the
// server, and the failure is on the server's side. Enumerating only the
// familiar 502/503/504 would leave a 500 from a query_canceled (Postgres
// 57014 under I/O saturation — the exact failure this retry exists for) or a
// 507/599 from an intermediary sitting in the terminal bucket.
//
// Three 4xx codes join them because they are transient by definition:
// 408 Request Timeout, 425 Too Early, 429 Too Many Requests. Every other 4xx
// is a statement about the request itself — retrying a 401/403/422 cannot
// change the outcome, and turning a permission error into a slow permission
// error is a regression, not a fix.
func (e *StatusError) Retryable() bool {
	if e == nil {
		return false
	}
	switch e.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return e.StatusCode >= 500
}

// reason is the short machine-greppable label for why this status landed in
// the bucket it did. It is logged so that a production misclassification can
// be diagnosed from logs alone.
func (e *StatusError) reason() string {
	switch {
	case e.StatusCode == http.StatusTooManyRequests:
		return "rate_limited"
	case e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooEarly:
		return "transient_status"
	case e.StatusCode >= 500:
		return "server_error"
	default:
		return "client_error"
	}
}

// retryAfterDelay parses the Retry-After header relative to now, supporting
// both forms RFC 9110 allows: delay-seconds and an HTTP-date. Returns false
// when the header is absent, unparseable, or in the past.
func (e *StatusError) retryAfterDelay(now time.Time) (time.Duration, bool) {
	if e == nil || e.RetryAfter == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(e.RetryAfter); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(e.RetryAfter); err == nil {
		if d := when.Sub(now); d > 0 {
			return d, true
		}
		return 0, false
	}
	return 0, false
}

// RetryPolicy bounds how hard the client tries to complete an upload before
// giving up. Both bounds are load-bearing: MaxAttempts stops a retry storm
// against an already-saturated backend, and Budget stops CI hanging.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts including the first.
	MaxAttempts int
	// BaseDelay is the first backoff interval; it doubles each attempt.
	BaseDelay time.Duration
	// MaxDelay caps a single backoff interval.
	MaxDelay time.Duration
	// Budget caps TOTAL WALL-CLOCK time from the first attempt: the requests
	// themselves as well as the sleeps between them. It is enforced by a
	// deadline on the context the attempts run under, so an attempt that is
	// still in flight when the budget runs out is cut off rather than being
	// allowed to finish its own request timeout first. Zero disables it.
	Budget time.Duration
}

// DefaultRetryPolicy is the policy cilock installs for `cilock run` uploads.
//
// Five attempts with 500ms doubling backoff is ~7.5s of sleep against a server
// that fails fast, so the common case costs almost nothing.
//
// The Budget is expressed as a MULTIPLE OF defaultHTTPTimeout rather than as a
// flat number of seconds, and that is load-bearing rather than stylistic. The
// budget is wall-clock from the first attempt — time spent waiting on a
// request counts against it, which is what bounds total run time — so a budget
// smaller than one request timeout would mean a STALLED upload consumed the
// entire budget before its first failure and got zero retries. That is exactly
// the saturation symptom this retry exists to absorb, so the feature would
// have been inert in production while every unit test passed. Deriving it here
// makes the two constants impossible to drift apart silently, and
// TestDefaultRetryPolicy_BudgetExceedsOneRequestTimeout pins the invariant.
//
// The resulting worst case is the budget itself — 4 minutes, because the
// budget bounds the attempts and not merely the sleeps between them — which is
// cheaper than the ~6 minutes of test execution that losing the whole gate run
// costs. Note that the second stalled attempt is the one the budget cuts short;
// that is intended, since a stall we already waited out once is not going to
// complete in the seconds that remain.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   500 * time.Millisecond,
		MaxDelay:    15 * time.Second,
		Budget:      2 * defaultHTTPTimeout,
	}
}

// normalize clamps a caller-supplied policy into a usable shape so a zero or
// negative field degrades to "one attempt, no sleeping" instead of panicking
// or looping forever.
func (p RetryPolicy) normalize() RetryPolicy {
	if p.MaxAttempts < 1 {
		p.MaxAttempts = 1
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = DefaultRetryPolicy().BaseDelay
	}
	if p.MaxDelay < p.BaseDelay {
		p.MaxDelay = p.BaseDelay
	}
	if p.Budget < 0 {
		p.Budget = 0
	}
	return p
}

// backoff returns the sleep before the given 1-based attempt's retry:
// exponential from BaseDelay, capped at MaxDelay, then multiplied by a random
// factor in [0.5, 1.0). The jitter is not decoration — every cilock run in a
// CI fleet sees the same 503 at the same moment, and un-jittered backoff would
// re-synchronise them into a second thundering herd against a database that is
// already the bottleneck.
func (p RetryPolicy) backoff(attempt int) time.Duration {
	d := p.BaseDelay
	for i := 1; i < attempt && d < p.MaxDelay; i++ {
		d *= 2
	}
	if d > p.MaxDelay {
		d = p.MaxDelay
	}
	half := d / 2
	if half <= 0 {
		return d
	}
	// G404 is not applicable: this jitter spreads retry timing across a CI
	// fleet, it does not protect anything. A CSPRNG here would buy no security
	// property and would make backoff depend on entropy availability.
	return half + time.Duration(rand.Int64N(int64(half))) //nolint:gosec // non-cryptographic backoff jitter
}

// WithRetry enables bounded retry of Store on retryable failures.
//
// Retry is OPT-IN, and New() deliberately leaves it off. This client is also
// used by judge-api and by the policy-publish path; silently changing the
// timing and failure semantics of every consumer to fix a cilock run problem
// would be a much larger blast radius than the bug warrants. cilock's
// ArchivistaOptions turns it on for the `cilock run` upload path.
func WithRetry(p RetryPolicy) Option {
	return func(c *Client) {
		normalized := p.normalize()
		c.retry = &normalized
	}
}

// ErrRetryBudgetExhausted is the identity a caller switches on when the upload
// was abandoned because the retry budget ran out, as opposed to because the
// user abandoned it.
//
// The distinction is not cosmetic. Budget exhaustion arrives wearing the same
// clothes as a user cancellation — the attempt context is done and the
// transport error unwraps to a context error — so without a sentinel the
// caller cannot tell "the server never came back" from "somebody pressed
// Ctrl-C". Only the former means the outage is real.
var ErrRetryBudgetExhausted = errors.New("archivista upload retry budget exhausted")

// Seams for tests: virtual time makes backoff assertions deterministic and
// free. Production values are the real clock.
var (
	retrySleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	retryNow = time.Now

	// retryBudgetContext derives the context that carries the retry budget's
	// deadline. It is a SEAM, and it deliberately reads the real clock rather
	// than retryNow, because a context deadline can only ever fire on the real
	// clock — handing context.WithDeadline a virtual timestamp would arm it in
	// 1970 and expire every fake-clock test instantly. Virtual-clock tests are
	// unaffected in practice: their budgets are seconds-to-hours while the test
	// itself finishes in milliseconds, so this deadline simply never fires and
	// the virtual budget accounting in next() is what bounds them.
	retryBudgetContext = func(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
		return context.WithDeadlineCause(parent, time.Now().Add(budget), ErrRetryBudgetExhausted)
	}
)

// IsRetryable is the classification decision, and its DEFAULT is deliberate.
//
// The terminal set is a closed allowlist:
//   - the caller's context is done — the whole operation is being abandoned,
//     so another attempt is pointless work against a dying deadline; and
//   - a StatusError whose code says the request itself is the problem.
//
// EVERYTHING ELSE RETRIES. That default is the opposite of the intuitive one,
// and it is chosen because the two failure modes are wildly asymmetric. A
// wrongly-retried error costs at most the retry budget and then surfaces the
// same error. A wrongly-terminal error costs an entire gate run — and it does
// so silently, in production, while every unit test still passes, because the
// way it happens is a real 504 arriving in a wrapper nobody enumerated.
//
// The concrete instance of that: the client's own http.Client.Timeout fires as
// a *url.Error that satisfies errors.Is(err, context.DeadlineExceeded). A
// classifier that treats DeadlineExceeded as terminal would give zero retries
// to the single most common saturation symptom. Checking the CALLER's context
// separately — rather than sniffing the error for a deadline — is what keeps
// those two cases apart.
//
// ctx is the CALLER's context. Exhaustion of the retry budget is deliberately
// not this predicate's business: the budget belongs to a particular upload
// loop, so storeWithRetry decides it against the narrowed attempt context. See
// classify.
func IsRetryable(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Retryable()
	}
	return true
}

// Classification buckets, as they appear in logs. Grep for
// "classification=terminal" to find uploads that were never retried.
const (
	classRetryable = "retryable"
	classTerminal  = "terminal"
)

// Reasons that are load-bearing beyond logging, so they are not spelled twice.
const (
	reasonCallerDone      = "caller_context_done"
	reasonBudgetExhausted = "budget_exhausted"
	reasonTransport       = "transport_error"
)

// classify returns the bucket label and the reason, for logging.
//
// It takes BOTH contexts, and the order of the two checks is the whole point.
// callerCtx is the caller's own; attemptCtx is callerCtx narrowed by the retry
// budget's deadline. A failed attempt can look identical in the two cases that
// matter — the client's own http.Client.Timeout and the budget deadline both
// surface as a *url.Error unwrapping to context.DeadlineExceeded — so the error
// itself cannot tell them apart. WHICH CONTEXT IS DONE is the only signal:
//
//   - callerCtx done   -> the whole operation is being abandoned;
//   - attemptCtx done  -> the budget is spent, and spending more of a budget
//     that is already gone is not a thing that can succeed;
//   - neither done      -> the request timed out on its own, which is precisely
//     the saturation symptom this retry exists to absorb, so it RETRIES.
//
// Getting this backwards in either direction is expensive: classifying budget
// expiry as retryable spins the loop against a dead deadline, and classifying a
// bare client timeout as terminal makes the whole feature inert.
func classify(callerCtx, attemptCtx context.Context, err error) (bucket, reason string) {
	if callerCtx != nil && callerCtx.Err() != nil {
		return classTerminal, reasonCallerDone
	}
	if attemptCtx != nil && attemptCtx.Err() != nil {
		return classTerminal, reasonBudgetExhausted
	}
	var se *StatusError
	if errors.As(err, &se) {
		if se.Retryable() {
			return classRetryable, se.reason()
		}
		return classTerminal, se.reason()
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return classRetryable, reasonTransport
	}
	return classRetryable, "unclassified_default_retryable"
}

// errFields renders the error-shape facts an operator needs when a
// classification looks wrong: the concrete Go type the classifier actually
// received, the HTTP status if there was one, and whether the error unwraps to
// a deadline. Logging a re-stringified summary instead would hide exactly the
// case that matters.
func errFields(err error) string {
	status := 0
	var se *StatusError
	if errors.As(err, &se) {
		status = se.StatusCode
	}
	return fmt.Sprintf("status=%d errtype=%s deadline_exceeded=%t canceled=%t",
		status, specificErrType(err),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled))
}

// specificErrType names the most specific typed error in the chain.
//
// Plain `%T` is worse than useless here: storeOnce wraps the transport failure
// with fmt.Errorf, so `%T` reports "*fmt.wrapError" for every single transport
// error — a 504-as-client-timeout, a DNS failure and a reset connection would
// all log identically, defeating the entire point of logging the shape. Skip
// the anonymous fmt wrappers and report the first error that actually carries a
// type, e.g. *url.Error or *archivista.StatusError.
func specificErrType(err error) string {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if t := fmt.Sprintf("%T", e); t != "*fmt.wrapError" && t != "*fmt.wrapErrors" {
			return t
		}
	}
	return fmt.Sprintf("%T", err)
}

// uploadHost is the endpoint host for logs. Only the host is logged: a full URL
// can carry credentials in userinfo or query parameters.
func (c *Client) uploadHost() string {
	if u, err := url.Parse(c.url); err == nil && u.Host != "" {
		return u.Host
	}
	return "unknown"
}

// uploadRetrier carries the per-call retry state and owns all upload logging.
//
// Nothing derived from the envelope body or the request headers is logged —
// only the endpoint host, the payload size, statuses, classifications and
// timings. The bytes are evidence and the headers carry the bearer.
// The logging rule above is now narrower than "nothing derived from the body",
// and the narrowing is deliberate AND bounded: only the FAILURE path renders an
// aggregated summary of the envelope's contents — attestor names, byte counts,
// leaf counts, and directory PREFIXES, each quoted if it carries anything
// unprintable. Nothing else crosses: no file contents, no digests, no per-file
// names, no headers, no bearer.
//
// The up-front warning below deliberately uses the SIZE-ONLY sizeAdvice. It
// fires on every oversized upload including ones that then SUCCEED, so putting
// the breakdown there would log repository structure on the happy path — a
// disclosure the success path never promised. Keeping the two forms apart is
// what makes the sentence above true rather than aspirational.
//
// That trade is what makes the error diagnosable. The alternative measured
// worse: the same message for two envelopes with opposite remedies, which cost
// a diagnosis cycle every time. Directory prefixes are the minimum that tells
// "delete these dependency trees" apart from "this is just the repository".
type uploadRetrier struct {
	policy RetryPolicy
	host   string
	size   int
	// body is the marshalled envelope, retained so a failure can REPORT what
	// is in it instead of guessing. Read only while rendering an error.
	body     []byte
	start    time.Time
	deadline time.Time
}

func (c *Client) newUploadRetrier(body []byte) *uploadRetrier {
	size := len(body)
	policy := DefaultRetryPolicy()
	if c.retry != nil {
		policy = *c.retry
	} else {
		// No WithRetry: preserve the historical single-attempt behaviour.
		policy.MaxAttempts = 1
		// And no retry budget either. This is load-bearing now that the budget
		// is enforced by a context deadline rather than merely consulted
		// between attempts: leaving the default 240s here would silently narrow
		// the caller's context on every single-attempt upload, which is exactly
		// the semantic change judge-api and the policy-publish path are
		// promised they will not get. There are no retries to bound, so there
		// is nothing for a budget to do.
		policy.Budget = 0
	}
	policy = policy.normalize()

	start := retryNow()
	return &uploadRetrier{
		policy:   policy,
		host:     c.uploadHost(),
		size:     size,
		body:     body,
		start:    start,
		deadline: start.Add(policy.Budget),
	}
}

// attempt runs one upload and logs its outcome.
func (r *uploadRetrier) attempt(ctx context.Context, n int, fn func(context.Context) (string, error)) (string, error) {
	attemptStart := retryNow()
	gitoid, err := fn(ctx)
	log.Debugf("archivista upload attempt: host=%s attempt=%d/%d bytes=%d elapsed=%s ok=%t",
		r.host, n, r.policy.MaxAttempts, r.size, retryNow().Sub(attemptStart), err == nil)

	if err == nil && n > 1 {
		// A silent success hides that we are riding on retries. This number is
		// the signal for whether the underlying saturation is improving.
		log.Infof("archivista upload succeeded after retry: host=%s attempts=%d elapsed=%s",
			r.host, n, retryNow().Sub(r.start))
	}
	return gitoid, err
}

// next decides what happens after a failed attempt: either a backoff duration
// to sleep before retrying, or a non-nil error meaning "stop, this is the
// result". Exactly one of the two is meaningful.
func (r *uploadRetrier) next(callerCtx, attemptCtx context.Context, n int, err error) (time.Duration, error) {
	bucket, reason := classify(callerCtx, attemptCtx, err)
	elapsed := retryNow().Sub(r.start)

	if bucket == classTerminal {
		log.Errorf("archivista upload failed: host=%s classification=%s reason=%s %s attempts=%d elapsed=%s bytes=%d",
			r.host, classTerminal, reason, errFields(err), n, elapsed, r.size)
		if reason == reasonBudgetExhausted {
			// The deadline we imposed is what killed the attempt, so the
			// returned error says so in its own words. Returning the bare
			// transport error would report a context deadline the CALLER never
			// set, and the attempt error stays reachable as secondary context.
			// Both %w verbs stay: callers match ErrRetryBudgetExhausted with
			// errors.Is, and the attempt error remains reachable as secondary
			// context. The advice is appended as trailing text precisely so it
			// cannot disturb the error chain.
			return 0, fmt.Errorf("%w after %d attempts in %s: %w%s",
				ErrRetryBudgetExhausted, n, elapsed.Round(time.Millisecond), err, sizeAdviceSuffix(r.size, r.body))
		}
		return 0, err
	}

	if n >= r.policy.MaxAttempts {
		log.Errorf("archivista upload failed: host=%s classification=%s reason=%s outcome=attempts_exhausted %s attempts=%d elapsed=%s bytes=%d",
			r.host, classRetryable, reason, errFields(err), n, elapsed, r.size)
		return 0, fmt.Errorf("%w (gave up after %d attempts in %s)", err, n, elapsed.Round(time.Millisecond))
	}

	delay := r.backoffFor(n, err)

	if r.policy.Budget > 0 && retryNow().Add(delay).After(r.deadline) {
		log.Errorf("archivista upload failed: host=%s classification=%s reason=%s outcome=budget_exhausted %s attempts=%d elapsed=%s next_backoff=%s budget=%s bytes=%d",
			r.host, classRetryable, reason, errFields(err), n, elapsed, delay, r.policy.Budget, r.size)
		return 0, fmt.Errorf("%w: gave up after %d attempts; next backoff %s would exceed the %s retry budget: %w%s",
			ErrRetryBudgetExhausted, n, delay.Round(time.Millisecond), r.policy.Budget, err, sizeAdviceSuffix(r.size, r.body))
	}

	log.Warnf("archivista upload retrying: host=%s classification=%s reason=%s %s attempt=%d/%d backoff=%s elapsed=%s",
		r.host, bucket, reason, errFields(err), n, r.policy.MaxAttempts, delay.Round(time.Millisecond), elapsed)
	return delay, nil
}

// backoffFor is the computed exponential backoff, unless the server sent a
// Retry-After — which overrides it verbatim. The server knows its own recovery
// window better than our exponential guess, and ignoring it is how a client
// turns rate limiting into a denial of service.
func (r *uploadRetrier) backoffFor(n int, err error) time.Duration {
	var se *StatusError
	if errors.As(err, &se) {
		if d, ok := se.retryAfterDelay(retryNow()); ok {
			return d
		}
	}
	return r.policy.backoff(n)
}

// abort renders the error for a run cut short while it was sleeping between
// attempts.
//
// Both errors go into the chain via %w, because a caller has two different
// questions to ask and each needs a different one. "Did the user abandon this?"
// is errors.Is(err, context.Canceled); "what was actually wrong with the
// server?" is errors.As(err, &StatusError{}). Formatting either with %v — which
// is what this used to do to the cancellation — silently deletes the answer to
// one of them, and the caller then gets told the server is broken when in fact
// somebody pressed Ctrl-C.
//
// The cancellation leads because it is the proximate reason we stopped; the
// upload failure follows as the context that explains why we were sleeping.
func (r *uploadRetrier) abort(callerCtx, attemptCtx context.Context, n int, uploadErr, sleepErr error) error {
	cause := sleepErr
	if callerCtx == nil || callerCtx.Err() == nil {
		// The caller is still willing; it was OUR deadline that ended the wait.
		// Reporting sleepErr verbatim here would hand the caller a
		// context.DeadlineExceeded it never set and cannot attribute.
		if c := context.Cause(attemptCtx); c != nil && errors.Is(c, ErrRetryBudgetExhausted) {
			cause = ErrRetryBudgetExhausted
		}
	}
	log.Errorf("archivista upload aborted during backoff: host=%s attempts=%d elapsed=%s reason=%v",
		r.host, n, retryNow().Sub(r.start), cause)
	return fmt.Errorf("archivista upload aborted during backoff after %d attempts: %w: %w", n, cause, uploadErr)
}

// storeWithRetry runs attemptFn against Archivista until it succeeds, hits a
// terminal classification, or exhausts MaxAttempts / Budget.
//
// The budget is enforced by a DERIVED CONTEXT, not merely consulted between
// attempts. Checking the deadline only before sleeping bounds nothing useful:
// an attempt that starts a millisecond under the deadline still gets a whole
// fresh http.Client.Timeout to itself, so total runtime could overshoot the
// budget by a full request timeout no matter what number the budget was set to.
// Narrowing the context the attempts run under is what turns the budget from a
// value the loop happens to look at into an actual bound on wall-clock time.
func (c *Client) storeWithRetry(ctx context.Context, body []byte, attemptFn func(context.Context) (string, error)) (string, error) {
	r := c.newUploadRetrier(body)

	// Say it BEFORE the upload, not only after it fails. An oversized envelope
	// takes minutes to fail, and the operator who hears "this is 18 MiB and
	// here is why that happens" up front can kill the run and fix the cause
	// instead of waiting out the retry budget to be told about a timeout.
	if advice := sizeAdvice(r.size); advice != "" {
		log.Warnf("archivista upload: %s", advice)
	}

	attemptCtx := ctx
	if r.policy.Budget > 0 {
		var cancel context.CancelFunc
		attemptCtx, cancel = retryBudgetContext(ctx, r.policy.Budget)
		defer cancel()
	}

	for n := 1; ; n++ {
		gitoid, err := r.attempt(attemptCtx, n, attemptFn)
		if err == nil {
			return gitoid, nil
		}

		delay, stop := r.next(ctx, attemptCtx, n, err)
		if stop != nil {
			return "", stop
		}

		if sleepErr := retrySleep(attemptCtx, delay); sleepErr != nil {
			return "", r.abort(ctx, attemptCtx, n, err, sleepErr)
		}
	}
}
