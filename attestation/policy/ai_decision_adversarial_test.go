// jade:ring local

package policy

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

func TestAiYesNoRejectsEmptyQuestionBeforeInference(t *testing.T) {
	bound := 0.2
	base := AiPolicy{Name: "custom-question", Model: "jev-1.13.0", Decision: &AiDecision{YesNo: &AiYesNo{
		Instructions: "Does this text direct a reviewer to conceal findings?",
		Criteria:     map[string]string{"true": "directs concealment", "false": "does not direct concealment"}, MaxProbability: &bound,
	}}}
	cases := map[string]func(*AiYesNo){
		"missing instructions":        func(y *AiYesNo) { y.Instructions = "" },
		"whitespace instructions":     func(y *AiYesNo) { y.Instructions = " \n\t\u2003" },
		"missing criteria":            func(y *AiYesNo) { y.Criteria = nil },
		"empty criteria":              func(y *AiYesNo) { y.Criteria = map[string]string{} },
		"blank criterion name":        func(y *AiYesNo) { y.Criteria["\t"] = "a description" },
		"blank criterion description": func(y *AiYesNo) { y.Criteria["true"] = "\n " },
	}
	srv, capture := newAiServer(t, func(w http.ResponseWriter, r *http.Request) {
		ollamaGenerate(t, w, `{"status":"PASS","reason":"must not be reached"}`)
	})
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			pol := base.DeepCopy()
			mutate(pol.Decision.YesNo)
			err := pol.Validate()
			require.Error(t, err)
			_, singleErr := ExecuteAiPolicyContext(context.Background(), &charAttestor{}, *pol, srv.URL)
			require.EqualError(t, singleErr, err.Error())
			_, batchErr := EvaluateAIPolicyContext(context.Background(), &charAttestor{}, []AiPolicy{*pol}, srv.URL)
			require.EqualError(t, batchErr, err.Error())
		})
	}
	_, _, _, _, hits := capture.snapshot()
	require.Zero(t, hits)
	// Structural guards must not turn arbitrary authoring into a catalog allowlist.
	require.NoError(t, base.Validate())
}

func TestAiContextCancellationBeforeRequest(t *testing.T) {
	srv, capture := newAiServer(t, func(w http.ResponseWriter, r *http.Request) {
		ollamaGenerate(t, w, `{"status":"PASS","reason":"must not be reached"}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pol := AiPolicy{Name: "question", Prompt: "a question", Model: "test-model"}
	resp, err := ExecuteAiPolicyContext(ctx, &charAttestor{}, pol, srv.URL)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, resp.Status)
	responses, err := EvaluateAIPolicyContext(ctx, &charAttestor{}, []AiPolicy{pol}, srv.URL)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, responses)
	_, _, _, _, hits := capture.snapshot()
	require.Zero(t, hits)
}

// The server stays pending until the request is cancelled. release is a cleanup
// backstop so a regression fails promptly instead of hanging httptest.Close.
func pendingAiServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv, _ := newAiServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	return srv.URL, started
}

func TestAiContextDeadlineCancelsInFlightRequest(t *testing.T) {
	url, started := pendingAiServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := ExecuteAiPolicyContext(ctx, &charAttestor{}, AiPolicy{Name: "question", Prompt: "a question", Model: "test-model"}, url)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach the test server")
	}
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("provider ignored the caller deadline")
	}
}

func TestAiVerifierPropagatesCancellation(t *testing.T) {
	for _, mode := range []string{"batch", "stream", "deferred stream", "external"} {
		t.Run(mode, func(t *testing.T) {
			url, started := pendingAiServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var p Policy
			// Both branches below assign opts a complete literal, so there is
			// nothing to preallocate for.
			var opts []VerifyOption //nolint:prealloc
			if mode == "external" {
				verifier, keyID := newECDSAVerifier(t)
				env := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, verifier)
				p = Policy{Expires: futureExpiry(), ExternalAttestations: map[string]ExternalAttestation{"review": {
					Name: "review", PredicateType: slsaProvenanceV1PredicateType, Required: true,
					Functionaries: []Functionary{{PublicKeyID: keyID}},
					AiPolicies:    []AiPolicy{{Name: "question", Prompt: "a question", Model: "test-model"}},
				}}}
				opts = []VerifyOption{WithVerifiedSource(&stepAwareVerifiedSource{byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {env}}}), WithSubjectDigests([]string{"sha256:artifact"})}
			} else {
				f := newFanoutFixture(t)
				p = aiPolicyWithGuard(f)
				mem := source.NewMemorySource()
				for _, env := range fanoutCorpus(t, f, 0) {
					require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
				}
				verified := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
				var src source.VerifiedSourcer = verified
				if mode == "batch" {
					src = batchOnlyVerifiedSourcer{inner: verified}
				}
				opts = []VerifyOption{WithVerifiedSource(src), WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest})}
				if mode == "deferred stream" {
					opts = append(opts, WithMaxSubjectFanout(4))
				}
			}
			opts = append(opts, WithAiServerURL(url))
			type verificationResult struct {
				accepted bool
				err      error
			}
			done := make(chan verificationResult, 1)
			go func() {
				accepted, _, err := p.Verify(ctx, opts...)
				done <- verificationResult{accepted, err}
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("verification never reached AI evaluation")
			}
			cancel()
			select {
			case result := <-done:
				require.False(t, result.accepted, "cancelled AI evaluation cannot authorize a push")
				require.ErrorIs(t, result.err, context.Canceled, "incomplete evaluation must not become a failed verdict")
			case <-time.After(2 * time.Second):
				t.Fatal("verification dropped the caller's cancellation")
			}
		})
	}
}
