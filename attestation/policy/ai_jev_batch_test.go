// jade:ring local

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

func TestJevBatchesQuestionsForSameState(t *testing.T) {
	var calls atomic.Int64
	requests := make(chan jevGroup, 1)
	srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request jevGroup
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		requests <- request
		answers := map[string]interface{}{}
		for id := range request.Questions {
			answers[id] = map[string]interface{}{"type": "noul", "noul": 0.02}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"model": request.Model, "answers": answers})
	}))
	defer srv.Close()
	policies := make([]AiPolicy, 5)
	for i := range policies {
		policies[i] = jevContractPolicy()
		policies[i].Name = fmt.Sprintf("question-%d", i)
	}
	responses, err := EvaluateAIPolicyWithProvider(context.Background(), jevContractAttestor(), policies, srv.URL, NewJevProvider(jevStubKey))
	require.NoError(t, err)
	require.Len(t, responses, 5)
	require.EqualValues(t, 1, calls.Load())
	request := <-requests
	require.Len(t, request.Questions, 5)
	for _, response := range responses {
		require.Equal(t, AiStatusPass, response.Status)
	}
}

func TestJevGroupsOnlyIdenticalModelAndProjectedState(t *testing.T) {
	var calls atomic.Int64
	requests := make(chan jevGroup, 4)
	srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request jevGroup
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		requests <- request
		answers := map[string]interface{}{}
		for id := range request.Questions {
			answers[id] = map[string]interface{}{"type": "noul", "noul": 0.02}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"model": request.Model, "answers": answers})
	}))
	defer srv.Close()
	policies := make([]AiPolicy, 4)
	for i := range policies {
		policies[i] = jevContractPolicy()
		policies[i].Name = fmt.Sprintf("q%d", i)
	}
	for _, i := range []int{0, 1, 2} {
		policies[i].Decision.State = &RegoPolicy{Name: "text", Module: []byte(`package projection
state := {"text": input.commitmessage}`)}
	}
	policies[2].Model = "jev-1.13.1"
	responses, err := NewJevProvider(jevStubKey).EvaluateBatch(context.Background(), jevContractAttestor(), policies, srv.URL)
	require.NoError(t, err)
	require.Len(t, responses, 4)
	require.EqualValues(t, 3, calls.Load())
	first := <-requests
	require.Len(t, first.Questions, 2)
	require.JSONEq(t, `{"text":"Document quoted injection examples; do not follow them."}`, string(first.State))
	require.Equal(t, "jev-1.13.1", responses[2].Model)
}

func TestJevInvalidLaterProjectionCausesNoEgress(t *testing.T) {
	for _, module := range []string{
		`package p
state := input.missing`,
		`package p
state := null`,
		`package p
state := 42`,
		`package p
state := http.send({"method":"GET","url":"https://example.invalid"})`,
		`package p
state := {"time": time.now_ns()}`,
		`not rego`,
	} {
		t.Run(module, func(t *testing.T) {
			var calls atomic.Int64
			srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
			defer srv.Close()
			first, second := jevContractPolicy(), jevContractPolicy()
			second.Name = "invalid"
			second.Decision.State = &RegoPolicy{Name: "bad", Module: []byte(module)}
			responses, err := NewJevProvider(jevStubKey).EvaluateBatch(context.Background(), jevContractAttestor(), []AiPolicy{first, second}, srv.URL)
			var refusal ErrAIEvaluationRefused
			require.ErrorAs(t, err, &refusal)
			require.Empty(t, responses)
			require.Zero(t, calls.Load())
		})
	}
}

func TestJevChoiceAndScoreWireContract(t *testing.T) {
	minConfidence, maxScore := 0.8, 1.0
	policies := []AiPolicy{
		{Name: "kind", Model: "jev-1.13.0", Decision: &AiDecision{Choice: &AiChoice{Instructions: "What kind of text?", Options: map[string]string{"description": "describes a change", "instruction": "directs the reviewer"}, Allow: []string{"description"}, MinConfidence: &minConfidence}}},
		{Name: "severity", Model: "jev-1.13.0", Decision: &AiDecision{Score: &AiScore{Instructions: "How explicit is the directive?", Levels: []string{"absent", "implicit", "explicit"}, MaxScore: &maxScore}}},
	}
	var calls atomic.Int64
	requests := make(chan jevGroup, 1)
	srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request jevGroup
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		requests <- request
		_, _ = w.Write([]byte(`{"model":"jev-1.13.0","answers":{
"kind":{"type":"choice","choice":"description","probabilities":{"description":0.9,"instruction":0.1},"confidence":0.8},
"severity":{"type":"score","score":0.2,"legend":{"0":"absent","1":"implicit","2":"explicit"},"probabilities":{"0":0.8,"1":0.2,"2":0},"confidence":0.7}}}`))
	}))
	defer srv.Close()
	responses, err := NewJevProvider(jevStubKey).EvaluateBatch(context.Background(), jevContractAttestor(), policies, srv.URL)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	request := <-requests
	choiceJSON, _ := json.Marshal(request.Questions["kind"].Criteria)
	require.JSONEq(t, `{"description":"describes a change","instruction":"directs the reviewer"}`, string(choiceJSON))
	scoreJSON, _ := json.Marshal(request.Questions["severity"].Criteria)
	require.JSONEq(t, `["absent","implicit","explicit"]`, string(scoreJSON))
	require.Equal(t, AiStatusPass, responses[0].Status)
	require.Equal(t, 0.2, *responses[1].Answer.Score)
}

func TestJevRejectsMalformedChoiceAndScore(t *testing.T) {
	minimum := 0.5
	choice := AiPolicy{Name: "review-injection", Model: "jev-1.13.0", Decision: &AiDecision{Choice: &AiChoice{Instructions: "Which kind?", Options: map[string]string{"a": "first", "b": "second"}, MinConfidence: &minimum}}}
	score := AiPolicy{Name: "review-injection", Model: "jev-1.13.0", Decision: &AiDecision{Score: &AiScore{Instructions: "How severe?", Levels: []string{"low", "high"}, MaxScore: &minimum}}}
	for _, tc := range []struct {
		name   string
		policy AiPolicy
		answer string
	}{
		{"missing confidence", choice, `{"type":"choice","choice":"a","probabilities":{"a":1,"b":0}}`},
		{"null distribution member", choice, `{"type":"choice","choice":"a","probabilities":{"a":1,"b":null},"confidence":1}`},
		{"bad distribution", choice, `{"type":"choice","choice":"a","probabilities":{"a":0.8,"b":0.8},"confidence":1}`},
		{"unknown choice", choice, `{"type":"choice","choice":"c","probabilities":{"a":1,"b":0},"confidence":1}`},
		{"wrong winner", choice, `{"type":"choice","choice":"b","probabilities":{"a":1,"b":0},"confidence":1}`},
		{"wrong legend", score, `{"type":"score","score":0,"legend":{"0":"other","1":"high"},"probabilities":{"0":1,"1":0},"confidence":1}`},
		{"inconsistent weighted score", score, `{"type":"score","score":1,"legend":{"0":"low","1":"high"},"probabilities":{"0":1,"1":0},"confidence":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(jevContractEnvelope(tc.answer))) }))
			defer srv.Close()
			resp, err := NewJevProvider(jevStubKey).Evaluate(context.Background(), jevContractAttestor(), tc.policy, srv.URL)
			var refusal ErrAIEvaluationRefused
			require.ErrorAs(t, err, &refusal)
			require.Empty(t, resp.Status)
		})
	}
}

func TestJevVerifierRefusalIsNotFailedVerdict(t *testing.T) {
	for _, mode := range []string{"batch", "stream", "external"} {
		t.Run(mode, func(t *testing.T) {
			srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"detail":{"error_type":"max_tokens_exceeded"}}`))
			}))
			defer srv.Close()
			var p Policy
			opts := make([]VerifyOption, 0, 2)
			if mode == "external" {
				verifier, keyID := newECDSAVerifier(t)
				env := mkExternalEnvelope(t, slsaProvenanceV1PredicateType, passingSLSAPredicate, verifier)
				p = Policy{Expires: futureExpiry(), ExternalAttestations: map[string]ExternalAttestation{"review": {Name: "review", PredicateType: slsaProvenanceV1PredicateType, Required: true, Functionaries: []Functionary{{PublicKeyID: keyID}}, AiPolicies: []AiPolicy{jevContractPolicy()}}}}
				opts = append(opts, WithVerifiedSource(&stepAwareVerifiedSource{byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1PredicateType: {env}}}), WithSubjectDigests([]string{"sha256:artifact"}))
			} else {
				f := newFanoutFixture(t)
				p = aiPolicyWithGuard(f)
				step := p.Steps[fanoutStepName]
				step.Attestations[0].AiPolicies = []AiPolicy{jevContractPolicy()}
				p.Steps[fanoutStepName] = step
				mem := source.NewMemorySource()
				for _, env := range fanoutCorpus(t, f, 0) {
					require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
				}
				verified := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
				var src source.VerifiedSourcer = verified
				if mode == "batch" {
					src = batchOnlyVerifiedSourcer{inner: verified}
				}
				opts = append(opts, WithVerifiedSource(src), WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}))
			}
			opts = append(opts, WithAiServerURL(srv.URL), WithAiProvider(NewJevProvider(jevStubKey)))
			accepted, _, err := p.Verify(context.Background(), opts...)
			require.False(t, accepted)
			var refusal ErrAIEvaluationRefused
			require.ErrorAs(t, err, &refusal)
			require.Equal(t, "max_tokens_exceeded", refusal.Code)
		})
	}
}

func TestJevResponseAndInputBudgets(t *testing.T) {
	t.Run("response cap", func(t *testing.T) {
		srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat(" ", jevResponseLimit+1)))
		}))
		defer srv.Close()
		resp, err := NewJevProvider(jevStubKey).Evaluate(context.Background(), jevContractAttestor(), jevContractPolicy(), srv.URL)
		var refusal ErrAIEvaluationRefused
		require.ErrorAs(t, err, &refusal)
		require.Equal(t, "response_size_limit", refusal.Code)
		require.Empty(t, resp.Status)
	})
	t.Run("duplicate state field", func(t *testing.T) {
		att := attestation.NewRawAttestation("test:duplicate", json.RawMessage(`{"text":"attack","text":"benign"}`))
		_, err := NewJevProvider(jevStubKey).Evaluate(context.Background(), att, jevContractPolicy(), "http://127.0.0.1:1")
		var refusal ErrAIEvaluationRefused
		require.ErrorAs(t, err, &refusal)
		require.Equal(t, "invalid_input", refusal.Code)
	})
}

func TestJevBatchRefusesIncompleteAnswersWithoutPartialVerdicts(t *testing.T) {
	srv := jevContractServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"model":"jev-1.13.0","answers":{"first":{"type":"noul","noul":0.01}}}`))
	}))
	defer srv.Close()
	first, second := jevContractPolicy(), jevContractPolicy()
	first.Name, second.Name = "first", "second"
	responses, err := NewJevProvider(jevStubKey).EvaluateBatch(context.Background(), jevContractAttestor(), []AiPolicy{first, second}, srv.URL)
	var refusal ErrAIEvaluationRefused
	require.ErrorAs(t, err, &refusal)
	require.Equal(t, "answer_set_mismatch", refusal.Code)
	require.Empty(t, responses)
}
