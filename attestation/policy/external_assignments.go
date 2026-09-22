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

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"sync"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/source"
)

// One verdict per input.
//
// A step reads an external as input.external.<name>, which is the external's
// FIRST passed candidate (externalAttestorAsJSON). The candidates arrive in
// whatever order the source returns them: EntSource has no ORDER BY on the
// predicate search, MemorySource ranges a map, MultiSource merges goroutines.
// Taking that first candidate as the only one would make the verdict follow
// the row order whenever a step's Rego accepts one candidate and denies another.
//
// The rule: the policy passes iff SOME assignment of one passed candidate
// to each external makes the whole policy pass, with every step that reads an
// external seeing the same candidate. Equivalently: PASS iff taking the
// candidates in some row order, first-candidate-only, would pass.
//
// Only DECISIVE externals are enumerated: named by some step's externalFrom
// and with at least two distinct candidates, where distinct means a different
// attestor JSON (what a step's Rego reads). With none, the verify runs once,
// exactly as before.
//
// Cost and the bound. With one decisive external every candidate is tried in
// canonical order and the walk stops at the first pass: linear and uncapped (a
// cap there would make "more evidence" able to hide a pass), and refused only
// when the source cannot be forked (below).
// With two or more the product is capped at maxExternalAssignments; when the
// product is larger and none of the tried assignments passes, the verify is
// refused (ErrExternalAssignmentsExceedBound), because an untried assignment
// could have passed.
//
// A partial walk answers only PASS. Every assignment after the first runs over
// a fork of the source; when no faithful fork can be had (forkVerified), the
// walk stops there, and the rule is the bound's: a PASS already found stands,
// because a satisfying assignment exists, and a FAIL with assignments left
// untried is refused. A FAILED is an answer only when every assignment was
// evaluated.

// maxExternalAssignments caps the assignments tried when two or more decisive
// externals are combined.
const maxExternalAssignments = 64

// externalCandidateKeys is the canonical order of one external candidate:
// the Rego view (sha256 of the attestor JSON a step reads), then the signed
// payload's sha256, then the reference. It is computed from content, so every
// source orders the same candidates the same way whatever references it
// assigns, and it is defined for an envelope with no payload or no attestor.
type externalCandidateKeys struct {
	view    string
	payload string
	ref     string
}

func externalKeys(env source.StatementEnvelope) externalCandidateKeys {
	return externalCandidateKeys{
		view:    externalViewKey(env),
		payload: externalPayloadKey(env),
		ref:     env.Reference,
	}
}

func (a externalCandidateKeys) less(b externalCandidateKeys) bool {
	if a.view != b.view {
		return a.view < b.view
	}
	if a.payload != b.payload {
		return a.payload < b.payload
	}
	return a.ref < b.ref
}

// externalViewKey hashes exactly what a step's Rego reads for this candidate.
// A candidate with no attestor (never a passed one) has the empty key.
func externalViewKey(env source.StatementEnvelope) string {
	if env.Attestor == nil {
		return ""
	}
	b, err := json.Marshal(env.Attestor)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func externalPayloadKey(env source.StatementEnvelope) string {
	payload := env.Envelope.Payload
	if len(payload) == 0 {
		b, err := json.Marshal(env.Statement)
		if err != nil {
			return ""
		}
		payload = b
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// sortExternalResult puts every candidate list of er in canonical order.
func sortExternalResult(er *ExternalResult) {
	sortByKeys(er.Passed, func(p PassedExternal) source.StatementEnvelope { return p.Envelope })
	sortByKeys(er.Rejected, func(r RejectedExternal) source.StatementEnvelope { return r.Envelope })
	sortByKeys(er.Unbound, func(r RejectedExternal) source.StatementEnvelope { return r.Envelope })
}

func sortByKeys[T any](items []T, envOf func(T) source.StatementEnvelope) {
	if len(items) < 2 {
		return
	}
	keys := make([]externalCandidateKeys, len(items))
	for i, it := range items {
		keys[i] = externalKeys(envOf(it))
	}
	idx := make([]int, len(items))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]].less(keys[idx[b]]) })
	sorted := make([]T, len(items))
	for i, j := range idx {
		sorted[i] = items[j]
	}
	copy(items, sorted)
}

// decisiveExternal is one external whose choice can change a step's input:
// its distinct passed candidates, in canonical order.
type decisiveExternal struct {
	name       string
	candidates []PassedExternal
}

// decisiveExternals lists, in sorted name order, the externals some step reads
// that have at least two distinct passed candidates. er.Passed must already be
// in canonical order; the first candidate of each distinct view is kept.
func (p Policy) decisiveExternals(externalResults map[string]ExternalResult) []decisiveExternal {
	referenced := map[string]bool{}
	for _, step := range p.Steps {
		for _, name := range step.ExternalFrom {
			referenced[name] = true
		}
	}
	names := make([]string, 0, len(referenced))
	for name := range referenced {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []decisiveExternal
	for _, name := range names {
		er, ok := externalResults[name]
		if !ok || len(er.Passed) < 2 {
			continue
		}
		seen := map[string]bool{}
		var distinct []PassedExternal
		for _, pe := range er.Passed {
			view := externalViewKey(pe.Envelope)
			if seen[view] {
				continue
			}
			seen[view] = true
			distinct = append(distinct, pe)
		}
		if len(distinct) >= 2 {
			out = append(out, decisiveExternal{name: name, candidates: distinct})
		}
	}
	return out
}

// verifyStepsOverExternals runs verifySteps once per assignment of the
// decisive externals, in canonical order, and returns the first assignment's
// results whose steps all pass. When none passes it returns the FIRST
// assignment's results, so the reasons are the same on every run, together
// with a refusal when an AI question went unanswered under any tried
// assignment, or when assignments were left untried (the k >= 2 bound, or a
// source that could not be forked for the next one).
func (p Policy) verifyStepsOverExternals(ctx context.Context, vo *verifyOptions, trustBundles map[string]TrustBundle, externalResults map[string]ExternalResult) (map[string]StepResult, error) {
	decisive := p.decisiveExternals(externalResults)
	if len(decisive) == 0 {
		return p.verifySteps(ctx, vo, trustBundles, externalResults)
	}

	total := 1
	for _, d := range decisive {
		total = saturatingMul(total, len(d.candidates))
	}
	limit := total
	if len(decisive) >= 2 && limit > maxExternalAssignments {
		limit = maxExternalAssignments
	}

	// One AI answer per attestor for the whole walk: the provider takes no step
	// context, so its answer cannot depend on the assignment, and asking again
	// would only multiply cost and disclosure. A FAIL or a refusal therefore
	// holds under every assignment.
	provider := newMemoAiProvider(vo.aiProvider)
	seeds := append([]string(nil), vo.subjectDigests...)

	var (
		first      map[string]StepResult
		refusal    error
		tried      int
		unforkable bool
	)
	for ; tried < limit; tried++ {
		runVo, ok := assignmentOptions(vo, provider, seeds, tried)
		if !ok {
			log.Debugf("external attestations %v: the evidence source cannot be forked for assignment %d of %d", decisiveNames(decisive), tried+1, total)
			unforkable = true
			break
		}
		results, err := p.verifySteps(ctx, runVo, trustBundles, projectAssignment(externalResults, decisive, tried))
		if err != nil {
			return results, err
		}
		if stepsAllPass(results) {
			return results, nil
		}
		if first == nil {
			first = results
		}
		if refusal == nil {
			refusal = refusedAIResults(results, nil)
		}
	}
	if refusal != nil {
		return first, refusal
	}
	if tried < total {
		return first, ErrExternalAssignmentsExceedBound{Externals: decisiveNames(decisive), Assignments: total, Bound: tried, SourceNotForkable: unforkable}
	}
	return first, nil
}

// assignmentOptions are the verify options for run i: the memoized AI
// provider, the caller's seeds, and for every run after the first a source in
// the state a fresh verify starts from. false: no faithful fork for run i.
func assignmentOptions(vo *verifyOptions, provider AiProvider, seeds []string, i int) (*verifyOptions, bool) {
	runVo := *vo
	runVo.aiProvider = provider
	runVo.subjectDigests = append([]string(nil), seeds...)
	if i > 0 {
		fresh, ok := forkVerified(vo.verifiedSource)
		if !ok {
			return nil, false
		}
		runVo.verifiedSource = fresh
	}
	return &runVo, true
}

// forkVerified returns a copy of src in the state a fresh verify starts from,
// or false when src cannot provide one faithfully.
//
// A fork must have src's own concrete type. A wrapper that embeds a forking
// source (a *source.VerifiedSource, say) and narrows its searches (a tenant
// scope, a commit binding) inherits ForkVerified, and the promoted method
// returns the INNER source: the assignment run over it would read evidence
// the wrapper filtered out. The check runs on every fork, not once, because
// nothing obliges a source to fork the same way twice. The sources below
// VerifiedSource are held to the same rule by source.Fork's own check.
func forkVerified(src source.VerifiedSourcer) (source.VerifiedSourcer, bool) {
	forker, ok := src.(forkingVerifiedSourcer)
	if !ok {
		return nil, false
	}
	fresh, ok := forker.ForkVerified()
	if !ok || fresh == nil || reflect.TypeOf(fresh) != reflect.TypeOf(src) {
		return nil, false
	}
	return fresh, true
}

// forkingVerifiedSourcer is a verified source that can hand out a copy in the
// state a fresh verify starts from (source.VerifiedSource.ForkVerified).
type forkingVerifiedSourcer interface {
	ForkVerified() (source.VerifiedSourcer, bool)
}

func decisiveNames(decisive []decisiveExternal) []string {
	names := make([]string, 0, len(decisive))
	for _, d := range decisive {
		names = append(names, d.name)
	}
	return names
}

// projectAssignment returns a copy of externalResults in which each decisive
// external's Passed list starts with the candidate assignment i picks. The
// walk is lexicographic: externals in sorted name order, the FIRST name
// varying slowest, each external's candidates in canonical order.
func projectAssignment(externalResults map[string]ExternalResult, decisive []decisiveExternal, i int) map[string]ExternalResult {
	projected := make(map[string]ExternalResult, len(externalResults))
	for name, er := range externalResults {
		projected[name] = er
	}
	for j := len(decisive) - 1; j >= 0; j-- {
		d := decisive[j]
		pick := i % len(d.candidates)
		i /= len(d.candidates)
		er := projected[d.name]
		er.Passed = []PassedExternal{d.candidates[pick]}
		projected[d.name] = er
	}
	return projected
}

// stepsAllPass is VerifyWithExternals' step half of the verdict.
func stepsAllPass(results map[string]StepResult) bool {
	for _, r := range results {
		if !r.Analyze() {
			return false
		}
	}
	return true
}

func saturatingMul(a, b int) int {
	const ceiling = 1 << 30
	if a == 0 || b == 0 {
		return 0
	}
	if a > ceiling/b {
		return ceiling
	}
	return a * b
}

// memoAiProvider answers each (attestor, policy, server) question once per
// verify. Errors are remembered too: a refusal must not turn into an answer
// by being asked again under another assignment.
type memoAiProvider struct {
	inner AiProvider
	mu    sync.Mutex
	one   map[string]memoAiAnswer
	batch map[string]memoAiBatchAnswer
}

type memoAiAnswer struct {
	resp AiResponse
	err  error
}

type memoAiBatchAnswer struct {
	resps []AiResponse
	err   error
}

// memoAiBatchProvider keeps the batch dispatch of an inner batch provider.
type memoAiBatchProvider struct {
	*memoAiProvider
	batchInner AiBatchProvider
}

func newMemoAiProvider(inner AiProvider) AiProvider {
	if inner == nil {
		inner = defaultAiProvider
	}
	m := &memoAiProvider{inner: inner, one: map[string]memoAiAnswer{}, batch: map[string]memoAiBatchAnswer{}}
	if batch, ok := inner.(AiBatchProvider); ok {
		return memoAiBatchProvider{memoAiProvider: m, batchInner: batch}
	}
	return m
}

func aiMemoKey(attestor attestation.Attestor, question any, serverURL string) (string, bool) {
	a, err := json.Marshal(attestor)
	if err != nil {
		return "", false
	}
	q, err := json.Marshal(question)
	if err != nil {
		return "", false
	}
	h := sha256.New()
	for _, part := range [][]byte{a, q, []byte(serverURL)} {
		sum := sha256.Sum256(part)
		h.Write(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

func (m *memoAiProvider) Evaluate(ctx context.Context, attestor attestation.Attestor, pol AiPolicy, serverURL string) (AiResponse, error) {
	key, ok := aiMemoKey(attestor, pol, serverURL)
	if !ok {
		return m.inner.Evaluate(ctx, attestor, pol, serverURL)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, hit := m.one[key]; hit {
		return a.resp, a.err
	}
	resp, err := m.inner.Evaluate(ctx, attestor, pol, serverURL)
	if ctx.Err() == nil {
		m.one[key] = memoAiAnswer{resp: resp, err: err}
	}
	return resp, err
}

func (m memoAiBatchProvider) EvaluateBatch(ctx context.Context, attestor attestation.Attestor, policies []AiPolicy, serverURL string) ([]AiResponse, error) {
	batch := m.batchInner
	key, ok := aiMemoKey(attestor, policies, serverURL)
	if !ok {
		return batch.EvaluateBatch(ctx, attestor, policies, serverURL)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, hit := m.batch[key]; hit {
		return append([]AiResponse(nil), a.resps...), a.err
	}
	resps, err := batch.EvaluateBatch(ctx, attestor, policies, serverURL)
	if ctx.Err() == nil {
		m.batch[key] = memoAiBatchAnswer{resps: append([]AiResponse(nil), resps...), err: err}
	}
	return resps, err
}

// sortedNames returns a map's keys in sorted order.
func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
