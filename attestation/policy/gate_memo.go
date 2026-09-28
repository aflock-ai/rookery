// Copyright 2026 The Witness Contributors
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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/aflock-ai/rookery/attestation/source"
)

// gateMemo remembers each step gate verdict for the duration of one
// verifySteps call, so the rounds of the attestationsFrom fixed point (#9813)
// ask each question once.
//
// A verdict is a function of the step, the collection, and the Rego/AI input
// context the step was gated under; the commit binding, AI server and provider
// are fixed for the whole verify. The key binds all three varying inputs, so a
// later round replays a verdict only when nothing it depended on changed, and
// re-evaluates as soon as the context does.
//
// Replaying instead of re-asking is what makes the fixed point well defined
// when a gate is not a pure function of its inputs: an AI provider that
// answers the same question differently on a second call would otherwise make
// the verdict depend on how many rounds ran, and could keep the loop from
// converging. It also removes the cost of re-evaluating Rego and AI for
// collections whose context did not change.
type gateMemo struct {
	mu       sync.Mutex
	verdicts map[string]gateVerdict
}

type gateVerdict struct {
	outcome  gateOutcome
	passed   PassedCollection
	rejected RejectedCollection
}

func newGateMemo() *gateMemo {
	return &gateMemo{verdicts: map[string]gateVerdict{}}
}

// stepGate is a gateMemo scoped to one step gated under one input context. The
// context is hashed once per step per round, not once per collection.
type stepGate struct {
	memo   *gateMemo
	prefix []byte
}

// forStep scopes the memo to step under stepCtx. It returns nil, meaning
// "evaluate every collection fresh", when the memo is off or the context
// cannot be encoded: an unkeyable context is never guessed at.
func (m *gateMemo) forStep(step string, stepCtx map[string]interface{}) *stepGate {
	if m == nil {
		return nil
	}
	// json.Marshal sorts map keys, and every value in a step context is
	// decoded JSON, so equal contexts encode to equal bytes.
	encoded, err := json.Marshal(stepCtx)
	if err != nil {
		return nil
	}
	ctxSum := sha256.Sum256(encoded)
	var prefix bytes.Buffer
	writeFramed(&prefix, []byte(step))
	writeFramed(&prefix, ctxSum[:])
	return &stepGate{memo: m, prefix: prefix.Bytes()}
}

// key identifies collection under this step and context. It binds the
// collection's reference, its statement and verified signers
// (passedCollectionKey), its signed envelope bytes, its verified TSA time, and
// any verification errors, so two collections share a key only if the gate
// could not tell them apart.
func (g *stepGate) key(collection source.CollectionVerificationResult) string {
	var buf bytes.Buffer
	buf.Write(g.prefix)
	writeFramed(&buf, []byte(collection.Reference))
	writeFramed(&buf, []byte(passedCollectionKey(PassedCollection{Collection: collection})))
	writeFramed(&buf, []byte(passedCollectionFallbackKey(collection)))
	// The collection's verified TSA time reaches Rego as input.collection.tsaTime
	// (#10528), so two collections that differ only in it must not share a verdict.
	ts, _ := regoTSATime(collection)
	writeFramed(&buf, []byte(ts))
	for _, err := range collection.Errors {
		writeFramed(&buf, []byte(err.Error()))
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func (g *stepGate) lookup(key string) (gateVerdict, bool) {
	g.memo.mu.Lock()
	defer g.memo.mu.Unlock()
	v, ok := g.memo.verdicts[key]
	return v, ok
}

func (g *stepGate) store(key string, v gateVerdict) {
	g.memo.mu.Lock()
	defer g.memo.mu.Unlock()
	g.memo.verdicts[key] = v
}
