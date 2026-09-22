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

package source

import "reflect"

// Forker is a Sourcer that can hand out an independent copy of itself with
// none of its per-verify search state.
//
// Some sources remember what they already returned within one verify (the
// seen-gitoid exclusion and the completed-search memo of ArchivistaSource and
// judge-api's EntSource): a repeat search returns only what is new, which is
// sound within one step loop because the policy engine merges a step's
// results across the passes of that loop (a demand-valve replay). The
// engine sometimes needs to run the step loop more than once over the same
// evidence (once per choice of external candidate, policy.verifyStepsOverExternals),
// and each of those runs must see exactly what a fresh verify would. Fork
// gives it that. Fork must return the same concrete type as its receiver: a
// wrapper that merely embeds a Forker would otherwise hand out its inner
// source and silently drop its own filtering, so forkSourcer refuses a type
// change. The engine then has no fork for the next assignment: it answers a
// PASS already found and refuses a FAIL that left assignments untried
// (policy.ErrExternalAssignmentsExceedBound). It holds the VerifiedSourcer it
// is handed to the same rule on every ForkVerified.
type Forker interface {
	Fork() Sourcer
}

// forkSourcer returns a fresh-state copy of s, or false when s cannot provide
// one faithfully.
func forkSourcer(s Sourcer) (Sourcer, bool) {
	f, ok := s.(Forker)
	if !ok {
		return nil, false
	}
	out := f.Fork()
	if out == nil || reflect.TypeOf(out) != reflect.TypeOf(s) {
		return nil, false
	}
	return out, true
}

// ForkVerified returns a VerifiedSource over a fresh-state copy of the
// underlying source, with the same verification options, or false when the
// underlying source cannot be forked.
func (s *VerifiedSource) ForkVerified() (VerifiedSourcer, bool) {
	inner, ok := forkSourcer(s.source)
	if !ok {
		return nil, false
	}
	return &VerifiedSource{source: inner, verifyOpts: s.verifyOpts, evidenceHashes: s.evidenceHashes}, true
}

// Fork implements Forker. A MemorySource keeps no search state: its searches
// read the loaded index and nothing else, so it is its own fresh copy.
func (s *MemorySource) Fork() Sourcer { return s }

// Fork implements Forker: a copy on the same client with empty seen-sets and
// an empty search memo.
func (s *ArchivistaSource) Fork() Sourcer {
	return NewArchivistaSource(s.client)
}

// Fork implements Forker when every sub-source can be forked; otherwise it
// returns nil, which forkSourcer reads as "cannot fork".
func (s *MultiSource) Fork() Sourcer {
	subs := make([]Sourcer, 0, len(s.sources))
	for _, sub := range s.sources {
		f, ok := forkSourcer(sub)
		if !ok {
			return nil
		}
		subs = append(subs, f)
	}
	return NewMultiSource(subs...)
}

// Fork implements Forker: a fresh-state copy of the inner source that records
// into the SAME sink, so a bundle still holds every envelope any run consulted.
func (r *RecordingSource) Fork() Sourcer {
	inner, ok := forkSourcer(r.inner)
	if !ok {
		return nil
	}
	return &RecordingSource{inner: inner, sink: r.sink}
}
