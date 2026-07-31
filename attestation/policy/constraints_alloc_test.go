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
	"crypto/x509/pkix"
	"testing"
)

// checkExtensions runs once per functionary per candidate collection per
// search depth — the prod #7572 leader logged ~1,500 lines/sec from this file
// while OOM-crashlooping. The no-constraint fast path (every Extensions field
// empty) must not allocate per call for reflection metadata or for boxing
// log arguments: reflect.VisibleFields of the FIXED certificate.Extensions
// type was recomputed per call, and a Debugf fired per empty field per call.
//
// Bound rationale (measured): old code ~50 allocs/op on this fixture; after
// hoisting the field list and dropping the per-field debug line it is ~2.
// The bound of 10 cleanly separates the implementations.
func TestCheckExtensions_NoConstraintFastPathAllocs(t *testing.T) {
	cc := CertConstraint{} // zero Extensions: every field empty -> allow all
	ext := []pkix.Extension{}

	allocs := testing.AllocsPerRun(1000, func() {
		if err := cc.checkExtensions(ext); err != nil {
			t.Fatalf("empty constraint over empty extensions must pass: %v", err)
		}
	})

	const maxAllocs = 10
	if allocs > maxAllocs {
		t.Fatalf("checkExtensions no-constraint path allocates %.0f/op (> %d): reflection metadata or log-arg boxing is being recomputed per call", allocs, maxAllocs)
	}
}
