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
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// THE INVARIANCE SUITE. Run this on the PRE-change tree first: it compares the
// frozen copy against the live eager engine and must be green BEFORE the lazy
// stop exists. Green there proves the copy is faithful; green after proves the
// change did not touch eager verification.
// ---------------------------------------------------------------------------
func TestFrozenOracleMatchesLiveEagerEngine(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, shape := range lazyShapes() {
		t.Run(shape.name, func(t *testing.T) {
			oracle := runLazyShape(t, shape, lazyOracleMode(), verifier, keyID)
			eager := runLazyShape(t, shape, lazyEagerMode(), verifier, keyID)

			assert.Equal(t, oracle.pass, eager.pass,
				"%s: the live eager engine disagrees with the frozen pre-change copy on the VERDICT — either eager verification changed (re-freeze lazy_frozen_oracle_test.go) or the change leaked into the flag-off path", shape.desc)
			assert.Equal(t, oracle.passed, eager.passed,
				"%s: the live eager engine disagrees with the frozen copy on the PASSED set", shape.desc)
			assert.Equal(t, oracle.rejected, eager.rejected,
				"%s: the live eager engine disagrees with the frozen copy on the REJECTED set", shape.desc)
			assert.Equal(t, oracle.yielded, eager.yielded,
				"%s: the live eager engine examined a different number of candidates than the frozen copy — the flag-off path must be cost-identical, not merely verdict-identical", shape.desc)
		})
	}
}
