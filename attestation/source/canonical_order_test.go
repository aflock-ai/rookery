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

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// VerifiedSource must FORWARD its wrapped Sourcer's canonical-order
// declaration, and must never invent one.
//
// The policy engine only ever holds a VerifiedSourcer, so this forwarding is
// the entire path by which a real source's promise reaches the minimum-witness
// stop. Both directions are load-bearing:
//
//   - forward TRUE, or no production source can ever qualify and the feature is
//     dead on arrival;
//   - forward FALSE (and default to false), or a source that cannot promise
//     ordering silently gets the stop and the signed attestation becomes
//     delivery-order-dependent.
// ---------------------------------------------------------------------------

// canonOrderStubSourcer is the variant that does NOT implement
// CanonicalOrderSourcer at all.
type canonOrderStubSourcer struct{}

func (s canonOrderStubSourcer) Search(_ context.Context, _ string, _, _ []string) ([]CollectionEnvelope, error) {
	return nil, nil
}

func (s canonOrderStubSourcer) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]StatementEnvelope, error) {
	return nil, nil
}

// canonOrderDeclaringSourcer is the variant that implements the interface.
type canonOrderDeclaringSourcer struct {
	canonOrderStubSourcer
	value bool
}

func (s canonOrderDeclaringSourcer) CanonicalStreamOrder() bool { return s.value }

func TestVerifiedSource_ForwardsCanonicalOrderDeclaration(t *testing.T) {
	cases := []struct {
		name string
		src  Sourcer
		want bool
	}{
		{
			name: "underlying declares true",
			src:  canonOrderDeclaringSourcer{value: true},
			want: true,
		},
		{
			name: "underlying declares false",
			src:  canonOrderDeclaringSourcer{value: false},
			want: false,
		},
		{
			name: "underlying does not implement the interface",
			src:  canonOrderStubSourcer{},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := NewVerifiedSource(tc.src)

			c, ok := interface{}(vs).(CanonicalOrderSourcer)
			require.True(t, ok, "*VerifiedSource must always implement CanonicalOrderSourcer so it can answer for what it wraps")
			assert.Equal(t, tc.want, c.CanonicalStreamOrder(),
				"VerifiedSource must report exactly what it wraps — it never reorders, so it can be neither stronger nor weaker than its source")
		})
	}
}

// ArchivistaSource must NOT declare canonical order: the ordering it yields is
// a remote server's query plan, not a promise this client can make. This is a
// deliberate omission, so it gets a test rather than a comment alone — an
// accidental future declaration would silently make every archivista-backed
// verify sign a delivery-order-dependent witness.
func TestArchivistaSource_DoesNotDeclareCanonicalOrder(t *testing.T) {
	var s Sourcer = NewArchivistaSource(nil)
	_, declares := s.(CanonicalOrderSourcer)
	assert.False(t, declares,
		"ArchivistaSource must NOT implement CanonicalOrderSourcer — its result order belongs to the remote server. "+
			"If archivista ever specifies and guarantees a canonical order, declare it THERE and update this test with the reference.")

	// And the wrapper must agree.
	vs := NewVerifiedSource(NewArchivistaSource(nil))
	c, ok := interface{}(vs).(CanonicalOrderSourcer)
	require.True(t, ok)
	assert.False(t, c.CanonicalStreamOrder(),
		"a VerifiedSource wrapping ArchivistaSource must report NO canonical order")
}
