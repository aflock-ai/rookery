// jade:ring local
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

// embeddingWrapper embeds a Forker and filters its searches. Its promoted Fork
// would return the INNER source and drop the filter, so it must not fork.
type embeddingWrapper struct {
	*MemorySource
}

func (w embeddingWrapper) Search(context.Context, string, []string, []string) ([]CollectionEnvelope, error) {
	return nil, nil
}

type opaqueSource struct{ Sourcer }

func TestForkSourcer(t *testing.T) {
	mem := NewMemorySource()

	t.Run("memory source is its own fresh copy", func(t *testing.T) {
		f, ok := forkSourcer(mem)
		require.True(t, ok)
		assert.Same(t, mem, f)
	})
	t.Run("a wrapper whose promoted Fork changes type is refused", func(t *testing.T) {
		_, ok := forkSourcer(embeddingWrapper{mem})
		assert.False(t, ok, "forking would drop the wrapper's own filter")
		_, ok = NewVerifiedSource(embeddingWrapper{mem}).ForkVerified()
		assert.False(t, ok)
	})
	t.Run("a source without Fork is refused", func(t *testing.T) {
		_, ok := forkSourcer(opaqueSource{mem})
		assert.False(t, ok)
	})
	t.Run("multi source forks only when every sub-source does", func(t *testing.T) {
		f, ok := forkSourcer(NewMultiSource(mem, NewMemorySource()))
		require.True(t, ok)
		assert.Len(t, f.(*MultiSource).sources, 2)
		_, ok = forkSourcer(NewMultiSource(mem, opaqueSource{mem}))
		assert.False(t, ok)
	})
	t.Run("archivista source forks with empty search state", func(t *testing.T) {
		a := NewArchivistaSource(nil)
		a.seenCollectionGitoids = append(a.seenCollectionGitoids, "g1")
		a.seenPredicateGitoids = append(a.seenPredicateGitoids, "g2")
		a.completedSearches = map[string]struct{}{"k": {}}
		f, ok := forkSourcer(a)
		require.True(t, ok)
		fa := f.(*ArchivistaSource)
		assert.NotSame(t, a, fa)
		assert.Empty(t, fa.seenCollectionGitoids)
		assert.Empty(t, fa.seenPredicateGitoids)
		assert.Empty(t, fa.completedSearches)
	})
	t.Run("recording source forks the inner source and shares the sink", func(t *testing.T) {
		r := NewRecordingSource(mem)
		f, ok := forkSourcer(r)
		require.True(t, ok)
		fr := f.(*RecordingSource)
		assert.NotSame(t, r, fr)
		assert.Same(t, r.sink, fr.sink, "a bundle must hold what every run consulted")
		_, ok = forkSourcer(NewRecordingSource(opaqueSource{mem}))
		assert.False(t, ok)
	})
	t.Run("verified source keeps its options", func(t *testing.T) {
		vs := NewVerifiedSource(mem)
		f, ok := vs.ForkVerified()
		require.True(t, ok)
		fvs := f.(*VerifiedSource)
		assert.NotSame(t, vs, fvs)
		assert.Same(t, mem, fvs.source)
	})
}
