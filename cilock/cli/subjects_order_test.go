// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package cli

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/require"
)

// `cilock run --subjects` puts the operator's subjects at the head of the
// signed statement in flag order. JFrog Evidence binds evidence to subject[0]
// and refuses the upload when that is not the artifact; before this, the
// material/product tree roots (https://aflock.ai/...) sorted ahead of it.
func TestRunSubjectsLeadStatementInFlagOrder(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, signer, _ := inventoryRunFixture(t)
	ro.Subjects = []string{
		"zz-image=sha256:" + strings.Repeat("bb", 32),
		"app.tar=sha256:" + strings.Repeat("aa", 32),
	}
	stdout, _, err := inventoryCapture(t, func() error {
		return runRun(t.Context(), ro, []string{"sh", "-c", "printf output > product"}, nil, nil, signer)
	})
	require.NoError(t, err)
	var summary options.RunSummary
	require.NoError(t, json.Unmarshal(stdout, &summary))

	st := inventoryStatement(t, summary.OutFile, signer)
	names := make([]string, 0, len(st.Subject))
	for _, s := range st.Subject {
		names = append(names, s.Name)
	}
	require.Greater(t, len(names), 2, "attestors must contribute subjects, or the order is not exercised: %v", names)
	require.Equal(t, []string{"zz-image", "app.tar"}, names[:2])
	require.Equal(t, strings.Repeat("bb", 32), st.Subject[0].Digest["sha256"])
	require.True(t, sort.StringsAreSorted(names[2:]), "attestor subjects stay sorted: %v", names[2:])
}
