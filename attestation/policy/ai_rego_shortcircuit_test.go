// jade:ring local

package policy

import (
	"context"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

func TestAiSkipsRegoRejectedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		module   []byte
		accepted bool
	}{
		{"accept control", regoAccept, true},
		{"explicit denial", []byte("package gate\ndeny[msg] { msg := \"not permitted\" }"), false},
		{"undefined deny rule", []byte("package gate\nallow := true"), false},
		{"invalid module", []byte("this is not rego"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFanoutFixture(t)
			p := aiPolicyWithGuard(f)
			step := p.Steps[fanoutStepName]
			step.Attestations[0].RegoPolicies = []RegoPolicy{{Name: "deterministic-gate", Module: tc.module}}
			p.Steps[fanoutStepName] = step
			mem := source.NewMemorySource()
			for _, env := range fanoutCorpus(t, f, 0) {
				require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
			}
			srv, calls := countingAIServer(t)
			accepted, _, err := p.Verify(context.Background(),
				WithVerifiedSource(source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))),
				WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}), WithAiServerURL(srv.URL))
			require.NoError(t, err)
			require.Equal(t, tc.accepted, accepted)
			if tc.accepted {
				require.Positive(t, calls.Load(), "control must reach the AI provider")
			} else {
				require.Zero(t, calls.Load(), "deterministically rejected evidence must not leave for inference")
			}
		})
	}
}
