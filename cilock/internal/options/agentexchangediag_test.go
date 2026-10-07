// jade:ring local

package options

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
)

func TestAgentExchangesLogTheUploadTokenFingerprintWithoutTheToken(t *testing.T) {
	isolateCredentialStore(t)
	logs := captureLogs(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatal(err)
	}

	out := logs.all()
	for _, want := range []string{
		"agent credential exchange (initial)", "agent credential exchange (refresh)",
		archivista.TokenSummary(agentUploadBearerFirst), archivista.TokenSummary(agentUploadBearerSecond),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logs lack %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{agentUploadBearerFirst, agentUploadBearerSecond, agentRefreshCredential} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain the secret %q", secret)
		}
	}
}
