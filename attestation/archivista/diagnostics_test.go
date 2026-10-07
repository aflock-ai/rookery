// jade:ring local

package archivista

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
)

type diagLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *diagLogger) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}
func (l *diagLogger) Errorf(f string, a ...interface{}) { l.add(fmt.Sprintf(f, a...)) }
func (l *diagLogger) Error(a ...interface{})            { l.add(fmt.Sprint(a...)) }
func (l *diagLogger) Warnf(f string, a ...interface{})  { l.add(fmt.Sprintf(f, a...)) }
func (l *diagLogger) Warn(a ...interface{})             { l.add(fmt.Sprint(a...)) }
func (l *diagLogger) Debugf(f string, a ...interface{}) { l.add(fmt.Sprintf(f, a...)) }
func (l *diagLogger) Debug(a ...interface{})            { l.add(fmt.Sprint(a...)) }
func (l *diagLogger) Infof(f string, a ...interface{})  { l.add(fmt.Sprintf(f, a...)) }
func (l *diagLogger) Info(a ...interface{})             { l.add(fmt.Sprint(a...)) }

func (l *diagLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func diagJWT(kid string, iat, exp int64, marker string) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(fmt.Sprintf(`{"alg":"ES256","kid":%q}`, kid)) + "." +
		enc(fmt.Sprintf(`{"iat":%d,"exp":%d}`, iat, exp)) + "." + enc("sig-"+marker)
}

func TestUpload401LogsTheTokenSentAndWhoRefusedItWithoutTheSecret(t *testing.T) {
	first := diagJWT("kid-one", 1700000000, 1700007200, "first")
	second := diagJWT("kid-two", 1700009000, 1700016200, "second")
	logs := &diagLogger{}
	log.SetLogger(logs)
	t.Cleanup(func() { log.SetLogger(log.SilentLogger{}) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.Header().Set("X-Request-Id", "req-123")
		w.Header().Set("X-Pod-Name", "judge-api-canary-9")
		w.Header().Set("Set-Cookie", "session=must-not-be-logged")
		http.Error(w, "Invalid API credential", http.StatusUnauthorized)
	}))
	defer srv.Close()

	token := first
	c := New(srv.URL,
		WithAuthTokenSource(func() (string, error) { return token, nil }),
		WithAuthRefresh(func() error { token = second; return nil }))
	_, err := c.Store(context.Background(), dsse.Envelope{Payload: []byte("{}"), PayloadType: "x"})
	if err == nil {
		t.Fatal("expected the refused upload to fail")
	}

	out := logs.all()
	for _, want := range []string{
		"fp=" + tokenFingerprint(first), "fp=" + tokenFingerprint(second),
		"kid=kid-one", "kid=kid-two", "exp=2023-11-15T00:13:20Z",
		`Www-Authenticate="Bearer error=\"invalid_token\""`, `X-Request-Id="req-123"`, `X-Pod-Name="judge-api-canary-9"`,
		" bytes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logs lack %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{first, second, strings.Split(first, ".")[2], strings.Split(second, ".")[1], "must-not-be-logged"} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
}
