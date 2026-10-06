// jade:ring local

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// When the platform advertises Pushgate, it is the default next step: one
// line to connect a repository, then a prompt to paste into a coding agent,
// printed as a plain unindented block so it copies clean. `cilock run` stays
// as the secondary path.
func TestPrintLoginResultPointsAtTheAdvertisedPushgate(t *testing.T) {
	var out bytes.Buffer
	printLoginResult(&out, config.DefaultPlatformURL, "https://pushgate.dev", &auth.Credential{
		AuthMode: auth.AuthModeBrowser, TenantID: "t-1", ProductID: "p-1",
	})
	got := out.String()
	connect := strings.Index(got, "\n"+auth.PushgateConnectLine("https://pushgate.dev")+"\n")
	prompt := strings.Index(got, "\n\n"+auth.PushgateAgentPrompt("https://pushgate.dev")+"\n")
	run := strings.Index(got, "Or attest a build directly:\n  "+auth.FirstRunCommand+"\n")
	if connect < 0 || prompt < 0 || run < 0 || connect > prompt || prompt > run {
		t.Fatalf("want connect line, then agent prompt, then the cilock run fallback:\n%s", got)
	}
}

// A platform that advertises no Pushgate (a self-hosted appliance) gets no
// Pushgate line, and `cilock run` is the next step.
func TestPrintLoginResultWithoutPushgateNamesNone(t *testing.T) {
	var out bytes.Buffer
	printLoginResult(&out, "https://judge.internal.example", "", &auth.Credential{AuthMode: auth.AuthModeBrowser, TenantID: "t-1", ProductID: "p-1"})
	got := out.String()
	if strings.Contains(strings.ToLower(got), "pushgate") || !strings.Contains(got, "Next, wrap your build") {
		t.Fatalf("want only the cilock run next step:\n%s", got)
	}
}

// Only a human browser login gets the Pushgate next step, and a CI login never
// pays for the discovery fetch.
func TestNextStepPushgateOriginOnlyForBrowserLogins(t *testing.T) {
	calls := 0
	lookup := func() string { calls++; return "https://pushgate.dev" }
	for mode, want := range map[string]string{
		auth.AuthModeBrowser:      "https://pushgate.dev",
		auth.AuthModeToken:        "",
		auth.AuthModeWorkflowOIDC: "",
	} {
		if got := nextStepPushgateOrigin(&auth.Credential{AuthMode: mode}, lookup); got != want {
			t.Errorf("%s: got %q, want %q", mode, got, want)
		}
	}
	if calls != 1 {
		t.Fatalf("discovery looked up %d times, want 1 (browser only)", calls)
	}
}

// The origin shown to a person comes from discovery and must be a bare secure
// origin; anything else is dropped rather than printed as a link.
func TestLoginPushgateOriginComesFromDiscovery(t *testing.T) {
	orig := discoverPushgateOrigin
	t.Cleanup(func() { discoverPushgateOrigin = orig })
	for advertised, want := range map[string]string{
		"https://pushgate.dev":           "https://pushgate.dev",
		"https://pushgate.dev/":          "https://pushgate.dev",
		"https://pushgate.dev/x?y=1":     "",
		"http://pushgate.example":        "",
		"https://user@pushgate.example/": "",
	} {
		discoverPushgateOrigin = func(string) (string, error) { return advertised, nil }
		if got := publishNextStepPushgateOrigin("https://platform.testifysec.com"); got != want {
			t.Errorf("advertised %q: origin = %q, want %q", advertised, got, want)
		}
	}
}

// A first login is where a new user stops if nothing says what to do next
// (prod journey 2026-10-06: signup, passkey, `cilock login`, then nothing).
// The success output must hand over the exact command and the page where its
// evidence will appear.
func TestPrintLoginResultNamesTheFirstRunAndWhereEvidenceAppears(t *testing.T) {
	for _, mode := range []string{auth.AuthModeBrowser, auth.AuthModeToken} {
		t.Run(mode, func(t *testing.T) {
			var out bytes.Buffer
			printLoginResult(&out, "https://platform.example.com/", "", &auth.Credential{
				AuthMode: mode, TenantID: "t-1", TenantName: "acme", ProductID: "p-1", ProductName: "web",
			})
			got := out.String()
			for _, want := range []string{
				"  " + auth.FirstRunCommand + "\n",
				"https://platform.example.com/products/p-1?tab=test-evidence&tenant=t-1\n",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("login output is missing %q:\n%s", want, got)
				}
			}
		})
	}
}

// The command is quoted verbatim in the web success page and in customer
// copy; changing it is a deliberate, reviewed act.
func TestFirstRunCommandIsStable(t *testing.T) {
	if auth.FirstRunCommand != "cilock run --step build -- <your build command>" {
		t.Fatalf("FirstRunCommand = %q", auth.FirstRunCommand)
	}
}

// Without a bound product there is no evidence page to name, and `cilock use`
// is the next step, so the run hint must not appear.
func TestPrintLoginResultWithoutProductKeepsTheUseHint(t *testing.T) {
	var out bytes.Buffer
	printLoginResult(&out, "https://platform.example.com", "", &auth.Credential{AuthMode: auth.AuthModeBrowser, TenantID: "t-1"})
	got := out.String()
	if !strings.Contains(got, "cilock use") || strings.Contains(got, "cilock run") || strings.Contains(got, "/products/") {
		t.Fatalf("unexpected output without a product:\n%s", got)
	}
}

// IDs come from the platform's callback; they are escaped into the URL rather
// than trusted to be URL-safe.
func TestPrintLoginResultEscapesIDsInEvidenceURL(t *testing.T) {
	var out bytes.Buffer
	printLoginResult(&out, "https://platform.example.com", "", &auth.Credential{
		AuthMode: auth.AuthModeBrowser, TenantID: "a&b=c", ProductID: "x/y?z",
	})
	if want := "https://platform.example.com/products/x%2Fy%3Fz?tab=test-evidence&tenant=a%26b%3Dc"; !strings.Contains(out.String(), want) {
		t.Fatalf("want %q in:\n%s", want, out.String())
	}
}
