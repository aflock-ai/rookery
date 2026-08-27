// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"

	// Register the fulcio signer provider so AddFlags wires up the
	// --signer-fulcio-* flags every keyless path targets.
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// fulcioTokenFlagName is the flag every keyless credential path installs a
// short-lived OIDC token on. The sweep below finds its setters in the source.
const fulcioTokenFlagName = "signer-fulcio-token"

// The certificate is minted lazily, at first signature, AFTER the wrapped
// command has run. Every token installed before the command is short lived, so
// EVERY keyless credential path — not just the stored-session one — has to hand
// back a signing-time refresher, or a long CI build presents an expired token
// to Fulcio and gets HTTP 400.
//
// These two tests are a sweep, not an instance check. The first quantifies over
// every credential shape that reaches a keyless signer and demands a working
// refresher from each. The second quantifies over the SOURCE: it finds every
// function that installs the fulcio token flag and every call site of those
// installers, and fails when one appears that the behavioral sweep does not
// cover. A new keyless path added without a refresher therefore cannot land
// silently — it breaks the closure check even if nobody writes a test for it.

// keylessPathCase is one credential shape that ends in a keyless Fulcio signer.
type keylessPathCase struct {
	name string
	// setup seeds the environment (credential store, stubs) and returns the
	// platform URL to resolve against.
	setup func(t *testing.T) string
}

func keylessPathCases() []keylessPathCase {
	return []keylessPathCase{
		{
			// applyPlatformCredential → applyKeylessFulcioToken
			name: "stored session credential exchanged at /oauth/sign-token",
			setup: func(t *testing.T) string {
				t.Helper()
				var n int64
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost && r.URL.Path == "/oauth/sign-token" {
						i := atomic.AddInt64(&n, 1)
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]string{
							"token":      "session-token-" + strconv.FormatInt(i, 10),
							"token_type": "oidc",
						})
						return
					}
					http.NotFound(w, r)
				}))
				t.Cleanup(srv.Close)

				if err := auth.Save(auth.Credential{
					PlatformURL: srv.URL,
					Token:       "stored-session-credential",
					AuthMode:    auth.AuthModeBrowser,
					ExpiresAt:   time.Now().Add(time.Hour),
				}); err != nil {
					t.Fatalf("seed session credential: %v", err)
				}
				return srv.URL
			},
		},
		{
			// applyPlatformCredential → applyWorkflowKeylessFulcioToken
			name: "stored workflow-identity credential minting ambient CI OIDC",
			setup: func(t *testing.T) string {
				t.Helper()
				const platform = "https://platform.sandbox.example.com"
				stubAmbientOIDC(t)
				if err := auth.Save(auth.Credential{
					PlatformURL: platform,
					AuthMode:    auth.AuthModeWorkflowOIDC,
					ExpiresAt:   time.Now().Add(time.Hour),
				}); err != nil {
					t.Fatalf("seed workflow-identity credential: %v", err)
				}
				return platform
			},
		},
		{
			// resolvePlatformIdentity → applyWorkflowKeylessFulcioToken
			name: "no login, ambient CI OIDC only",
			setup: func(t *testing.T) string {
				t.Helper()
				stubAmbientOIDC(t)
				return "https://platform.sandbox.example.com"
			},
		},
	}
}

// stubAmbientOIDC stands up a GitHub Actions OIDC endpoint that hands back a
// DIFFERENT token on every mint, so a refresher that genuinely re-mints is
// distinguishable from one that reinstalls the same stale value.
func stubAmbientOIDC(t *testing.T) {
	t.Helper()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := atomic.AddInt64(&n, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"value": fmt.Sprintf("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3b3JrZmxvdyIsIm4iOiV%d9.sig", i),
		})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghs-fake-bearer")
}

// TestEveryKeylessCredentialPathInstallsASigningTimeRefresher sweeps every
// credential shape that reaches a keyless Fulcio signer and demands the same
// property from each: a non-nil signing-time refresher that, when invoked,
// succeeds and installs a freshly minted token on the flag.
func TestEveryKeylessCredentialPathInstallsASigningTimeRefresher(t *testing.T) {
	for _, tc := range keylessPathCases() {
		t.Run(tc.name, func(t *testing.T) {
			isolateCredentialStore(t)
			platform := tc.setup(t)

			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags([]string{"--platform-url", platform}); err != nil {
				t.Fatal(err)
			}
			ro.ResolvePlatformDefaults(cmd)

			// Precondition: this case really is a keyless path. Without it a
			// regression that stops installing a token would pass vacuously.
			before := cmd.Flags().Lookup(fulcioTokenFlagName).Value.String()
			if before == "" {
				t.Fatalf("precondition failed: no keyless token installed, so this case proves nothing")
			}

			refresh := ro.FulcioTokenRefresher()
			if refresh == nil {
				t.Fatalf("keyless path installed a short-lived token but no signing-time refresher; "+
					"a build longer than the token lifetime will present an expired token to Fulcio "+
					"(installed token %q)", before)
			}

			if err := refresh(); err != nil {
				t.Fatalf("signing-time refresh failed: %v", err)
			}
			after := cmd.Flags().Lookup(fulcioTokenFlagName).Value.String()
			if after == "" {
				t.Fatal("refresher cleared the fulcio token instead of replacing it")
			}
			if after == before {
				t.Fatalf("refresher reinstalled the SAME token %q; it must re-mint, "+
					"otherwise the expiry it exists to defeat is unchanged", after)
			}
		})
	}
}

// TestKeylessFulcioTokenInstallersAreAllSwept closes the sweep over the source
// rather than over a hand-listed set of behaviors: it finds every function in
// this package that installs the fulcio token flag, and every call site of those
// installers, and fails when one shows up that the behavioral sweep above does
// not exercise. Adding a fourth keyless path without a refresher breaks here.
func TestKeylessFulcioTokenInstallersAreAllSwept(t *testing.T) {
	// The refresher exists because `cilock run` mints the token during option
	// resolution and requests the Fulcio certificate AFTER the wrapped command.
	// Call sites therefore fall into exactly two categories, and a new one that
	// lands in neither fails this test.
	//
	// deferredSigningCallers run a wrapped command between the mint and the
	// signature, so each MUST install a refresher and each is exercised by
	// keylessPathCases above.
	deferredSigningCallers := map[string]bool{
		"applyPlatformCredential": true, // RunOptions: session and workflow-identity
		"resolvePlatformIdentity": true, // RunOptions: ambient CI, no login
	}
	// immediateSigningCallers sign inside the same option-resolution window that
	// minted the token — no wrapped command, so nothing can expire in between and
	// the refresher is deliberately discarded. Moving one of these behind a
	// long-running step means moving it into the deferred set and giving it a case.
	immediateSigningCallers := map[string]bool{
		"applyKeylessPlatformSigner": true, // SignOptions: `cilock sign` wraps no command
	}
	// Installer functions the sweep knows about.
	sweptInstallers := map[string]bool{
		"applyKeylessFulcioToken":         true,
		"applyWorkflowKeylessFulcioToken": true,
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		// Production sources only — a test file may legitimately set the flag.
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the options package: %v", err)
	}

	installers := map[string]bool{}
	callers := map[string]map[string]bool{}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if setsFulcioTokenFlag(call) {
						installers[fn.Name.Name] = true
					}
					if ident, ok := call.Fun.(*ast.Ident); ok && sweptInstallers[ident.Name] {
						if callers[ident.Name] == nil {
							callers[ident.Name] = map[string]bool{}
						}
						callers[ident.Name][fn.Name.Name] = true
					}
					return true
				})
			}
		}
	}

	if len(installers) == 0 {
		t.Fatal("found no function installing " + fulcioTokenFlagName + "; the source sweep is broken, not the code")
	}
	for _, name := range sortedKeys(installers) {
		if !sweptInstallers[name] {
			t.Errorf("%s installs %s but the keyless refresher sweep does not know about it; "+
				"it must hand back a signing-time refresher and be listed in sweptInstallers",
				name, fulcioTokenFlagName)
		}
	}
	for installer := range sweptInstallers {
		if !installers[installer] {
			t.Errorf("%s no longer installs %s — the sweep is stale, update sweptInstallers",
				installer, fulcioTokenFlagName)
			continue
		}
		for _, caller := range sortedKeys(callers[installer]) {
			switch {
			case deferredSigningCallers[caller], immediateSigningCallers[caller]:
			default:
				t.Errorf("%s is called from %s, which is in neither the deferred-signing nor the "+
					"immediate-signing set. Every caller installs a SHORT-LIVED token: if a wrapped or "+
					"long-running step sits between the mint and the signature it must install the "+
					"refresher and get a case in keylessPathCases; if it signs immediately, say so by "+
					"listing it in immediateSigningCallers", installer, caller)
			}
		}
	}
	// Every caller the sweep claims to cover must actually exist, or the two
	// tests drift apart and the behavioral sweep silently stops proving anything.
	covered := map[string]bool{}
	for _, byCaller := range callers {
		for caller := range byCaller {
			covered[caller] = true
		}
	}
	for caller := range deferredSigningCallers {
		if !covered[caller] {
			t.Errorf("deferred-signing caller %s no longer installs a keyless token; the sweep is stale", caller)
		}
	}
	for caller := range immediateSigningCallers {
		if !covered[caller] {
			t.Errorf("immediate-signing caller %s no longer installs a keyless token; the sweep is stale", caller)
		}
	}
}

// setsFulcioTokenFlag reports whether the call is `…Set("signer-fulcio-token", …)`.
func setsFulcioTokenFlag(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Set" || len(call.Args) == 0 {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	name, err := strconv.Unquote(lit.Value)
	return err == nil && name == fulcioTokenFlagName
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
