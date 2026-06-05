package options

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const sandbox = "https://platform.aws-sandbox-staging.testifysec.dev"

func TestResolve_GitHubSaaS(t *testing.T) {
	o := &TrustOptions{PlatformURL: sandbox, Provider: "github", Slug: "testifysec/judge"}
	r, err := o.Resolve("tenant-123")
	if err != nil {
		t.Fatal(err)
	}
	want := &ResolvedTrust{
		Name:      "github:testifysec/judge",
		Subject:   "repo:testifysec/judge:*",
		Audience:  sandbox + "/archivista",
		IssuerURL: "https://token.actions.githubusercontent.com",
		Scopes:    []string{"attestation:upload"},
		TenantID:  "tenant-123",
	}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("got  %+v\nwant %+v", r, want)
	}
}

func TestResolve_GitHubOnPrem(t *testing.T) {
	o := &TrustOptions{PlatformURL: sandbox, Provider: "github", Slug: "acme/app", Host: "github.acme.com"}
	r, err := o.Resolve("t")
	if err != nil {
		t.Fatal(err)
	}
	if r.IssuerURL != "https://github.acme.com/_services/token" {
		t.Fatalf("GHES issuer = %q", r.IssuerURL)
	}
	if r.Subject != "repo:acme/app:*" {
		t.Fatalf("subject = %q", r.Subject)
	}
}

func TestResolve_GitLabNestedGroup(t *testing.T) {
	o := &TrustOptions{PlatformURL: sandbox, Provider: "gitlab", Slug: "acme/team/app"}
	r, err := o.Resolve("t")
	if err != nil {
		t.Fatal(err)
	}
	if r.IssuerURL != "https://gitlab.com" {
		t.Fatalf("gitlab issuer = %q", r.IssuerURL)
	}
	if r.Subject != "project_path:acme/team/app:*" {
		t.Fatalf("subject = %q", r.Subject)
	}
}

func TestResolve_Generic(t *testing.T) {
	o := &TrustOptions{PlatformURL: sandbox, Issuer: "https://oidc.corp.example/foo", Subject: "build:acme:*"}
	r, err := o.Resolve("t")
	if err != nil {
		t.Fatal(err)
	}
	if r.IssuerURL != "https://oidc.corp.example/foo" || r.Subject != "build:acme:*" {
		t.Fatalf("generic issuer/subject = %q / %q", r.IssuerURL, r.Subject)
	}
	if r.Name != "oidc:oidc.corp.example" {
		t.Fatalf("derived name = %q", r.Name)
	}
}

func TestResolve_RejectsInsecureIssuer(t *testing.T) {
	// OIDC issuers are dereferenced server-side for discovery/JWKS, so a
	// non-https issuer is an insecure trust root / SSRF vector and must be
	// rejected client-side (not just by the platform mutation).
	for _, issuer := range []string{"http://oidc.corp.example/foo", "oidc.corp.example/foo", "ftp://oidc.corp.example"} {
		o := &TrustOptions{PlatformURL: sandbox, Issuer: issuer, Subject: "build:acme:*"}
		if _, err := o.Resolve("t"); err == nil {
			t.Fatalf("expected rejection of insecure issuer %q, got nil", issuer)
		}
	}
}

func TestResolve_VerifyAddsReadScope(t *testing.T) {
	o := &TrustOptions{PlatformURL: sandbox, Provider: "github", Slug: "a/b", Verify: true}
	r, err := o.Resolve("t")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Scopes, []string{"attestation:upload", "attestation:read"}) {
		t.Fatalf("scopes = %v", r.Scopes)
	}
}

func TestResolve_AudienceOverride(t *testing.T) {
	o := &TrustOptions{PlatformURL: sandbox, Provider: "github", Slug: "a/b", Audience: "custom-aud"}
	r, _ := o.Resolve("t")
	if r.Audience != "custom-aud" {
		t.Fatalf("audience = %q", r.Audience)
	}
}

func TestResolve_RejectsManagementScopes(t *testing.T) {
	for _, bad := range []string{"tenant:admin", "oidc:write", "supplychain:admin", "compliance:write"} {
		o := &TrustOptions{PlatformURL: sandbox, Provider: "github", Slug: "a/b", Scopes: []string{bad}}
		if _, err := o.Resolve("t"); err == nil {
			t.Fatalf("expected rejection of scope %q", bad)
		}
	}
}

func TestResolve_Errors(t *testing.T) {
	cases := map[string]*TrustOptions{
		"unknown provider": {PlatformURL: sandbox, Provider: "bitbucket", Slug: "a/b"},
		"no slug":          {PlatformURL: sandbox, Provider: "github"},
		"bad slug url":     {PlatformURL: sandbox, Provider: "github", Slug: "https://github.com/a/b"},
		"bad slug .git":    {PlatformURL: sandbox, Provider: "github", Slug: "a/b.git/"},
		"github 3 segs":    {PlatformURL: sandbox, Provider: "github", Slug: "a/b/c"},
		"nothing":          {PlatformURL: sandbox},
		"no tenant":        {PlatformURL: sandbox, Provider: "github", Slug: "a/b"},
		"empty platform":   {Provider: "github", Slug: "a/b"},
	}
	for name, o := range cases {
		tenant := "t"
		if name == "no tenant" {
			tenant = ""
		}
		if _, err := o.Resolve(tenant); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseOriginRemote(t *testing.T) {
	cases := []struct {
		in       string
		provider string
		slug     string
		host     string
		wantErr  bool
	}{
		{"git@github.com:testifysec/judge.git", "github", "testifysec/judge", "", false},
		{"https://github.com/testifysec/judge.git", "github", "testifysec/judge", "", false},
		{"https://github.com/testifysec/judge", "github", "testifysec/judge", "", false},
		{"git@gitlab.com:acme/team/app.git", "gitlab", "acme/team/app", "", false},
		{"https://x-token@github.com/testifysec/judge.git", "github", "testifysec/judge", "", false},
		{"git@github.acme.com:acme/app.git", "github", "acme/app", "github.acme.com", false},
		{"https://gitlab.acme.com/acme/app.git", "gitlab", "acme/app", "gitlab.acme.com", false},
		{"https://bitbucket.org/acme/app.git", "", "acme/app", "bitbucket.org", true}, // unknown host
		{"", "", "", "", true},
	}
	for _, c := range cases {
		p, s, h, err := ParseOriginRemote(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if p != c.provider || s != c.slug || h != c.host {
			t.Errorf("%q: got (%q,%q,%q) want (%q,%q,%q)", c.in, p, s, h, c.provider, c.slug, c.host)
		}
	}
}

func TestCreateOIDCCredential(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"createCredential":{"credential":{"id":"cred-1","name":"github:testifysec/judge","type":"OIDC","subject":"repo:testifysec/judge:*","audience":"` + sandbox + `/archivista","issuerURL":"https://token.actions.githubusercontent.com","scopes":["attestation:upload"]}}}}`))
	}))
	defer srv.Close()

	r := &ResolvedTrust{
		Name: "github:testifysec/judge", Subject: "repo:testifysec/judge:*",
		Audience: sandbox + "/archivista", IssuerURL: "https://token.actions.githubusercontent.com",
		Scopes: []string{"attestation:upload"}, TenantID: "tenant-123",
	}
	cred, err := CreateOIDCCredential(context.Background(), srv.URL, "sess-tok", r)
	if err != nil {
		t.Fatal(err)
	}
	if cred.ID != "cred-1" || cred.Type != "OIDC" {
		t.Fatalf("cred = %+v", cred)
	}
	if gotAuth != "Bearer sess-tok" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	// The request must always send type=OIDC and the exact input fields.
	var sent struct {
		Variables struct {
			Input map[string]any `json:"input"`
		} `json:"variables"`
	}
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Variables.Input["type"] != "OIDC" {
		t.Fatalf("request type = %v, must be OIDC", sent.Variables.Input["type"])
	}
	if sent.Variables.Input["tenantID"] != "tenant-123" || sent.Variables.Input["issuerURL"] != "https://token.actions.githubusercontent.com" {
		t.Fatalf("input = %v", sent.Variables.Input)
	}
}

func TestCreateOIDCCredential_GraphQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"forbidden: requires oidc:write"}]}`))
	}))
	defer srv.Close()
	_, err := CreateOIDCCredential(context.Background(), srv.URL, "t", &ResolvedTrust{Name: "x", TenantID: "t"})
	if err == nil || !strings.Contains(err.Error(), "oidc:write") {
		t.Fatalf("want GraphQL error surfaced, got %v", err)
	}
}
