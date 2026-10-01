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

package l3

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/sigstore/fulcio/pkg/certificate"
)

const (
	// GitHubIssuer is the OIDC issuer of GitHub Actions job tokens.
	GitHubIssuer = "https://token.actions.githubusercontent.com"
	// ProvenancePredicateType is the SLSA v1 provenance predicate type (#9827).
	ProvenancePredicateType = "https://slsa.dev/provenance/v1"
	// StatementTypeV1 is the in-toto v1 statement type.
	StatementTypeV1 = "https://in-toto.io/Statement/v1"
	// BuildType is the buildDefinition.buildType provenance.yml writes.
	BuildType = "https://aflock.ai/cilock/provenance-workflow@v1"

	githubURL          = "https://github.com/"
	runnerGitHubHosted = "github-hosted"
)

var (
	repoName  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	digits    = regexp.MustCompile(`^[0-9]+$`)
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ExtFromCertificate reads the Fulcio GitHub extensions from cert, literally.
// A missing extension is an error, never a wildcard; the issuer must be
// GitHub Actions; and the run in Run Invocation URI must belong to the source
// repository. The attempt number is dropped: a rerun is the same run.
func ExtFromCertificate(cert *x509.Certificate) (Ext, error) {
	if cert == nil {
		return Ext{}, fmt.Errorf("no certificate")
	}
	ext, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		return Ext{}, fmt.Errorf("parse fulcio extensions: %w", err)
	}
	if ext.Issuer != GitHubIssuer {
		return Ext{}, fmt.Errorf("certificate issuer %q is not %q", ext.Issuer, GitHubIssuer)
	}
	path, ref, err := splitGitHubRef(ext.BuildSignerURI)
	if err != nil {
		return Ext{}, fmt.Errorf("build signer URI: %w", err)
	}
	repo, err := githubRepo(ext.SourceRepositoryURI)
	if err != nil {
		return Ext{}, fmt.Errorf("source repository URI: %w", err)
	}
	run, err := parseRunURI(ext.RunInvocationURI)
	if err != nil {
		return Ext{}, fmt.Errorf("run invocation URI: %w", err)
	}
	if run.attempt == "" {
		return Ext{}, fmt.Errorf("run invocation URI %q has no attempt", ext.RunInvocationURI)
	}
	if run.repo != repo {
		return Ext{}, fmt.Errorf("run invocation URI names repository %q, source repository is %q", run.repo, repo)
	}
	for name, v := range map[string]string{
		"build signer digest": ext.BuildSignerDigest, "source repository digest": ext.SourceRepositoryDigest, "build trigger": ext.BuildTrigger,
	} {
		if v == "" {
			return Ext{}, fmt.Errorf("certificate has no %s", name)
		}
	}
	return Ext{
		SignerPath: path, SignerRef: ref, SignerDigest: ext.BuildSignerDigest,
		SourceRepo: repo, SourceDigest: ext.SourceRepositoryDigest, RunID: run.id,
		Trigger: ext.BuildTrigger, Hosted: ext.RunnerEnvironment == runnerGitHubHosted,
	}, nil
}

// buildConfigURI is the certificate's Build Config URI (workflow_ref), or ""
// when it has none. ExtFromCertificate has already parsed the extensions.
func buildConfigURI(cert *x509.Certificate) string {
	ext, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		return ""
	}
	return ext.BuildConfigURI
}

// checkExternalParameters enforces the externalParameters of BuildType:
// exactly {"workflow": {"repository", "path", "ref"}}, all strings, and
// "https://github.com/<repository>/<path>@<ref>" equal to the signer
// certificate's Build Config URI. Unknown fields are refused (SLSA
// verifying-artifacts: "SHOULD reject unrecognized fields").
func checkExternalParameters(raw json.RawMessage, signer Cert) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return fmt.Errorf("externalParameters is not an object")
	}
	for k := range top {
		if k != "workflow" {
			return fmt.Errorf("externalParameters has unknown field %q", k)
		}
	}
	fields, err := workflowFields(top["workflow"])
	if err != nil {
		return err
	}
	if want := githubURL + signer.Ext.SourceRepo; fields["repository"] != want {
		return fmt.Errorf("externalParameters.workflow.repository %q is not the certificate's %q", fields["repository"], want)
	}
	if got := fields["repository"] + "/" + fields["path"] + "@" + fields["ref"]; signer.ConfigURI == "" || got != signer.ConfigURI {
		return fmt.Errorf("externalParameters.workflow names %q; the certificate's Build Config URI is %q", got, signer.ConfigURI)
	}
	return nil
}

// workflowFields decodes externalParameters.workflow: exactly repository,
// path and ref, each a non-empty string.
func workflowFields(raw json.RawMessage) (map[string]string, error) {
	var wf map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wf); err != nil || wf == nil {
		return nil, fmt.Errorf("externalParameters.workflow is not an object")
	}
	fields := map[string]string{}
	for k, v := range wf {
		if k != "repository" && k != "path" && k != "ref" {
			return nil, fmt.Errorf("externalParameters.workflow has unknown field %q", k)
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil || s == "" {
			return nil, fmt.Errorf("externalParameters.workflow.%s is not a non-empty string", k)
		}
		fields[k] = s
	}
	if len(fields) != 3 {
		return nil, fmt.Errorf("externalParameters.workflow needs repository, path and ref")
	}
	return fields, nil
}

// splitGitHubRef splits "https://github.com/<path>@<ref>" at the first "@".
// GitHub owner and repository names cannot contain "@", so the first "@"
// ends the path.
func splitGitHubRef(uri string) (path, ref string, err error) {
	rest, ok := strings.CutPrefix(uri, githubURL)
	if !ok {
		return "", "", fmt.Errorf("%q is not under %s", uri, githubURL)
	}
	path, ref, ok = strings.Cut(rest, "@")
	if !ok || path == "" || ref == "" {
		return "", "", fmt.Errorf("%q is not <path>@<ref>", uri)
	}
	return path, ref, nil
}

func githubRepo(uri string) (string, error) {
	repo, ok := strings.CutPrefix(uri, githubURL)
	if !ok || !repoName.MatchString(repo) {
		return "", fmt.Errorf("%q is not %s<owner>/<name>", uri, githubURL)
	}
	return repo, nil
}

type runRef struct{ repo, id, attempt string }

// parseRunURI parses "https://github.com/<owner>/<name>/actions/runs/<id>"
// with an optional "/attempts/<n>".
func parseRunURI(uri string) (runRef, error) {
	rest, ok := strings.CutPrefix(uri, githubURL)
	if !ok {
		return runRef{}, fmt.Errorf("%q is not under %s", uri, githubURL)
	}
	parts := strings.Split(rest, "/")
	if (len(parts) != 5 && len(parts) != 7) || parts[2] != "actions" || parts[3] != "runs" || !digits.MatchString(parts[4]) {
		return runRef{}, fmt.Errorf("%q is not a GitHub Actions run URL", uri)
	}
	r := runRef{repo: parts[0] + "/" + parts[1], id: parts[4]}
	if !repoName.MatchString(r.repo) {
		return runRef{}, fmt.Errorf("%q names an invalid repository", uri)
	}
	if len(parts) == 7 {
		if parts[5] != "attempts" || !digits.MatchString(parts[6]) {
			return runRef{}, fmt.Errorf("%q is not a GitHub Actions run URL", uri)
		}
		r.attempt = parts[6]
	}
	return r, nil
}

type rawStatement struct {
	Type          string           `json:"_type"`
	Subject       []intoto.Subject `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     json.RawMessage  `json:"predicate"`
}

func decodeStatement(payload []byte) (rawStatement, error) {
	var st rawStatement
	if err := rejectCollidingKeys(payload); err != nil {
		return st, fmt.Errorf("decode in-toto statement: %w", err)
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		return st, fmt.Errorf("decode in-toto statement: %w", err)
	}
	if st.Type != StatementTypeV1 && st.Type != intoto.StatementType {
		return st, fmt.Errorf("statement type %q is not in-toto", st.Type)
	}
	return st, nil
}

// rejectCollidingKeys refuses a JSON document in which any object carries two
// keys equal up to case, a repeated key included. The statement is decoded
// into structs, and encoding/json matches a key to a field case-insensitively
// and keeps the last match, while an exact-key reader (Rego, a map decode, a
// first-wins parser) resolves the same object to a different value. Refusing
// the collision keeps every reader of the envelope on one subject, builder
// and parameter set.
func rejectCollidingKeys(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var stack keyStack
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stack.next(tok); err != nil {
			return err
		}
	}
}

// keyFrame is one open JSON container in rejectCollidingKeys: an object's
// keys (folded key -> the spelling seen), or nil keys for an array.
type keyFrame struct {
	keys    map[string]string
	wantKey bool
}

// keyStack is the open containers, innermost last.
type keyStack []*keyFrame

// next consumes one decoder token, refusing an object key equal up to case
// to a key that object already has.
func (s *keyStack) next(tok json.Token) error {
	var top *keyFrame
	if n := len(*s); n > 0 {
		top = (*s)[n-1]
	}
	if top != nil && top.keys != nil && top.wantKey {
		if tok == json.Delim('}') {
			*s = (*s)[:len(*s)-1]
			return nil
		}
		return top.addKey(tok)
	}
	if top != nil && top.keys != nil {
		top.wantKey = true
	}
	switch tok {
	case json.Delim('{'):
		*s = append(*s, &keyFrame{keys: map[string]string{}, wantKey: true})
	case json.Delim('['):
		*s = append(*s, &keyFrame{})
	case json.Delim(']'):
		*s = (*s)[:len(*s)-1]
	}
	return nil
}

// addKey records an object key, refusing one equal up to case to a key the
// object already has.
func (f *keyFrame) addKey(tok json.Token) error {
	key, _ := tok.(string)
	folded := strings.ToLower(strings.ToUpper(key))
	if prev, seen := f.keys[folded]; seen {
		return fmt.Errorf("object has both %q and %q; keys equal up to case are refused", prev, key)
	}
	f.keys[folded] = key
	f.wantKey = false
	return nil
}

// subjectKeys returns the "sha256:<hex>" key of each subject. With strict set,
// a subject without a well-formed sha256 digest is an error; otherwise it is
// skipped (it can link nothing).
func subjectKeys(subjects []intoto.Subject, strict bool) ([]string, error) {
	var keys []string
	for _, s := range subjects {
		d := strings.ToLower(s.Digest["sha256"])
		if !sha256Hex.MatchString(d) {
			if strict {
				return nil, fmt.Errorf("subject %q has no well-formed sha256 digest", s.Name)
			}
			continue
		}
		if k := "sha256:" + d; !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// StatementFromPayload reads a SLSA v1 provenance statement: builder.id from
// runDetails.builder.id, repository and run from runDetails.metadata.
// invocationId, and the commit from the one git commit digest among
// buildDefinition.resolvedDependencies. Anything ambiguous is an error.
func StatementFromPayload(payload []byte) (Statement, error) {
	st, err := decodeStatement(payload)
	if err != nil {
		return Statement{}, err
	}
	if st.PredicateType != ProvenancePredicateType {
		return Statement{}, fmt.Errorf("predicate type %q is not %q", st.PredicateType, ProvenancePredicateType)
	}
	var pred struct {
		BuildDefinition struct {
			BuildType            string          `json:"buildType"`
			ExternalParameters   json.RawMessage `json:"externalParameters"`
			ResolvedDependencies []struct {
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				InvocationID string `json:"invocationId"`
			} `json:"metadata"`
		} `json:"runDetails"`
	}
	if err := json.Unmarshal(st.Predicate, &pred); err != nil {
		return Statement{}, fmt.Errorf("decode provenance predicate: %w", err)
	}
	path, ref, err := splitGitHubRef(pred.RunDetails.Builder.ID)
	if err != nil {
		return Statement{}, fmt.Errorf("builder.id: %w", err)
	}
	run, err := parseRunURI(pred.RunDetails.Metadata.InvocationID)
	if err != nil {
		return Statement{}, fmt.Errorf("invocationId: %w", err)
	}
	var commits []string
	for _, dep := range pred.BuildDefinition.ResolvedDependencies {
		for _, alg := range []string{"gitCommit", "sha1"} {
			if c := dep.Digest[alg]; c != "" && !slices.Contains(commits, c) {
				commits = append(commits, c)
			}
		}
	}
	if len(commits) != 1 {
		return Statement{}, fmt.Errorf("provenance names %d source commits, want exactly 1", len(commits))
	}
	subjects, err := subjectKeys(st.Subject, true)
	if err != nil {
		return Statement{}, err
	}
	return Statement{
		BuilderPath: path, BuilderRef: ref, Repo: run.repo, Commit: commits[0], RunID: run.id, Subjects: subjects,
		BuilderID: pred.RunDetails.Builder.ID, BuildType: pred.BuildDefinition.BuildType, ExternalParameters: pred.BuildDefinition.ExternalParameters,
	}, nil
}
