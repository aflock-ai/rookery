// Copyright 2021 The Witness Contributors
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

package github

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "github"
	Type    = "https://aflock.ai/attestations/github/v0.1"
	RunType = attestation.PreMaterialRunType
)

const (
	tokenAudience = "witness"
	jwksURL       = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ GitHubAttestor         = &Attestor{}
)

type GitHubAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor

	// Subjecter
	Subjects() map[string]cryptoutil.DigestSet

	// Backreffer
	BackRefs() map[string]cryptoutil.DigestSet
}

// init registers the github attestor.
func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// ErrNotGitHub is an error type that indicates the environment is not a github ci job.
type ErrNotGitHub struct{}

// Error returns the error message for ErrNotGitHub.
func (e ErrNotGitHub) Error() string {
	return "not in a github ci job"
}

// Attestor is a struct that holds the necessary information for github attestation.
type Attestor struct {
	JWT          *jwt.Attestor `json:"jwt,omitempty"`
	CIConfigPath string        `json:"ciconfigpath"`
	PipelineID   string        `json:"pipelineid"`
	PipelineName string        `json:"pipelinename"`
	PipelineUrl  string        `json:"pipelineurl"`
	ProjectUrl   string        `json:"projecturl"`
	RunnerID     string        `json:"runnerid"`
	CIHost       string        `json:"cihost"`
	CIServerUrl  string        `json:"ciserverurl"`
	RunnerArch   string        `json:"runnerarch"`
	RunnerOS     string        `json:"runneros"`

	jwksURL  string
	tokenURL string
	aud      string
}

// New creates and returns a new github attestor.
func New() *Attestor {
	customJWKSURL := os.Getenv("WITNESS_GITHUB_JWKS_URL")
	if customJWKSURL == "" {
		customJWKSURL = jwksURL
	}
	return &Attestor{
		aud:      tokenAudience,
		jwksURL:  customJWKSURL,
		tokenURL: os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
	}
}

// Name returns the name of the attestor.
func (a *Attestor) Name() string {
	return Name
}

// Type returns the type of the attestor.
func (a *Attestor) Type() string {
	return Type
}

// RunType returns the run type of the attestor.
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	// DoNotReference inlines nested types instead of emitting shared $defs keyed
	// by bare type name. github.Attestor and the embedded jwt.Attestor are BOTH
	// named "Attestor", so the default reflector collapses them into one
	// "#/$defs/Attestor" and the `jwt` property wrongly inherits github's
	// required fields (ciconfigpath/pipelineid/...) — making a valid github
	// predicate fail its own schema. Inlining gives the jwt field its own schema.
	r := jsonschema.Reflector{DoNotReference: true}
	s := r.Reflect(a)
	// The embedded jwt.Attestor's VerifiedBy.JWK is a jose.JSONWebKey, a type
	// with a custom MarshalJSON that emits JWK JSON (kty/n/e/kid/...) rather than
	// the reflected Go struct shape. DoNotReference inlines it here as
	// jwt.verifiedBy.jwk, so reuse the jwt attestor's permissive-object patch
	// (same fix, one source of jose-marshalling knowledge) — otherwise a valid
	// github predicate fails its own Schema() on the jwk's bogus required fields.
	jwt.PermissiveJWK(s)
	return s
}

// Attest performs the attestation for the github environment.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	*a = Attestor{jwksURL: a.jwksURL, tokenURL: a.tokenURL, aud: a.aud}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return ErrNotGitHub{}
	}
	server := os.Getenv("GITHUB_SERVER_URL")
	u, err := parseServerURL(server)
	if err != nil {
		return err
	}
	repository := os.Getenv("GITHUB_REPOSITORY")
	if err := validateRepository(repository); err != nil {
		return err
	}
	runID := os.Getenv("GITHUB_RUN_ID")
	run, err := strconv.ParseUint(runID, 10, 64)
	if err != nil || run == 0 || strconv.FormatUint(run, 10) != runID {
		return fmt.Errorf("invalid GITHUB_RUN_ID")
	}

	jwtString, err := fetchToken(a.tokenURL, os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"), "witness")
	if err != nil {
		return fmt.Errorf("error on fetching token %w", err)
	}

	if jwtString == "" {
		return fmt.Errorf("empty JWT string")
	}

	a.JWT = jwt.New(jwt.WithToken(jwtString), jwt.WithJWKSUrl(a.jwksURL))
	if err := a.JWT.Attest(ctx); err != nil {
		return fmt.Errorf("failed to attest github jwt: %w", err)
	}
	if claim, ok := a.JWT.Claims["repository"].(string); !ok || claim != repository {
		return fmt.Errorf("github JWT repository claim does not match GITHUB_REPOSITORY")
	}
	if claim, ok := a.JWT.Claims["run_id"].(string); !ok || claim != runID {
		return fmt.Errorf("github JWT run_id claim does not match GITHUB_RUN_ID")
	}

	a.CIServerUrl = strings.TrimSuffix(server, "/")
	a.CIHost = u.Hostname()
	a.CIConfigPath = os.Getenv("GITHUB_ACTION_PATH")

	a.PipelineID = runID
	a.PipelineName = os.Getenv("GITHUB_WORKFLOW")

	a.ProjectUrl = fmt.Sprintf("%s/%s", a.CIServerUrl, repository)
	a.RunnerID = os.Getenv("RUNNER_NAME")
	a.RunnerArch = os.Getenv("RUNNER_ARCH")
	a.RunnerOS = os.Getenv("RUNNER_OS")
	a.PipelineUrl = fmt.Sprintf("%s/actions/runs/%s", a.ProjectUrl, a.PipelineID)
	return nil
}

func parseServerURL(server string) (*url.URL, error) {
	u, err := url.Parse(server)
	if err != nil || len(server) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("invalid GITHUB_SERVER_URL")
	}
	return u, nil
}

var repositoryPath = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func validateRepository(repository string) error {
	parts := strings.Split(repository, "/")
	if len(repository) > 256 || !repositoryPath.MatchString(repository) || len(parts) != 2 || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return fmt.Errorf("invalid GITHUB_REPOSITORY")
	}
	return nil
}

func (a *Attestor) Data() *Attestor {
	return a
}

// Subjects returns a map of subjects and their corresponding digest sets.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	if a.PipelineUrl != "" {
		if pipelineSubj, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.PipelineUrl), hashes); err == nil {
			subjects[fmt.Sprintf("pipelineurl:%v", a.PipelineUrl)] = pipelineSubj
		} else {
			log.Debugf("(attestation/github) failed to record github pipelineurl subject: %v", err)
		}
	}

	if a.ProjectUrl != "" {
		if projectSubj, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ProjectUrl), hashes); err == nil {
			subjects[fmt.Sprintf("projecturl:%v", a.ProjectUrl)] = projectSubj
		} else {
			log.Debugf("(attestation/github) failed to record github projecturl subject: %v", err)
		}
	}

	return subjects
}

// BackRefs returns a map of back references and their corresponding digest sets.
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	backRefs := make(map[string]cryptoutil.DigestSet)
	for subj, ds := range a.Subjects() {
		if strings.HasPrefix(subj, "pipelineurl:") {
			backRefs[subj] = ds
			break
		}
	}

	return backRefs
}

var tokenHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchToken fetches the token from the given URL.
func fetchToken(tokenURL string, bearer string, audience string) (string, error) {
	u, err := url.Parse(tokenURL)
	if err != nil {
		return "", fmt.Errorf("error on parsing token url %w", err)
	}
	if u.Scheme != "https" || !strings.HasSuffix(strings.ToLower(u.Hostname()), ".actions.githubusercontent.com") || u.User != nil || (u.Port() != "" && u.Port() != "443") || u.Fragment != "" {
		return "", fmt.Errorf("invalid GitHub Actions token endpoint")
	}

	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	reqURL := u.String()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("error on creating request %w", err)
	}
	req.Header.Add("Authorization", "bearer "+bearer)
	resp, err := tokenHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error on request %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	body, err := readResponseBody(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error on reading response body %w", err)
	}

	var tokenResponse GithubTokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("error on unmarshaling token response %w", err)
	}

	return tokenResponse.Value, nil
}

// GithubTokenResponse is a struct that holds the response from the github token request.
type GithubTokenResponse struct {
	Count int    `json:"count"`
	Value string `json:"value"`
}

// readResponseBody reads the response body and returns it as a byte slice.
// Limits read size to prevent OOM from a malicious or compromised server.
const maxResponseBodySize = 1 << 20 // 1MB

func readResponseBody(body io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(io.LimitReader(body, maxResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if buf.Len() > maxResponseBodySize {
		return nil, fmt.Errorf("token response exceeds %d bytes", maxResponseBodySize)
	}
	return buf.Bytes(), nil
}
