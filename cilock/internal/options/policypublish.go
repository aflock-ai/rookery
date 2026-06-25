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

package options

// Package note — the platform policy-publish client.
//
// This is cilock's minimal GraphQL client for the TestifySec platform's policy
// surface. It exists for `cilock policy push` and `cilock policy bind`. It is
// deliberately a hand-rolled raw-POST client (the same shape as
// CreateOIDCCredential in trust.go) rather than a generated GraphQL stack — the
// public rookery module must not pull in a heavyweight gqlgen/codegen dependency
// for two mutations and a handful of lookups.
//
// Auth model: every call carries the stored session Bearer (Authorization:
// Bearer <token>). The server enforces scope:
//   - the DSSE upload to Archivista needs attestation:upload (the credential has it);
//   - createPolicyRelease / createPolicyBinding need policy:write;
//   - createPolicyDefinition is being extended to policy:write too.
// The client never enforces scope locally — it surfaces a clear, actionable
// error when the server rejects a call for a missing scope (see classifyGQLErr).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// PolicyClient is the minimal platform GraphQL client for policy publishing. It
// is constructed with a fully-resolved GraphQL endpoint URL (the caller resolves
// discovery → ${platform}/query) and the session bearer token.
type PolicyClient struct {
	GraphQLURL string
	Token      string
	// HTTPClient is the transport; nil uses a default 30s-timeout client.
	HTTPClient *http.Client
}

// gqlError mirrors a single GraphQL error entry.
type gqlError struct {
	Message string `json:"message"`
}

// post sends a raw GraphQL POST (query + variables), authenticated with the
// session bearer, and unmarshals the `data` field into out. A non-200 status or
// a non-empty `errors` array is turned into an error; scope/permission denials
// are rewritten by classifyGQLErr into an actionable remedy.
func (c *PolicyClient) post(ctx context.Context, query string, variables map[string]any, out any) error {
	if c.GraphQLURL == "" {
		return fmt.Errorf("no platform GraphQL endpoint resolved")
	}
	if c.Token == "" {
		return fmt.Errorf("no session token — run `cilock login` first")
	}
	// Refuse to attach the session bearer over cleartext to a non-loopback host
	// (#5997).
	if err := config.RequireSecurePlatformURL(c.GraphQLURL); err != nil {
		return err
	}

	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.GraphQLURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("platform request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) //nolint:errcheck // diagnostic
	if resp.StatusCode != http.StatusOK {
		return classifyGQLErr(resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []gqlError      `json:"errors"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		msgs := make([]string, 0, len(envelope.Errors))
		for _, e := range envelope.Errors {
			msgs = append(msgs, e.Message)
		}
		return classifyGQLErr(http.StatusOK, strings.Join(msgs, "; "))
	}
	if out != nil && len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("decode data: %w", err)
		}
	}
	return nil
}

// classifyGQLErr turns a transport/GraphQL error into a user-actionable one. A
// scope/permission denial is the common, recoverable case: the session predates
// the policy:write grant, so the remedy is to re-authenticate. Everything else
// is passed through with its status for diagnosis.
func classifyGQLErr(status int, msg string) error {
	lower := strings.ToLower(msg)
	if status == http.StatusUnauthorized || status == http.StatusForbidden ||
		strings.Contains(lower, "missing required scope") ||
		strings.Contains(lower, "policy:write") ||
		strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "not authorized") {
		return fmt.Errorf("platform denied this operation (likely missing the %q scope): %s\n"+
			"Re-authenticate to pick up policy:write, then retry:\n\n"+
			"  cilock login", "policy:write", msg)
	}
	if status != http.StatusOK {
		return fmt.Errorf("platform returned %d: %s", status, msg)
	}
	return fmt.Errorf("platform rejected request: %s", msg)
}

// --- queries: resolve-by-name / resolve-by-gitoid ---

const dsseByGitoidQuery = `query CilockDsseByGitoid($gitoid: String!) {
  dsses(first: 1, where: {gitoidSha256: $gitoid}) {
    edges { node { id gitoidSha256 } }
  }
}`

// ResolveDsseIDByGitoid finds the platform Dsse record id (a UUID) for an
// uploaded envelope's gitoid. The gitoid that the Archivista upload returns is
// NOT the Dsse edge id — createPolicyRelease.dsseID wants the ent record id, so
// the gitoid must be resolved to it here. Returns "" (no error) when no Dsse
// matches yet, so the caller can surface a clear message.
func (c *PolicyClient) ResolveDsseIDByGitoid(ctx context.Context, gitoid string) (string, error) {
	var out struct {
		Dsses struct {
			Edges []struct {
				Node struct {
					ID           string `json:"id"`
					GitoidSha256 string `json:"gitoidSha256"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"dsses"`
	}
	if err := c.post(ctx, dsseByGitoidQuery, map[string]any{"gitoid": gitoid}, &out); err != nil {
		return "", fmt.Errorf("resolve dsse by gitoid: %w", err)
	}
	if len(out.Dsses.Edges) == 0 {
		return "", nil
	}
	return out.Dsses.Edges[0].Node.ID, nil
}

const policyDefinitionByNameQuery = `query CilockPolicyDefByName($name: String!) {
  policyDefinitions(first: 1, where: {name: $name}) {
    edges { node { id name } }
  }
}`

// PolicyDefinitionRef is the slice of a PolicyDefinition the publish flow needs.
type PolicyDefinitionRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResolvePolicyDefinitionByName returns the definition with the exact name, or
// nil (no error) when none exists — the create-if-missing seam for `push`.
func (c *PolicyClient) ResolvePolicyDefinitionByName(ctx context.Context, name string) (*PolicyDefinitionRef, error) {
	var out struct {
		PolicyDefinitions struct {
			Edges []struct {
				Node PolicyDefinitionRef `json:"node"`
			} `json:"edges"`
		} `json:"policyDefinitions"`
	}
	if err := c.post(ctx, policyDefinitionByNameQuery, map[string]any{"name": name}, &out); err != nil {
		return nil, fmt.Errorf("resolve policy definition %q: %w", name, err)
	}
	if len(out.PolicyDefinitions.Edges) == 0 {
		return nil, nil
	}
	node := out.PolicyDefinitions.Edges[0].Node
	return &node, nil
}

const productByNameQuery = `query CilockProductByName($name: String!) {
  products(first: 2, where: {name: $name}) {
    edges { node { id name } }
  }
}`

const productByIDQuery = `query CilockProductByID($id: ID!) {
  products(first: 1, where: {id: $id}) {
    edges { node { id name } }
  }
}`

// ProductRef is the slice of a Product the bind flow needs.
type ProductRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResolveProduct resolves a product by id first (when the argument is a valid
// platform id) and falls back to an exact-name lookup. An ambiguous name (more
// than one match) is an error — binding the wrong product is worse than asking
// the user to pass the id.
func (c *PolicyClient) ResolveProduct(ctx context.Context, idOrName string) (*ProductRef, error) {
	// Try id first — a productByID lookup is exact and cheap. A malformed id
	// surfaces as a platform error, which we treat as a miss and retry by name.
	if ref, err := c.productByID(ctx, idOrName); err == nil && ref != nil {
		return ref, nil
	}
	var out struct {
		Products struct {
			Edges []struct {
				Node ProductRef `json:"node"`
			} `json:"edges"`
		} `json:"products"`
	}
	if err := c.post(ctx, productByNameQuery, map[string]any{"name": idOrName}, &out); err != nil {
		return nil, fmt.Errorf("resolve product %q: %w", idOrName, err)
	}
	switch len(out.Products.Edges) {
	case 0:
		return nil, fmt.Errorf("no product found matching %q (pass the product id or exact name)", idOrName)
	case 1:
		node := out.Products.Edges[0].Node
		return &node, nil
	default:
		return nil, fmt.Errorf("multiple products match name %q — pass the product id to disambiguate", idOrName)
	}
}

// productByID resolves a product by id, or nil (no error) on a miss.
func (c *PolicyClient) productByID(ctx context.Context, id string) (*ProductRef, error) {
	var out struct {
		Products struct {
			Edges []struct {
				Node ProductRef `json:"node"`
			} `json:"edges"`
		} `json:"products"`
	}
	if err := c.post(ctx, productByIDQuery, map[string]any{"id": id}, &out); err != nil {
		return nil, err
	}
	if len(out.Products.Edges) == 0 {
		return nil, nil
	}
	node := out.Products.Edges[0].Node
	return &node, nil
}

const policyReleaseByTagQuery = `query CilockReleaseByTag($defID: ID!, $tag: String!) {
  policyReleases(first: 1, where: {tag: $tag, hasPolicyDefinitionWith: [{id: $defID}]}) {
    edges { node { id tag } }
  }
}`

// PolicyReleaseRef is the slice of a PolicyRelease the bind flow needs.
type PolicyReleaseRef struct {
	ID  string `json:"id"`
	Tag string `json:"tag"`
}

// ResolveReleaseByTag returns the release under definitionID with the given tag,
// or nil (no error) when none exists.
func (c *PolicyClient) ResolveReleaseByTag(ctx context.Context, definitionID, tag string) (*PolicyReleaseRef, error) {
	var out struct {
		PolicyReleases struct {
			Edges []struct {
				Node PolicyReleaseRef `json:"node"`
			} `json:"edges"`
		} `json:"policyReleases"`
	}
	if err := c.post(ctx, policyReleaseByTagQuery, map[string]any{"defID": definitionID, "tag": tag}, &out); err != nil {
		return nil, fmt.Errorf("resolve release tag %q: %w", tag, err)
	}
	if len(out.PolicyReleases.Edges) == 0 {
		return nil, nil
	}
	node := out.PolicyReleases.Edges[0].Node
	return &node, nil
}

// --- mutations ---

const createPolicyDefinitionMutation = `mutation CilockCreatePolicyDef($input: CreatePolicyDefinitionInput!) {
  createPolicyDefinition(input: $input) { id name }
}`

// CreatePolicyDefinition creates a PolicyDefinition and returns its id. tenantID
// is required by the schema; name+description are required. isActive defaults to
// true so a freshly published policy is usable without a follow-up update.
func (c *PolicyClient) CreatePolicyDefinition(ctx context.Context, tenantID, name, description string) (*PolicyDefinitionRef, error) {
	if description == "" {
		description = "Published via cilock policy push"
	}
	input := map[string]any{
		"tenantID":    tenantID,
		"name":        name,
		"description": description,
		"isActive":    true,
	}
	var out struct {
		CreatePolicyDefinition PolicyDefinitionRef `json:"createPolicyDefinition"`
	}
	if err := c.post(ctx, createPolicyDefinitionMutation, map[string]any{"input": input}, &out); err != nil {
		return nil, fmt.Errorf("create policy definition %q: %w", name, err)
	}
	if out.CreatePolicyDefinition.ID == "" {
		return nil, fmt.Errorf("platform returned no policy definition id")
	}
	return &PolicyDefinitionRef{ID: out.CreatePolicyDefinition.ID, Name: out.CreatePolicyDefinition.Name}, nil
}

const createPolicyReleaseMutation = `mutation CilockCreatePolicyRelease($input: CreatePolicyReleaseInput!) {
  createPolicyRelease(input: $input) { id tag }
}`

// CreatePolicyRelease creates a PolicyRelease pinning a definition to a DSSE
// (the uploaded signed policy, resolved to its Dsse edge id) under a tag.
// tenantID and tag are required by the schema; policyDefinitionID + dsseID are
// the edges that make the release point at the published policy.
func (c *PolicyClient) CreatePolicyRelease(ctx context.Context, tenantID, definitionID, dsseID, tag string) (*PolicyReleaseRef, error) {
	input := map[string]any{
		"tenantID":           tenantID,
		"tag":                tag,
		"policyDefinitionID": definitionID,
		"dsseID":             dsseID,
	}
	var out struct {
		CreatePolicyRelease PolicyReleaseRef `json:"createPolicyRelease"`
	}
	if err := c.post(ctx, createPolicyReleaseMutation, map[string]any{"input": input}, &out); err != nil {
		return nil, fmt.Errorf("create policy release %q: %w", tag, err)
	}
	if out.CreatePolicyRelease.ID == "" {
		return nil, fmt.Errorf("platform returned no policy release id")
	}
	return &PolicyReleaseRef{ID: out.CreatePolicyRelease.ID, Tag: out.CreatePolicyRelease.Tag}, nil
}

const createPolicyBindingMutation = `mutation CilockCreatePolicyBinding($input: CreatePolicyBindingInput!) {
  createPolicyBinding(input: $input) {
    id
    policyDefinition { id name }
    policyRelease { id tag }
    product { id name }
  }
}`

// PolicyBindingResult is the slice of a created binding the bind flow reports.
type PolicyBindingResult struct {
	ID               string               `json:"id"`
	PolicyDefinition *PolicyDefinitionRef `json:"policyDefinition"`
	PolicyRelease    *PolicyReleaseRef    `json:"policyRelease"`
	Product          *ProductRef          `json:"product"`
}

// CreatePolicyBinding binds a definition (and optionally a specific release) to a
// product. tenantID is required by the schema; the edge ids select what is being
// bound. releaseID may be empty (bind the definition, latest release applies).
func (c *PolicyClient) CreatePolicyBinding(ctx context.Context, tenantID, definitionID, releaseID, productID string) (*PolicyBindingResult, error) {
	input := map[string]any{
		"tenantID":           tenantID,
		"policyDefinitionID": definitionID,
		"productID":          productID,
	}
	if releaseID != "" {
		input["policyReleaseID"] = releaseID
	}
	var out struct {
		CreatePolicyBinding PolicyBindingResult `json:"createPolicyBinding"`
	}
	if err := c.post(ctx, createPolicyBindingMutation, map[string]any{"input": input}, &out); err != nil {
		return nil, fmt.Errorf("create policy binding: %w", err)
	}
	if out.CreatePolicyBinding.ID == "" {
		return nil, fmt.Errorf("platform returned no policy binding id")
	}
	return &out.CreatePolicyBinding, nil
}
