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

import (
	"context"
	"fmt"
	"sort"
)

// productBindingsPageSize is the page size for ListProductBindings. It is a
// page size, not a cap: the listing follows pageInfo to exhaustion.
const productBindingsPageSize = 50

// GraphQL variable names shared by several queries in this package.
const (
	gqlVarFirst     = "first"
	gqlVarProductID = "productID"
)

const productBindingsPageQuery = `query CilockProductBindings($productID: ID!, $first: Int!, $after: Cursor) {
  policyBindings(first: $first, after: $after, where: {hasProductWith: [{id: $productID}]}) {
    pageInfo { hasNextPage endCursor }
    edges { node {
      id
      createdAt
      createdBy { name email }
      policyDefinition { id name }
      policyRelease { id tag dsse { gitoidSha256 } }
    } }
  }
}`

// ListProductBindings returns EVERY policy binding of a product, for the
// platform verify door, which evaluates each one and passes only when all do.
//
// Exactness is the contract. The listing follows the connection's pageInfo to
// exhaustion, because a binding dropped by a page cap is a policy silently
// dropped from the gate. A server that reports another page without advancing
// its cursor is an error rather than a truncated list.
//
// The door addresses a binding by id and resolves its release server side, so
// no release lookup happens here: a pinned binding carries its tag and policy
// gitoid, and an unpinned one carries neither rather than a client-side guess
// about which release the server will pick.
//
// The result is sorted by (definition name, release tag, binding id) so the
// per-binding report reads the same on every run. No bindings is an empty
// slice and a nil error: the caller owns that message.
func (c *PolicyClient) ListProductBindings(ctx context.Context, productID string) ([]BoundPolicy, error) {
	var (
		out   []BoundPolicy
		seen  = map[string]bool{}
		after string
	)
	for {
		page, err := c.productBindingsPage(ctx, productID, after)
		if err != nil {
			return nil, err
		}
		for _, e := range page.Edges {
			n := e.Node
			if n.ID == "" {
				return nil, fmt.Errorf("list policy bindings for product %s: the platform returned a binding with no id", productID)
			}
			if !seen[n.ID] {
				seen[n.ID] = true
				out = append(out, n.boundPolicyUnresolved())
			}
		}
		pi := page.PageInfo
		if !pi.HasNextPage {
			break
		}
		if pi.EndCursor == "" || pi.EndCursor == after {
			return nil, fmt.Errorf("list policy bindings for product %s: the platform reported another page but did not advance its cursor (%q); refusing a partial list, which would drop policies from the gate", productID, pi.EndCursor)
		}
		after = pi.EndCursor
	}
	SortBoundPolicies(out)
	return out, nil
}

// productBindingsConnection is one page of the policyBindings connection.
type productBindingsConnection struct {
	PageInfo struct {
		HasNextPage bool   `json:"hasNextPage"`
		EndCursor   string `json:"endCursor"`
	} `json:"pageInfo"`
	Edges []struct {
		Node boundPolicyNode `json:"node"`
	} `json:"edges"`
}

func (c *PolicyClient) productBindingsPage(ctx context.Context, productID, after string) (*productBindingsConnection, error) {
	vars := map[string]any{gqlVarProductID: productID, gqlVarFirst: productBindingsPageSize}
	if after != "" {
		vars["after"] = after
	}
	var page struct {
		PolicyBindings productBindingsConnection `json:"policyBindings"`
	}
	if err := c.post(ctx, productBindingsPageQuery, vars, &page); err != nil {
		return nil, fmt.Errorf("list policy bindings for product %s: %w", productID, err)
	}
	return &page.PolicyBindings, nil
}

// boundPolicyUnresolved maps a binding node to a BoundPolicy without any
// release lookup: the pinned release's tag and gitoid when pinned, else
// neither (the platform resolves an unpinned binding).
func (n *boundPolicyNode) boundPolicyUnresolved() BoundPolicy {
	bp := BoundPolicy{BindingID: n.ID, BoundBy: n.binder(), BoundAt: n.CreatedAt}
	if n.PolicyDefinition != nil {
		bp.DefinitionName = n.PolicyDefinition.Name
	}
	if n.PolicyRelease != nil {
		bp.ReleaseTag = n.PolicyRelease.Tag
		if n.PolicyRelease.Dsse != nil {
			bp.Gitoid = n.PolicyRelease.Dsse.GitoidSha256
		}
	}
	return bp
}

// SortBoundPolicies orders bindings by (definition name, release tag, binding
// id): stable across runs and independent of server or scheduling order.
func SortBoundPolicies(bs []BoundPolicy) {
	sort.SliceStable(bs, func(i, j int) bool {
		a, b := bs[i], bs[j]
		if a.DefinitionName != b.DefinitionName {
			return a.DefinitionName < b.DefinitionName
		}
		if a.ReleaseTag != b.ReleaseTag {
			return a.ReleaseTag < b.ReleaseTag
		}
		return a.BindingID < b.BindingID
	})
}
