// conventions.go — per-Steampipe-plugin column conventions.
//
// Steampipe's table schemas are stable per plugin. Every AWS table has an
// `account_id` column; every resource-shaped AWS table has an `arn` column.
// GitHub tables expose `name_with_owner` / `login`. Encoding this once here
// means recipe authors don't have to declare per-row identity selectors for
// the common cases — the attestor reads `Frontmatter.Plugin` and picks the
// right extractors.
//
// Subject digest convention matches prowler / aws-config / asff:
// SHA-256 of the identity string itself, not a snapshot of the row state.
// That's what makes cross-attestation graph traversal work — policyverify
// joins by digest value, so two attestors that hash the same identity
// string converge regardless of subject-key style.
//
// BackRef convention matches github / gitlab / jenkins: emit a subset of
// Subjects filtered to one canonical-handle prefix per plugin. For AWS,
// the canonical handle is the ARN; for GitHub repos, the owner/name slug.
// Recipes that need a different anchor can override via WithBackRefPrefix.
package steampipe

import (
	"strconv"
	"strings"
)

// columnExtractor maps a Steampipe column name to a subject prefix. For each
// row, if the column is present and non-empty, the attestor emits
// `<prefix><value>` with digest = sha256(value).
type columnExtractor struct {
	column string
	prefix string
}

// pluginConvention bundles the subject extractors for one Steampipe
// plugin. Lookup keyed by `Frontmatter.Plugin`.
//
// Note: there is intentionally no per-plugin BackRef prefix. BackRefs
// are attestation-level (one content-addressed `steampipe-run:<hex>`
// anchor per attestation, computed from the recipe id + sql + source
// digest in steampipe.go's recipeRunIdent), not per-resource — see the
// commentary on BackRefs() for why.
type pluginConvention struct {
	subjectExtractors []columnExtractor
}

// pluginConventions is the per-plugin convention table. Add new entries
// when adopting a new Steampipe plugin; the per-plugin docs at
// hub.steampipe.io list the canonical column shapes.
var pluginConventions = map[string]pluginConvention{
	"aws": {
		subjectExtractors: []columnExtractor{
			{column: "account_id", prefix: "aws:account:"},
			{column: "arn", prefix: "aws:arn:"},
			// Some AWS tables expose `region` as an addressable axis — useful for
			// "show me all evidence about us-east-1" pivots. Empty regions
			// (global services) are skipped by the non-empty guard in extract().
			{column: "region", prefix: "aws:region:"},
		},
	},
	"github": {
		subjectExtractors: []columnExtractor{
			// github_my_repository / github_repository
			{column: "name_with_owner", prefix: "github:repo:"},
			// github_my_organization / github_organization
			{column: "login", prefix: "github:org:"},
		},
	},
	"okta": {
		subjectExtractors: []columnExtractor{
			{column: "id", prefix: "okta:user:"},
			{column: "organization", prefix: "okta:org:"},
		},
	},
	"kubernetes": {
		subjectExtractors: []columnExtractor{
			{column: "uid", prefix: "k8s:uid:"},
			{column: "namespace", prefix: "k8s:namespace:"},
		},
	},
	// googledirectory is the turbot/googledirectory plugin — the Google
	// Workspace Admin SDK Directory (users, groups, domains, org units, roles).
	// This is the plugin a Workspace *security-posture* recipe targets (MFA
	// enrollment, super-admins, OU layout), so it's the one that overlaps with
	// the scubagoggles attestor. Every directory table carries `customer_id`,
	// the GWS customer/tenant id; the scubagoggles attestor hashes that same
	// value as its tenant subject, so a Steampipe googledirectory attestation
	// and a ScubaGoggles attestation converge on `customer_id`/`domain_name`
	// in policyverify's digest-value graph join. Columns verified against
	// github.com/turbot/steampipe-plugin-googledirectory.
	"googledirectory": {
		subjectExtractors: []columnExtractor{
			{column: "customer_id", prefix: "googleworkspace:customer:"},
			{column: "primary_email", prefix: "googleworkspace:user:"}, // googledirectory_user
			{column: "email", prefix: "googleworkspace:group:"},        // googledirectory_group
			{column: "domain_name", prefix: "googleworkspace:domain:"}, // googledirectory_domain
			{column: "org_unit_path", prefix: "googleworkspace:orgunit:"},
		},
	},
	// googleworkspace is the turbot/googleworkspace plugin — Workspace *content/
	// activity* (gmail settings, drive, calendar, people, audit activity), NOT
	// directory objects. Identity here is the per-user mailbox owner or the
	// actor on an audit event. Columns verified against
	// github.com/turbot/steampipe-plugin-googleworkspace.
	"googleworkspace": {
		subjectExtractors: []columnExtractor{
			{column: "customer_id", prefix: "googleworkspace:customer:"}, // googleworkspace_activity_report
			{column: "user_email", prefix: "googleworkspace:user:"},      // googleworkspace_gmail_settings
			{column: "actor_email", prefix: "googleworkspace:user:"},     // googleworkspace_activity_report
		},
	},
}

// extract pulls identity-bearing values out of one row according to the
// plugin's convention. Returns a slice of (subject-key, value-to-digest)
// pairs. Caller is responsible for `sha256(value)` and dedup via the
// subjects map.
func extract(plugin string, row map[string]any) []struct{ Key, Value string } {
	conv, ok := pluginConventions[plugin]
	if !ok {
		return nil
	}
	out := make([]struct{ Key, Value string }, 0, len(conv.subjectExtractors))
	for _, e := range conv.subjectExtractors {
		raw, ok := row[e.column]
		if !ok || raw == nil {
			continue
		}
		val := stringify(raw)
		if val == "" {
			continue
		}
		out = append(out, struct{ Key, Value string }{Key: e.prefix + val, Value: val})
	}
	return out
}

// stringify coerces a JSON-decoded value (string / number / bool) into a
// plain string suitable for use as an identity. Returns "" for unsupported
// shapes (arrays, objects) so the caller skips them.
func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		// JSON numbers always decode to float64. Render with no scientific
		// notation; trailing-zero trimming so integers look like integers.
		s := formatFloat(x)
		return s
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}

// formatFloat renders a float64 the way ECMAScript / JSON-canonical form
// does — no decimal point for whole numbers, shortest round-trip otherwise.
// AWS account ids and other numeric ids come back as float64 from
// encoding/json and need to round-trip as integer strings ("339150376714",
// not "3.39150376714e+11").
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
