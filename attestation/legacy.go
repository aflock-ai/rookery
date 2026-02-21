package attestation

// legacyAliases maps legacy predicate type URIs (witness.dev, witness.testifysec.com)
// to their current aflock.ai equivalents. This ensures old attestation JSON stored
// in Archivista can still be deserialized by rookery.
//
// NOTE: This must be called AFTER all attestors have registered via their init() functions.
// It is called from RegisterLegacyAliases() which should be invoked at startup.
var legacyAliases = map[string]string{
	// Collection type
	"https://witness.testifysec.com/attestation-collection/v0.1": "https://aflock.ai/attestation-collection/v0.1",

	// Attestor predicate types (witness.dev → aflock.ai)
	"https://witness.dev/attestations/command-run/v0.1":      "https://aflock.ai/attestations/command-run/v0.1",
	"https://witness.dev/attestations/docker/v0.1":           "https://aflock.ai/attestations/docker/v0.1",
	"https://witness.dev/attestations/environment/v0.1":      "https://aflock.ai/attestations/environment/v0.1",
	"https://witness.dev/attestations/git/v0.1":              "https://aflock.ai/attestations/git/v0.1",
	"https://witness.dev/attestations/github/v0.1":           "https://aflock.ai/attestations/github/v0.1",
	"https://witness.dev/attestations/githubwebhook/v0.1":    "https://aflock.ai/attestations/githubwebhook/v0.1",
	"https://witness.dev/attestations/gitlab/v0.1":           "https://aflock.ai/attestations/gitlab/v0.1",
	"https://witness.dev/attestations/gcp-iit/v0.1":          "https://aflock.ai/attestations/gcp-iit/v0.1",
	"https://witness.dev/attestations/aws/v0.1":              "https://aflock.ai/attestations/aws/v0.1",
	"https://witness.dev/attestations/aws-codebuild/v0.1":    "https://aflock.ai/attestations/aws-codebuild/v0.1",
	"https://witness.dev/attestations/jenkins/v0.1":          "https://aflock.ai/attestations/jenkins/v0.1",
	"https://witness.dev/attestations/jwt/v0.1":              "https://aflock.ai/attestations/jwt/v0.1",
	"https://witness.dev/attestations/k8smanifest/v0.2":      "https://aflock.ai/attestations/k8smanifest/v0.2",
	"https://witness.dev/attestations/lockfiles/v0.1":        "https://aflock.ai/attestations/lockfiles/v0.1",
	"https://witness.dev/attestations/material/v0.1":         "https://aflock.ai/attestations/material/v0.1",
	"https://witness.dev/attestations/maven/v0.1":            "https://aflock.ai/attestations/maven/v0.1",
	"https://witness.dev/attestations/oci/v0.1":              "https://aflock.ai/attestations/oci/v0.1",
	"https://witness.dev/attestations/omnitrail/v0.1":        "https://aflock.ai/attestations/omnitrail/v0.1",
	"https://witness.dev/attestations/product/v0.1":          "https://aflock.ai/attestations/product/v0.1",
	"https://witness.dev/attestations/sarif/v0.1":            "https://aflock.ai/attestations/sarif/v0.1",
	"https://witness.dev/attestations/sbom/v0.1":             "https://aflock.ai/attestations/sbom/v0.1",
	"https://witness.dev/attestations/secretscan/v0.1":       "https://aflock.ai/attestations/secretscan/v0.1",
	"https://witness.dev/attestations/system-packages/v0.1":  "https://aflock.ai/attestations/system-packages/v0.1",
}

// reverseLegacyAliases maps current aflock.ai URIs back to their witness.dev equivalents.
var reverseLegacyAliases map[string]string

func init() {
	reverseLegacyAliases = make(map[string]string, len(legacyAliases))
	for legacy, current := range legacyAliases {
		reverseLegacyAliases[current] = legacy
	}
}

// ResolveLegacyType returns the current URI for a legacy type, or the
// original type if no alias exists. This is a pure lookup — no registration needed.
func ResolveLegacyType(uri string) string {
	if current, ok := legacyAliases[uri]; ok {
		return current
	}
	return uri
}

// LegacyAlternate returns the "other" form of a type URI. For witness.dev URIs
// it returns the aflock.ai equivalent, and vice versa. Returns empty string if
// no alternate exists.
func LegacyAlternate(uri string) string {
	if current, ok := legacyAliases[uri]; ok {
		return current
	}
	if legacy, ok := reverseLegacyAliases[uri]; ok {
		return legacy
	}
	return ""
}

// RegisterLegacyAliases registers all known legacy predicate type URIs as aliases
// for their current equivalents. This must be called after all attestor plugins
// have been imported and registered via init().
func RegisterLegacyAliases() {
	for legacy, current := range legacyAliases {
		RegisterLegacyAlias(legacy, current)
	}
}
