package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The approval the human granted decides which tenant the release lands in,
// so it must be the tenant the document was hydrated for — and an approval
// that does not say which tenant it is for is not trusted to be the right one.
func TestPolicyPublish_ApprovalMustBeForTheHydratedTenant(t *testing.T) {
	require.NoError(t, approvalIsForHydration("tenant-a", "tenant-a"))
	err := approvalIsForHydration("tenant-b", "tenant-a")
	require.Error(t, err)
	require.Contains(t, err.Error(), "tenant-b")
	require.Contains(t, err.Error(), "tenant-a")
	require.Error(t, approvalIsForHydration("", "tenant-a"), "an approval that names no tenant is refused")
	require.Error(t, approvalIsForHydration("tenant-a", ""), "a hydration that names no tenant is refused")
}

// The signer the command reports is the one the PLATFORM reported, never the
// session's own email: the human who approved need not be whoever ran cilock.
func TestPolicyPublish_ReportsThePlatformsSignerNotTheSession(t *testing.T) {
	require.Equal(t, "reviewer@acme-corp.com at aal2", publishSignedLine(&policyPublishResult{SignerEmail: "reviewer@acme-corp.com", ACR: "aal2"}))
	require.Equal(t, "at aal2", publishSignedLine(&policyPublishResult{ACR: "aal2"}), "a platform that did not name the signer gets the level alone")
}
