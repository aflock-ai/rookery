// jade:ring local

package git

import "github.com/aflock-ai/rookery/attestation/gitremote"

// The remote grammar and its tests moved to attestation/gitremote (#9211).
// The contract sweep that drives it through the attestor stays here and reads
// the shared package through these names.
const (
	remoteRefused  = gitremote.Refused
	remoteClean    = gitremote.Clean
	remoteRedacted = gitremote.Redacted

	refusalAmbiguousAuthority     = gitremote.ReasonAmbiguousAuthority
	refusalOpaqueTransport        = gitremote.ReasonOpaqueTransport
	refusalPathBytesNotRedactable = gitremote.ReasonPathBytesNotRedactable
)

type remoteVerdict = gitremote.Verdict

func recordRemote(raw string) (remoteVerdict, string, string) { return gitremote.Record(raw) }
