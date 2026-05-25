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

package detection

// Stable codes emitted by the detection subsystem itself (as opposed to
// per-plugin warning codes declared in detector.yaml). These codes are
// part of the API contract for LLM consumers and CI integrations: once
// shipped, they may not be renamed.
//
// Per-plugin warning codes (e.g. DOCKER_NO_PROVENANCE) live in the
// individual detector.yaml files. Plugin authors own them.
const (
	// CodeNoAttestorsFired is emitted when a run produced no attestor
	// invocations at all — usually a configuration bug or empty workspace.
	CodeNoAttestorsFired = "CILOCK_NO_ATTESTORS_FIRED"

	// CodeBinaryUnknownDigest is emitted when an attestor matched on a
	// binary whose digest is not in any known-good allowlist. Advisory.
	CodeBinaryUnknownDigest = "CILOCK_BINARY_UNKNOWN_DIGEST"

	// CodeUndetectedToolInvocation is emitted post-hoc (M5) when the exec
	// trace shows a tool ran inside the step but no top-level detector
	// matched it. Suggests invoking cilock at the tool's layer or adding
	// the attester explicitly.
	CodeUndetectedToolInvocation = "CILOCK_UNDETECTED_TOOL_INVOCATION"

	// CodeDetectionDrift is emitted in shadow mode (M1b) when auto-detected
	// attestor set diverges from the user's explicit -a list. Telemetry
	// signal; not a fix-needed warning.
	CodeDetectionDrift = "CILOCK_DETECTION_DRIFT"

	// CodeMutationConflict is reserved for a future mutation feature
	// (currently NOT implemented — cilock never mutates user commands).
	// Reserved so the code namespace stays stable if it ever ships.
	CodeMutationConflict = "CILOCK_MUTATION_CONFLICT"

	// CodeProbeTimeout is emitted when a named probe (imds_reachable,
	// socket_listening) exceeded its time budget. The predicate is
	// treated as false.
	CodeProbeTimeout = "CILOCK_PROBE_TIMEOUT"

	// CodeSchemaUnsupported is emitted when a detector.yaml declares an
	// apiVersion the current binary does not understand. The detector is
	// skipped; the run continues without it.
	CodeSchemaUnsupported = "CILOCK_SCHEMA_UNSUPPORTED"
)

// IsCoreCode reports whether the given code is one of the cilock-emitted
// codes defined above (as opposed to a plugin-defined warning code).
func IsCoreCode(code string) bool {
	switch code {
	case CodeNoAttestorsFired,
		CodeBinaryUnknownDigest,
		CodeUndetectedToolInvocation,
		CodeDetectionDrift,
		CodeMutationConflict,
		CodeProbeTimeout,
		CodeSchemaUnsupported:
		return true
	}
	return false
}
