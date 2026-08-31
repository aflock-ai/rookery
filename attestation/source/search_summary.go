package source

import (
	"fmt"
	"time"
)

// searchSummary renders the one-line telemetry record every evidence search
// emits, in key=value form so Loki can parse it without a schema.
//
// WHY THIS LINE EXISTS (bounded-verify.md, migration step 1). The cost model
// that sized the verify redesign had to be calibrated from three ad-hoc log
// lines and two ASSUMED parameters, and its core assumption — that search
// cost is linear in scope size — is untestable without scope_size and
// duration on the same line. This record makes every future sizing question a
// grep instead of a campaign:
//
//   - scope_size    how many subject digests anchored the search — the input
//     the BoundedScope invariant constrains, and the regression
//     variable for the linearity test;
//   - candidates    how many envelopes the sieve matched — the number that is
//     O(history) today and must become O(commit);
//   - verified_ok   how many passed signature verification — with candidates,
//     the waste ratio that filter-before-crypto would reclaim;
//   - duration_ms   wall time for the whole search including per-candidate
//     crypto — the cost side of the linearity regression.
//
// The line is also the drift alarm for the invariant itself: enforcement is
// type + structural check, deliberately with NO runtime rejection, so a
// regression in scope discipline shows up here as a growing scope_size before
// it shows up as a database incident.
func searchSummary(collectionName, mode string, scopeSize, candidates, verifiedOK int, started time.Time) string {
	return fmt.Sprintf(
		"[verified-source] search collection=%q mode=%s scope_size=%d candidates=%d verified_ok=%d duration_ms=%d",
		collectionName, mode, scopeSize, candidates, verifiedOK, time.Since(started).Milliseconds())
}

// verifiedOKCount counts results whose envelope passed signature verification
// — the definition is "no errors recorded", which matches how the policy gate
// distinguishes usable candidates from failed ones.
func verifiedOKCount(results []CollectionVerificationResult) int {
	n := 0
	for i := range results {
		if len(results[i].Errors) == 0 {
			n++
		}
	}
	return n
}
