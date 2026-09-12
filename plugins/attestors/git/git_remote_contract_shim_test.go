// jade:ring local

package git

// redactRemoteURL is the TWO-VALUED VIEW of recordRemote, and it lives in a
// test file because production no longer has a two-valued contract.
//
// The suites written before #9177's contract change — six sweep files, some
// two thousand lines — assert the property "this string does not reach signed
// evidence" and "this string reaches it unchanged". Neither claim needs the
// clean/redacted distinction, so every one of those assertions is still exactly
// as true and as load-bearing under the three-valued contract as it was under
// the two-valued one. Rewriting them all to the new signature would have been a
// two-thousand-line diff that changed no assertion, which is a worse thing to
// put in front of a reviewer than this adapter.
//
// It is deliberately NOT in git.go. A two-valued entry point in production
// would be a second contract, and the next edit would be made against whichever
// of the two the author happened to open — which is the drift that this whole
// change exists to stop. Attest calls recordRemote and nothing else.
//
// It collapses remoteClean and remoteRedacted into `true` and remoteRefused
// into `false`, which is precisely the information the old contract carried.
func redactRemoteURL(raw string) (string, bool) {
	verdict, recorded, _ := recordRemote(raw)
	return recorded, verdict.recordable()
}
