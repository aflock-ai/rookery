// jade:ring local

package auth

import "testing"

// TestOpenURLStartsAnOpenerOnWindows is the native half of #11530. The opener
// used to fall through to macOS's `open`, which no Windows machine has, so
// cmd.Start failed and every ceremony reported "nothing opened a browser" to a
// human sitting in front of one. A pure-function test of the switch can be
// fooled by a case that names a binary Windows does not ship; this one asks the
// real OS to start the real process, which is the claim the login output makes.
//
// Port 9 (discard) on loopback: if a browser does come up on the runner it
// fetches nothing and reaches nothing off the machine.
func TestOpenURLStartsAnOpenerOnWindows(t *testing.T) {
	t.Setenv("BROWSER", "")
	if !OpenURL("http://127.0.0.1:9/") {
		t.Fatal("OpenURL reported that no opener started on Windows; the opener has no windows case (#11530)")
	}
}
