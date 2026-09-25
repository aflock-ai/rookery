// jade:ring local
// Copyright 2026 The Rookery Contributors
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

//go:build linux

package commandrun

import (
	"errors"
	"strings"
	"testing"
)

func forceFanotifyUnavailable(t *testing.T) {
	t.Helper()
	prev := fanotifyProbe
	fanotifyProbe = func(string) error {
		return errors.New("FanotifyInit: operation not permitted (CAP_SYS_ADMIN required)")
	}
	t.Cleanup(func() { fanotifyProbe = prev })
}

// --hardening standard seeds CILOCK_FANOTIFY=auto: an unprivileged host must
// get a stated "unavailable" outcome carrying the kernel's reason, not an
// error that fails the attestor.
func TestMaybeStartFanotify_AutoDegradesWithAReason(t *testing.T) {
	forceFanotifyUnavailable(t)
	for _, mode := range []string{"", "auto"} {
		t.Setenv(EnvVarFanotify, mode)
		s, out, err := maybeStartFanotify(t.TempDir(), nil)
		if err != nil || s != nil {
			t.Fatalf("mode %q: session=%v err=%v; want degrade, not fail", mode, s, err)
		}
		if out.State != fanotifyUnavailable || !strings.Contains(out.Reason, "operation not permitted") {
			t.Fatalf("mode %q: outcome %+v; want unavailable with the kernel reason", mode, out)
		}
	}
}

// --hardening strict seeds CILOCK_FANOTIFY=1: unavailable is still a refusal.
func TestMaybeStartFanotify_RequiredStillRefuses(t *testing.T) {
	forceFanotifyUnavailable(t)
	for _, mode := range []string{"1", "on"} {
		t.Setenv(EnvVarFanotify, mode)
		_, _, err := maybeStartFanotify(t.TempDir(), nil)
		var fe *fanotifyUnavailableError
		if !errors.As(err, &fe) {
			t.Fatalf("mode %q: err = %v; want fanotifyUnavailableError", mode, err)
		}
	}
}

func TestMaybeStartFanotify_DisabledIsStated(t *testing.T) {
	for _, mode := range []string{"off", "0", "bogus"} {
		t.Setenv(EnvVarFanotify, mode)
		s, out, err := maybeStartFanotify(t.TempDir(), nil)
		if err != nil || s != nil || out.State != fanotifyDisabled || out.Reason == "" {
			t.Fatalf("mode %q: session=%v outcome=%+v err=%v; want disabled with a reason", mode, s, out, err)
		}
	}
}
