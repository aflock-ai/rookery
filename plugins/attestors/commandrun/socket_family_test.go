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

// Coverage gate for the socket-family vocabulary.
//
// NO BUILD TAG, deliberately, and the scan below reads the package's sources as
// TEXT through go/parser rather than through the compiler.
//
// A family constant belongs to the wire contract wherever it is declared,
// including in a file the building GOOS excludes. Every CI runner here is
// Linux, so a gate that only saw the compiled files would let a platform-tagged
// backend put a family on the wire that no consumer classifies — and an
// unclassified IP family is dropped by cilock's egress filter, which makes
// `Hermetic = len(NetworkEgress) == 0` sign "reached nothing" over a build that
// reached the network. Reading the directory works on every GOOS, so the whole
// vocabulary is gated on the runners that actually execute the suite.

package commandrun

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// socketFamilyLiteralRe matches a string constant that names a socket family.
// Any constant in this package whose value looks like this is part of the wire
// vocabulary a consumer will read off a signed predicate.
var socketFamilyLiteralRe = regexp.MustCompile(`^AF_[A-Z0-9_]+$`)

// declaredSocketFamilies parses every non-test source file in this package —
// including the ones this GOOS excludes from the build — and returns the family
// literal declared by each constant, keyed by constant name.
func declaredSocketFamilies(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}
	fset := token.NewFileSet()
	found := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// ParseFile ignores build constraints, which is the whole point: a
		// platform-tagged source must be read on a runner that excludes it.
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, val := range vs.Values {
					lit, ok := val.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil || !socketFamilyLiteralRe.MatchString(s) {
						continue
					}
					found[vs.Names[i].Name] = s
				}
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("found no socket-family constants at all, so this gate is not reading the sources it is supposed to gate")
	}
	return found
}

// TestEverySocketFamilyConstantIsClassified is the gate that makes the family
// vocabulary closed.
//
// A family constant that no consumer classifies does not fail loudly: cilock's
// egress filter drops the connection, externalEgress returns an empty list, and
// `Hermetic = len(NetworkEgress) == 0` signs "this build reached nothing" over a
// build that reached the network. Nothing crashes and no test that only knows
// the older families goes red — which is exactly why the gate has to be a scan
// of the declarations rather than a hand-maintained list of cases.
func TestEverySocketFamilyConstantIsClassified(t *testing.T) {
	declared := declaredSocketFamilies(t)
	for constName, family := range declared {
		if _, ok := socketFamilyClasses[family]; !ok {
			t.Errorf("socket family %s = %q is declared but absent from socketFamilyClasses. "+
				"Every family this attestor can put on the wire must be classified in that one table, "+
				"because a consumer that does not recognise an IP family silently publishes an empty "+
				"egress list for a build that reached the network. Add it there.", constName, family)
		}
	}
}

// TestSocketFamilyTableHasNoDeadEntries keeps the table honest in the other
// direction: an entry for a family no constant declares is a rule nothing can
// reach, and it makes the coverage gate above look stronger than it is.
func TestSocketFamilyTableHasNoDeadEntries(t *testing.T) {
	declared := declaredSocketFamilies(t)
	byValue := map[string]string{}
	for constName, family := range declared {
		byValue[family] = constName
	}
	for family := range socketFamilyClasses {
		if _, ok := byValue[family]; !ok {
			t.Errorf("socketFamilyClasses classifies %q, which no constant in this package declares", family)
		}
	}
}

// TestFamilyInetUnspecifiedIsIP pins the reading that any observation channel
// narrower than the syscall depends on: an IP socket whose version the observer
// could not name is an OBSERVATION of IP egress, not the absence of one.
func TestFamilyInetUnspecifiedIsIP(t *testing.T) {
	for _, family := range []string{FamilyIPv4, FamilyIPv6, FamilyInetUnspecified} {
		if !FamilyIsIP(family) {
			t.Errorf("FamilyIsIP(%q) = false, want true", family)
		}
	}
	for _, family := range []string{FamilyUnix, FamilyUnspecified, FamilyNotObservable, FamilyNetlink, "AF_16", ""} {
		if FamilyIsIP(family) {
			t.Errorf("FamilyIsIP(%q) = true, want false", family)
		}
	}
	if !FamilyIsUnix(FamilyUnix) {
		t.Errorf("FamilyIsUnix(%q) = false, want true", FamilyUnix)
	}
	if got := ClassifySocketFamily("AF_16"); got != FamilyClassUndefined {
		t.Errorf("ClassifySocketFamily of an unnamed numeric family = %v, want FamilyClassUndefined", got)
	}
}

// TestRuntimeFamiliesOutsideTheVocabularyAreUndefined states the limit of the
// scan above, so nobody mistakes it for a proof that the classifier is total.
//
// TestEverySocketFamilyConstantIsClassified reasons over CONSTANTS discovered
// by go/parser. The Linux tracer emits fmt.Sprintf("AF_%d", domain) for any
// domain it has no name for, and NO CONSTANT DECLARES "AF_42" — so the scan
// cannot see it and never will. The runtime domain of Family is every string a
// tracer can produce, and for the part of it this vocabulary does not define
// the answer is FamilyClassUndefined, which a consumer must read as possible
// egress. cilock's TestUnclassifiedRuntimeFamilyBreaksHermeticity is the other
// half: that the consumer actually does.
func TestRuntimeFamiliesOutsideTheVocabularyAreUndefined(t *testing.T) {
	if FamilyClassUndefined != 0 {
		t.Error("FamilyClassUndefined is no longer the zero value; a family missing from the " +
			"table would then get whatever class happens to be zero instead of the conservative one")
	}
	// Shapes a tracer really produces, none of them declared as a constant.
	for _, family := range []string{"AF_42", "AF_40", "AF_16", "AF_0", ""} {
		if got := ClassifySocketFamily(family); got != FamilyClassUndefined {
			t.Errorf("ClassifySocketFamily(%q) = %v, want FamilyClassUndefined", family, got)
		}
	}
}

// TestVSockIsRemoteCapableAndNotIP pins AF_VSOCK's classification in both
// directions. It reaches another machine context — a guest's hypervisor host —
// so it is egress; it is not IP, and calling it IP would be false on the wire,
// where these names travel inside the signed predicate.
func TestVSockIsRemoteCapableAndNotIP(t *testing.T) {
	if got := ClassifySocketFamily(FamilyVSock); got != FamilyClassRemoteNonIP {
		t.Errorf("ClassifySocketFamily(%q) = %v, want FamilyClassRemoteNonIP", FamilyVSock, got)
	}
	if FamilyIsIP(FamilyVSock) {
		t.Errorf("FamilyIsIP(%q) = true; a VM socket is not IP and the predicate must not say it is", FamilyVSock)
	}
	if FamilyIsUnix(FamilyVSock) {
		t.Errorf("FamilyIsUnix(%q) = true; it is not named by a filesystem path", FamilyVSock)
	}
}

// TestUnobservedIsNotUnspecified pins the split that keeps "this reached
// nothing" apart from "I could not see what this reached".
//
// AF_UNSPEC on connect() is the resolver's disconnect idiom: the observer READ
// sa_family, and what it read reaches nothing, so it is non-remote and every
// build that looks up a hostname stays hermetic. An operation the observer
// could not read at all is a different fact, gets a different name, and gets
// the conservative class — because a channel nobody watched is one a build
// could have fetched through, and `Hermetic = len(NetworkEgress) == 0` turns
// any silence here into a signed claim that it did not.
//
// One value for both facts is what makes the second one disappear. cilock's
// TestUnobservedConnectBreaksHermeticity is the consumer half.
func TestUnobservedIsNotUnspecified(t *testing.T) {
	if FamilyUnspecified == FamilyNotObservable {
		t.Fatal("the described and the unobservable case share one family value, so a consumer " +
			"cannot tell them apart and one of the two is being answered wrongly")
	}
	if got := ClassifySocketFamily(FamilyUnspecified); got != FamilyClassNonRemote {
		t.Errorf("ClassifySocketFamily(%q) = %v, want FamilyClassNonRemote — a read AF_UNSPEC "+
			"reaches nothing, and counting it makes every build that resolves a name non-hermetic",
			FamilyUnspecified, got)
	}
	if got := ClassifySocketFamily(FamilyNotObservable); got != FamilyClassUnobservable {
		t.Errorf("ClassifySocketFamily(%q) = %v, want FamilyClassUnobservable — an operation "+
			"nobody could describe must not be classified as one that reached nothing",
			FamilyNotObservable, got)
	}
	if FamilyIsIP(FamilyNotObservable) || FamilyIsUnix(FamilyNotObservable) {
		t.Errorf("%q was reported as a concrete family; it is the absence of one", FamilyNotObservable)
	}
}

// TestUnobservedConnectionIsRecordedNotDropped pins the shape a backend hands
// on when it saw an outbound operation and could not read its arguments. Every
// field has to say "unobservable" in a way a consumer already recognises,
// because the alternative a backend reaches for is dropping the event, and a
// dropped connect() is the empty egress list that gets signed hermetic.
func TestUnobservedConnectionIsRecordedNotDropped(t *testing.T) {
	conn := UnobservedConnection("connect", FDNotObservable)
	if conn.Syscall != "connect" {
		t.Errorf("Syscall = %q, want \"connect\"; cilock only counts connect() against hermeticity", conn.Syscall)
	}
	if conn.Family != FamilyNotObservable {
		t.Errorf("Family = %q, want %q", conn.Family, FamilyNotObservable)
	}
	if conn.Address != HostNotObservable {
		t.Errorf("Address = %q, want %q — an empty address reads as a resolved endpoint of none",
			conn.Address, HostNotObservable)
	}
	if conn.Port != 0 {
		t.Errorf("Port = %d, want 0; no port was observed and inventing one would be a claim", conn.Port)
	}
	if ClassifySocketFamily(conn.Family) != FamilyClassUnobservable {
		t.Error("the connection this helper builds does not classify as unobservable, so a " +
			"consumer would not count it and the event is lost after all")
	}
}

// TestSocketFamilyClassificationsIsACopy proves a consumer's test cannot mutate
// the live classification table through the accessor it reads it with.
func TestSocketFamilyClassificationsIsACopy(t *testing.T) {
	got := SocketFamilyClassifications()
	got[FamilyIPv4] = FamilyClassNonRemote
	delete(got, FamilyUnix)
	if !FamilyIsIP(FamilyIPv4) || !FamilyIsUnix(FamilyUnix) {
		t.Fatal("mutating the returned map changed the live table")
	}
}
