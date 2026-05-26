// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"crypto"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ds(hex string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}: hex,
	}
}

func TestUntrackedMaterialsAllowed_EmptyMaterials_OK(t *testing.T) {
	step := Step{Name: "build"}
	mats := map[string]cryptoutil.DigestSet{}
	proven := map[string]struct{}{}
	require.NoError(t, untrackedMaterialsAllowed(step, mats, proven))
}

func TestUntrackedMaterialsAllowed_AllProven_OK(t *testing.T) {
	step := Step{Name: "build"}
	mats := map[string]cryptoutil.DigestSet{
		"src/main.go": ds("a"),
		"src/util.go": ds("b"),
	}
	proven := map[string]struct{}{
		"src/main.go": {},
		"src/util.go": {},
	}
	require.NoError(t, untrackedMaterialsAllowed(step, mats, proven))
}

func TestUntrackedMaterialsAllowed_StrictFailsWhenAnyUncovered(t *testing.T) {
	step := Step{Name: "build"} // no AllowedUntracked
	mats := map[string]cryptoutil.DigestSet{
		"src/main.go": ds("a"),
		"/usr/lib/libc.so": ds("b"),
	}
	proven := map[string]struct{}{
		"src/main.go": {},
	}
	err := untrackedMaterialsAllowed(step, mats, proven)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without chain-of-custody proof")
	assert.Contains(t, err.Error(), "/usr/lib/libc.so")
}

func TestUntrackedMaterialsAllowed_GlobCoversSystemPaths(t *testing.T) {
	step := Step{
		Name: "build",
		AllowedUntracked: []string{
			"/usr/lib/**",
			"/opt/hostedtoolcache/**",
		},
	}
	mats := map[string]cryptoutil.DigestSet{
		"src/main.go":                                ds("a"),
		"/usr/lib/libc.so":                           ds("b"),
		"/opt/hostedtoolcache/go/1.26/x64/bin/go":    ds("c"),
	}
	proven := map[string]struct{}{
		"src/main.go": {},
	}
	require.NoError(t, untrackedMaterialsAllowed(step, mats, proven))
}

func TestUntrackedMaterialsAllowed_GlobMustActuallyMatch(t *testing.T) {
	step := Step{
		Name:             "build",
		AllowedUntracked: []string{"/usr/lib/**"},
	}
	mats := map[string]cryptoutil.DigestSet{
		// Not under /usr/lib — should fail.
		"/etc/passwd": ds("x"),
	}
	proven := map[string]struct{}{}
	err := untrackedMaterialsAllowed(step, mats, proven)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/etc/passwd")
}

func TestCompileAllowedUntracked_RejectsEmptyPattern(t *testing.T) {
	_, err := compileAllowedUntracked([]string{"/usr/lib/**", ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty glob")
}

func TestCompileAllowedUntracked_RejectsBadGlobSyntax(t *testing.T) {
	_, err := compileAllowedUntracked([]string{"[invalid"})
	require.Error(t, err)
}

func TestUntrackedMaterialsAllowed_TruncatesLargeUncoveredList(t *testing.T) {
	step := Step{Name: "build"}
	mats := map[string]cryptoutil.DigestSet{}
	for _, p := range []string{
		"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h",
	} {
		mats[p] = ds("x")
	}
	err := untrackedMaterialsAllowed(step, mats, map[string]struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "showing 5 of 8")
}
