// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"testing"
	"time"
)

func TestResolveString_HierarchyOrder(t *testing.T) {
	// 1. CLI flag wins over everything.
	t.Run("cli wins over env", func(t *testing.T) {
		t.Setenv("FOO", "envval")
		got := ResolveString("cliVal", true, "FOO", "defaultVal")
		if got != "cliVal" {
			t.Fatalf("expected cli to win, got %q", got)
		}
	})

	// 1a. Empty-but-explicit CLI wins (Cole's --platform-url="" pattern).
	t.Run("explicit empty cli wins", func(t *testing.T) {
		t.Setenv("FOO", "envval")
		got := ResolveString("", true, "FOO", "defaultVal")
		if got != "" {
			t.Fatalf("explicit empty cli value should win over env, got %q", got)
		}
	})

	// 2. Env beats default.
	t.Run("env beats default", func(t *testing.T) {
		t.Setenv("FOO", "envval")
		got := ResolveString("", false, "FOO", "defaultVal")
		if got != "envval" {
			t.Fatalf("expected env to win over default, got %q", got)
		}
	})

	// 3. Default is the floor.
	t.Run("default is floor", func(t *testing.T) {
		t.Setenv("FOO", "")
		got := ResolveString("", false, "FOO", "defaultVal")
		if got != "defaultVal" {
			t.Fatalf("expected default, got %q", got)
		}
	})
}

func TestResolveInt_HierarchyOrder(t *testing.T) {
	t.Run("cli wins", func(t *testing.T) {
		t.Setenv("FOO", "20")
		got := ResolveInt(10, true, "FOO", 40)
		if got != 10 {
			t.Fatalf("got %d, want 10", got)
		}
	})
	t.Run("env beats default", func(t *testing.T) {
		t.Setenv("FOO", "20")
		got := ResolveInt(0, false, "FOO", 40)
		if got != 20 {
			t.Fatalf("got %d, want 20", got)
		}
	})
	t.Run("invalid env falls through to default", func(t *testing.T) {
		t.Setenv("FOO", "not-a-number")
		got := ResolveInt(0, false, "FOO", 40)
		if got != 40 {
			t.Fatalf("got %d, want 40 (default), unparseable env should fall through", got)
		}
	})
	t.Run("default floor", func(t *testing.T) {
		t.Setenv("FOO", "")
		got := ResolveInt(0, false, "FOO", 40)
		if got != 40 {
			t.Fatalf("got %d, want 40", got)
		}
	})
}

func TestResolveDuration_HierarchyOrder(t *testing.T) {
	t.Run("cli wins", func(t *testing.T) {
		t.Setenv("FOO", "2s")
		got := ResolveDuration(1*time.Second, true, "FOO", 4*time.Second)
		if got != 1*time.Second {
			t.Fatalf("got %v, want 1s", got)
		}
	})
	t.Run("env wins", func(t *testing.T) {
		t.Setenv("FOO", "2s")
		got := ResolveDuration(0, false, "FOO", 4*time.Second)
		if got != 2*time.Second {
			t.Fatalf("got %v, want 2s", got)
		}
	})
	t.Run("invalid env falls back to default", func(t *testing.T) {
		t.Setenv("FOO", "garbage")
		got := ResolveDuration(0, false, "FOO", 4*time.Second)
		if got != 4*time.Second {
			t.Fatalf("got %v, want default 4s", got)
		}
	})
	t.Run("default floor", func(t *testing.T) {
		t.Setenv("FOO", "")
		got := ResolveDuration(0, false, "FOO", 4*time.Second)
		if got != 4*time.Second {
			t.Fatalf("got %v, want default 4s", got)
		}
	})
}
