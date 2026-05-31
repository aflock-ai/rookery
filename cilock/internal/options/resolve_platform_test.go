// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"testing"

	"github.com/spf13/cobra"

	// Register the fulcio signer provider so AddFlags wires up --signer-fulcio-url,
	// the flag whose default ResolvePlatformDefaults derives from --platform-url.
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

func newRunCmd(t *testing.T) (*cobra.Command, *RunOptions) {
	t.Helper()
	ro := &RunOptions{}
	cmd := &cobra.Command{Use: "run"}
	ro.AddFlags(cmd)
	return cmd, ro
}

func fulcioURL(t *testing.T, cmd *cobra.Command) string {
	t.Helper()
	f := cmd.Flags().Lookup("signer-fulcio-url")
	if f == nil {
		t.Fatal("signer-fulcio-url flag not registered")
	}
	return f.Value.String()
}

// TestResolvePlatformDefaults_DerivesFulcioURL pins the contract that
// --platform-url derives the Fulcio signer URL, the same way it already
// derives Archivista and the TSA. Before this, `cilock run --platform-url X`
// still errored "fulcio URL must include a host" unless the user ALSO passed
// --signer-fulcio-url, because the fulcio signer's default URL is "".
func TestResolvePlatformDefaults_DerivesFulcioURL(t *testing.T) {
	t.Run("default platform url derives fulcio url", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags(nil); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), "https://platform.testifysec.com/fulcio"; got != want {
			t.Fatalf("fulcio url = %q, want %q", got, want)
		}
	})

	t.Run("custom platform url derives fulcio url and tsa", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", "http://localhost:8083"}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), "http://localhost:8083/fulcio"; got != want {
			t.Fatalf("fulcio url = %q, want %q", got, want)
		}
		// Regression guard: TSA derivation (the existing behavior) is unchanged.
		if len(ro.TimestampServers) != 1 || ro.TimestampServers[0] != "http://localhost:8083/api/v1/timestamp" {
			t.Fatalf("tsa servers = %v, want [http://localhost:8083/api/v1/timestamp]", ro.TimestampServers)
		}
	})

	t.Run("trailing slash on platform url is normalized", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", "https://judge.example.com/"}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), "https://judge.example.com/fulcio"; got != want {
			t.Fatalf("fulcio url = %q, want %q", got, want)
		}
	})

	t.Run("explicit signer-fulcio-url wins over derivation", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", "http://localhost:8083",
			"--signer-fulcio-url", "https://custom.example/fulcio",
		}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), "https://custom.example/fulcio"; got != want {
			t.Fatalf("explicit --signer-fulcio-url should win, got %q want %q", got, want)
		}
	})

	t.Run("offline platform-url empty does not derive fulcio url", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got := fulcioURL(t, cmd); got != "" {
			t.Fatalf("offline (--platform-url \"\") must leave fulcio url empty, got %q", got)
		}
	})
}
