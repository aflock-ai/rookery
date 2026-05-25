// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !linux

package commandrun

// EnvVarFanotify is exported for cross-platform reference; on non-Linux
// it's never consulted.
const EnvVarFanotify = "CILOCK_FANOTIFY"

type fanotifySession struct{}

func maybeStartFanotify(workingDir string) (*fanotifySession, error) {
	return nil, nil
}

func (s *fanotifySession) stop() (map[string][32]byte, fanotifyStatsStub) {
	return nil, fanotifyStatsStub{}
}

type fanotifyStatsStub struct{}

func mergeFanotifyDigests(processes []ProcessInfo, fanDigests map[string][32]byte) (int, map[string]string) {
	return 0, nil
}
