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

// fanotifyStatsStub mirrors fanotify.Stats fields the Linux integration
// reads; on non-Linux all values are zero.
type fanotifyStatsStub struct {
	EventsHashed    uint64
	HandlerTimeouts uint64
	QueueOverflows  uint64
	DigestsCapHit   uint64
}

func (s *fanotifySession) stop() (map[string][32]byte, fanotifyStatsStub) {
	return nil, fanotifyStatsStub{}
}

func mergeFanotifyDigests(processes []ProcessInfo, fanDigests map[string][32]byte) (int, map[string]string) {
	return 0, nil
}
