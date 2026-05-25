// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !linux

package commandrun

import "sync/atomic"

const EnvVarFsVerity = "CILOCK_FSVERITY"

type fsVerityState struct {
	Available    bool
	Sealed       atomic.Uint64
	SealFailures atomic.Uint64
}

func probeFsVerity(workspaceDir string) (*fsVerityState, error) {
	return nil, nil
}

func (s *fsVerityState) sealProduct(path string) string {
	return ""
}
