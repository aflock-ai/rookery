// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package cryptoutil

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fsverityEnableArg mirrors the kernel uapi struct fsverity_enable_arg
// from include/uapi/linux/fsverity.h. Size MUST equal 128 bytes; the
// kernel rejects writes of any other size.
type fsverityEnableArg struct {
	Version       uint32
	HashAlgorithm uint32
	BlockSize     uint32
	SaltSize      uint32
	SaltPtr       uint64
	SigSize       uint32
	_             uint32
	SigPtr        uint64
	_             [11]uint64
}

// fsverityDigest mirrors struct fsverity_digest. The flexible array
// member is allocated separately; we use a fixed 64-byte tail to
// hold the largest supported algorithm (SHA-512).
type fsverityDigest struct {
	DigestAlgorithm uint16
	DigestSize      uint16 // input: buffer size; output: actual size
	Digest          [64]byte
}

// EnableVerity calls FS_IOC_ENABLE_VERITY on the file at path,
// computing and storing a Merkle root over its content. After this
// succeeds the file becomes immutable; reads of corrupted blocks
// will be rejected by the kernel. Returns nil on success or an
// error describing why (filesystem doesn't support, file already
// has verity, file isn't a regular file, etc.).
//
// hashAlg: FS_VERITY_HASH_ALG_SHA256 (default 1) or _SHA512 (2).
// Block size 4096 is the universal default.
func EnableVerity(path string, hashAlg uint32) error {
	if hashAlg == 0 {
		hashAlg = unix.FS_VERITY_HASH_ALG_SHA256
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	arg := fsverityEnableArg{
		Version:       1,
		HashAlgorithm: hashAlg,
		BlockSize:     4096,
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		f.Fd(),
		uintptr(unix.FS_IOC_ENABLE_VERITY),
		uintptr(unsafe.Pointer(&arg)),
	)
	if errno != 0 {
		return verityErrno(errno)
	}
	return nil
}

// MeasureVerity reads the Merkle root digest for a fs-verity-enabled
// file. Returns the digest bytes (the kernel-computed Merkle root,
// NOT a plain SHA over the file content), the algorithm constant,
// and any error.
//
// On ENODATA the file isn't fs-verity-enabled. On ENOTTY the
// filesystem doesn't support fs-verity (or it isn't enabled at
// mkfs time). Both are signals to fall back to streaming SHA.
func MeasureVerity(path string) ([]byte, uint16, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	d := fsverityDigest{DigestSize: 64}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		f.Fd(),
		uintptr(unix.FS_IOC_MEASURE_VERITY),
		uintptr(unsafe.Pointer(&d)),
	)
	if errno != 0 {
		return nil, 0, verityErrno(errno)
	}
	if d.DigestSize > 64 {
		return nil, d.DigestAlgorithm, fmt.Errorf("unexpected digest size %d > 64", d.DigestSize)
	}
	out := make([]byte, d.DigestSize)
	copy(out, d.Digest[:d.DigestSize])
	return out, d.DigestAlgorithm, nil
}

// VerityHexDigest returns the Merkle root as a hex string (suitable
// for inclusion in DigestSet). Empty + nil error means "not enabled
// on this file"; non-empty + nil error is the success path.
func VerityHexDigest(path string) (string, error) {
	d, _, err := MeasureVerity(path)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTTY) ||
			errors.Is(err, syscall.EOPNOTSUPP) {
			return "", nil
		}
		return "", err
	}
	return hex.EncodeToString(d), nil
}

// VeritySupported probes whether the filesystem holding the given
// path supports fs-verity. The probe creates a file in the same
// directory, attempts to enable verity, and reports the outcome.
// Returns nil if supported, error otherwise. The probe file is
// deleted on success.
//
// Used at trace-mode startup to decide whether to attempt
// post-write sealing at all — saves per-file ioctl latency.
func VeritySupported(workspaceDir string) error {
	if workspaceDir == "" {
		workspaceDir = "."
	}
	probe, err := os.CreateTemp(workspaceDir, ".cilock-fsverity-probe-*")
	if err != nil {
		return fmt.Errorf("create probe: %w", err)
	}
	probePath := probe.Name()
	defer os.Remove(probePath)
	// Write something — fs-verity refuses empty files on some FS.
	if _, err := probe.Write([]byte("probe")); err != nil {
		probe.Close()
		return fmt.Errorf("write probe: %w", err)
	}
	probe.Close()
	if err := EnableVerity(probePath, unix.FS_VERITY_HASH_ALG_SHA256); err != nil {
		return err
	}
	// fs-verity makes the file immutable on enable; just delete.
	return nil
}

// verityErrno wraps the syscall errno into a typed error so callers
// can detect ENODATA/ENOTTY/EOPNOTSUPP without losing context.
func verityErrno(errno syscall.Errno) error {
	return os.NewSyscallError("fsverity ioctl", errno)
}
