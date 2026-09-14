//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func newPrivateRunDir(dir string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("inventory evidence directory must be a private 0700 directory, not a symlink: %q", dir)
	}
	return os.MkdirTemp(dir, "run-")
}

// Exclusive descriptor-relative creation refuses existing files and links.
func writePrivateRunEnvelope(path string, body []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(body)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		_ = root.Remove(filepath.Base(path))
	}
	return err
}
