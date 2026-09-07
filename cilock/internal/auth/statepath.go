package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const stateDirectoryEnv = "CILOCK_STATE_DIR"

func isolatedStateEnabled() bool {
	_, present := os.LookupEnv(stateDirectoryEnv)
	return present
}

// Explicit state is an isolation boundary, including when its value is invalid.
// Require an existing canonical private directory rather than creating a path
// through symlinks or silently consulting another credential store on failure.
func cilockStateDirectory() (string, error) {
	dir, explicit := os.LookupEnv(stateDirectoryEnv)
	if !explicit {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve user config dir: %w", err)
		}
		return filepath.Join(base, "cilock"), nil
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.ContainsFunc(dir, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("CILOCK_STATE_DIR must name an existing canonical absolute private directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o700 != 0o700 {
		return "", fmt.Errorf("CILOCK_STATE_DIR must be an existing 0700 directory, not a symlink")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil || canonical != dir {
		return "", fmt.Errorf("CILOCK_STATE_DIR must not traverse symlinks")
	}
	return dir, nil
}
