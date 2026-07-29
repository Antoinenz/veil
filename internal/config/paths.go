package config

import (
	"os"
	"path/filepath"
)

// defaultClientDataDir returns a per-user data directory for client state.
// Cross-platform via os.UserConfigDir (%AppData% on Windows, ~/.config on Linux).
func defaultClientDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(".", ".veil")
	}
	return filepath.Join(dir, "veil")
}
