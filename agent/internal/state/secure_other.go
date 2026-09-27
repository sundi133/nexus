//go:build !windows

package state

import "os"

// secureDir keeps the state folder owner-only (the files inside are 0600 too).
func secureDir(dir string) error { return os.Chmod(dir, 0o700) }
