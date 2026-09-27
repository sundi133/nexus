//go:build !darwin && !windows

package enforce

func execPath(int) string { return "" } // Linux reads /proc/<pid>/exe instead
