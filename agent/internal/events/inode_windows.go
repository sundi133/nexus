//go:build windows

package events

import "os"

// Windows: rotation is noticed by the file getting shorter than what was read.
func inodeOf(os.FileInfo) uint64 { return 0 }
