//go:build darwin || linux

package collect

import (
	"os"

	"golang.org/x/sys/unix"
)

// systemDisk is the volume people's files live on: on macOS the data volume (the system volume
// is a sealed snapshot sharing its space), elsewhere the root.
func systemDisk() []Disk {
	mount := "/"
	if _, err := os.Stat("/System/Volumes/Data"); err == nil {
		mount = "/System/Volumes/Data"
	}
	var st unix.Statfs_t
	if err := unix.Statfs(mount, &st); err != nil || st.Blocks == 0 {
		return nil
	}
	bs := uint64(st.Bsize)
	// Bavail: what ordinary users can still write (root's reserve isn't free for them).
	return []Disk{{Mount: mount, SizeBytes: st.Blocks * bs, FreeBytes: st.Bavail * bs}}
}
