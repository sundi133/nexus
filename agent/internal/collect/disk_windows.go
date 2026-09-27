//go:build windows

package collect

import (
	"os"

	"golang.org/x/sys/windows"
)

// systemDisk is the Windows system drive (usually C:).
func systemDisk() []Disk {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	path, err := windows.UTF16PtrFromString(drive + `\`)
	if err != nil {
		return nil
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(path, &free, &total, &totalFree); err != nil || total == 0 {
		return nil
	}
	return []Disk{{Mount: drive, SizeBytes: total, FreeBytes: free}}
}
