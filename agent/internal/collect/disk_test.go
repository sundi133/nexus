package collect

import "testing"

func TestSystemDisk(t *testing.T) {
	d := systemDisk()
	if len(d) != 1 || d[0].SizeBytes == 0 || d[0].FreeBytes > d[0].SizeBytes || d[0].Mount == "" {
		t.Fatalf("system disk: %+v", d)
	}
	t.Logf("%s: %.1f of %.1f GB free", d[0].Mount, float64(d[0].FreeBytes)/1e9, float64(d[0].SizeBytes)/1e9)
}
