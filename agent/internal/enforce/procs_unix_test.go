//go:build !windows

package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParsePS(t *testing.T) {
	for line, want := range map[string]Proc{
		"  1501   501 /Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper": {PID: 1501, Path: "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper"},
		"    1     0 /sbin/launchd": {PID: 1, Path: "/sbin/launchd"},
	} {
		got, ok := parsePS(line)
		if !ok || got.PID != want.PID || got.Path != want.Path {
			t.Errorf("parsePS(%q) = %+v", line, got)
		}
	}
}

func TestExecPathOfARealProcess(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	procs, err := ListProcesses()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.PID == os.Getpid() {
			exe, _ := os.Executable()
			if p.Path != exe {
				t.Fatalf("own path = %q, want %q", p.Path, exe)
			}
			return
		}
	}
	t.Fatal("didn't find this test process")
}

func TestExecPathIsAbsoluteForARelativeLaunch(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	dir := t.TempDir()
	// A program started as ./prog: ps and the exec path say "./prog"; the kernel knows where it is.
	src := filepath.Join(dir, "main.go")
	os.WriteFile(src, []byte("package main\nimport \"time\"\nfunc main() { time.Sleep(time.Minute) }\n"), 0o644)
	if out, err := exec.Command("go", "build", "-o", filepath.Join(dir, "prog"), src).CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	cmd := exec.Command("./prog")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	want, _ := filepath.EvalSymlinks(filepath.Join(dir, "prog"))
	if got := execPath(cmd.Process.Pid); got != want {
		t.Fatalf("execPath = %q, want %q", got, want)
	}
}
