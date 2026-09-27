//go:build !windows

package enforce

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var userNames = map[string]string{}

func userName(uid string) string {
	if n, ok := userNames[uid]; ok {
		return n
	}
	n := uid
	if u, err := user.LookupId(uid); err == nil {
		n = u.Username
	}
	userNames[uid] = n
	return n
}

// ListProcesses returns running programs with their executable paths.
func ListProcesses() ([]Proc, error) {
	if runtime.GOOS == "linux" {
		return linuxProcs()
	}
	// macOS: ps prints the full executable path (comm), which may contain spaces.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-axo", "pid=,uid=,comm=").Output()
	if err != nil {
		return nil, err
	}
	var procs []Proc
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if p, ok := parsePS(sc.Text()); ok {
			// ps shows what the program was started as ("yes"); the kernel knows the executable (/usr/bin/yes).
			if exe := execPath(p.PID); exe != "" {
				p.Path = exe
			}
			procs = append(procs, p)
		}
	}
	return procs, sc.Err()
}

// parsePS reads "  PID   UID /path/with spaces/to/program" (field by field: the path may contain spaces).
func parsePS(line string) (Proc, bool) {
	pidS, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok {
		return Proc{}, false
	}
	uidS, path, ok := strings.Cut(strings.TrimLeft(rest, " "), " ")
	pid, err := strconv.Atoi(pidS)
	if !ok || err != nil {
		return Proc{}, false
	}
	return Proc{PID: pid, Path: strings.TrimSpace(path), User: userName(uidS)}, true
}

func linuxProcs() ([]Proc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []Proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue // kernel threads, or gone
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		var uid string
		if st, err := os.Stat(filepath.Join("/proc", e.Name())); err == nil {
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = strconv.Itoa(int(s.Uid))
			}
		}
		procs = append(procs, Proc{PID: pid, Path: exe, User: userName(uid)})
	}
	return procs, nil
}

// KillProcess terminates a process at once (SIGKILL: a blocked app gets no chance to object).
func KillProcess(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

// FlushDNS makes a new hosts file take effect for apps that cached lookups.
func FlushDNS() {
	run := func(name string, args ...string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, name, args...).Run()
	}
	if runtime.GOOS == "darwin" {
		run("dscacheutil", "-flushcache")
		run("killall", "-HUP", "mDNSResponder")
		return
	}
	run("resolvectl", "flush-caches")
}
