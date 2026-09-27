//go:build darwin

package enforce

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	resolvedMu sync.Mutex
	resolved   = map[string]string{} // "pid|exec path as launched" → absolute path
)

// execPath is the executable's absolute path, or "" if it can't be read (without root, only this
// user's processes are readable). kern.procargs2 has the path the program was exec'd with: absolute
// for apps started by launchd, Finder or the Dock. A relative one ("./tool" from a shell) is resolved
// once with lsof and remembered for that process.
func execPath(pid int) string {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(raw) < 5 {
		return ""
	}
	i := bytes.IndexByte(raw[4:], 0)
	if i <= 0 {
		return ""
	}
	launched := string(raw[4 : 4+i])
	if strings.HasPrefix(launched, "/") {
		return launched
	}
	key := strconv.Itoa(pid) + "|" + launched
	resolvedMu.Lock()
	p, ok := resolved[key]
	resolvedMu.Unlock()
	if ok {
		return p
	}
	p = lsofExecutable(pid)
	resolvedMu.Lock()
	if len(resolved) > 4096 {
		resolved = map[string]string{}
	}
	resolved[key] = p
	resolvedMu.Unlock()
	return p
}

func lsofExecutable(pid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "lsof", "-a", "-p", strconv.Itoa(pid), "-d", "txt", "-Fn").Output()
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "n/") {
			return line[1:] // the first text file is the executable
		}
	}
	return ""
}
