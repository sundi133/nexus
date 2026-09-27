//go:build windows

package assist

import (
	"context"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/votal-ai/nexus/agent/internal/rfb"
)

// ForThisOS is the Windows side of Remote Assist: a helper in the person's session serves the screen.
func ForThisOS(exe string) Deps {
	w := &Windows{Exe: exe}
	return Deps{GOOS: "windows", ConsoleUser: w.ConsoleUser, Ask: w.Ask, Showing: w.Showing, Notify: w.Notify, Sharing: w, DialVNC: w.DialVNC}
}

var procMessageBoxW = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")

// HelperMain runs in the signed-in person's session: it serves the screen until they click OK on
// the message saying someone can see it (or the agent ends the session and stops it).
func HelperMain(args []string) int {
	if len(args) != 2 {
		return 2
	}
	screen, err := rfb.NewWindowsScreen()
	if err != nil {
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host, _ := os.Hostname()
	done := make(chan struct{})
	go func() {
		_ = RunHelper(ctx, args[0], args[1], screen, host)
		close(done)
	}()
	go func() {
		title, _ := syscall.UTF16PtrFromString("Remote Assist")
		text, _ := syscall.UTF16PtrFromString("Someone from your IT team can see and control your screen through Nexus Remote Assist.\n\nClick OK to end the session.")
		_, _, _ = procMessageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x30|0x40000|0x10000) // warning, topmost, foreground
		cancel()
	}()
	<-done
	return 0
}
