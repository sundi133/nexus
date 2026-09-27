//go:build windows

package assist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSSendMessageW             = wtsapi32.NewProc("WTSSendMessageW")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")
)

const (
	wtsUserName   = 5
	mbOK          = 0x0
	mbYesNo       = 0x4
	mbIconWarning = 0x30
	mbDefButton2  = 0x100
	mbTopmost     = 0x40000
	mbForeground  = 0x10000
	idYes         = 6
	idTimeout     = 32000
	noWindow      = 0x08000000
)

// Windows is Remote Assist's Windows side. The agent runs as a service in session 0, which can't
// see the desktop, so screen sharing is a helper (this same program) started in the signed-in
// person's session; it serves the screen over RFB to the agent through a loopback Link.
type Windows struct {
	Exe string // this program, started again as the helper

	mu   sync.Mutex
	link *Link
	proc windows.Handle
}

func consoleSession() uint32 { return windows.WTSGetActiveConsoleSessionId() }

// ConsoleUser is who's signed in at the screen ("" at the sign-in screen).
func (w *Windows) ConsoleUser(context.Context) string {
	sid := consoleSession()
	if sid == 0xFFFFFFFF {
		return ""
	}
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(sid), wtsUserName, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

// message shows a message box in the console session; it waits for the answer when wait is set.
func message(title, text string, style uint32, timeout time.Duration, wait bool) (uint32, error) {
	t, _ := syscall.UTF16FromString(title)
	m, _ := syscall.UTF16FromString(text)
	var resp uint32
	var w uintptr
	if wait {
		w = 1
	}
	r, _, err := procWTSSendMessageW.Call(0, uintptr(consoleSession()),
		uintptr(unsafe.Pointer(&t[0])), uintptr(len(t)*2-2), uintptr(unsafe.Pointer(&m[0])), uintptr(len(m)*2-2),
		uintptr(style), uintptr(timeout/time.Second), uintptr(unsafe.Pointer(&resp)), w)
	if r == 0 {
		return 0, err
	}
	return resp, nil
}

// Ask shows "Allow screen sharing?" with Yes and No (No is the default).
func (w *Windows) Ask(ctx context.Context, user, requester, reason string, timeout time.Duration) (Answer, error) {
	text := fmt.Sprintf("%s from your IT team wants to see and control your screen to help you.\n\nReason: %s\n\nAllow it? They can see everything on your screen until the session ends.", requester, reason)
	resp, err := message("Remote Assist", text, mbYesNo|mbIconWarning|mbDefButton2|mbTopmost|mbForeground, timeout, true)
	switch {
	case err != nil:
		return Declined, err
	case resp == idYes:
		return Allowed, nil
	case resp == idTimeout:
		return NoAnswer, nil
	}
	return Declined, nil
}

// Notify shows a message without waiting for it to be closed.
func (w *Windows) Notify(user, title, body string) {
	_, _ = message(title, body, mbOK|mbTopmost, 30*time.Second, false)
}

// On is always false: there's no screen sharing to find already running.
func (w *Windows) On(context.Context) bool { return false }

// Enable starts the helper in the signed-in person's session.
func (w *Windows) Enable(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	link, err := NewLink()
	if err != nil {
		return err
	}
	proc, err := startInSession(w.Exe, []string{"assist-helper", link.Addr(), link.Secret()})
	if err != nil {
		link.Close()
		return err
	}
	w.link, w.proc = link, proc
	return nil
}

// Disable stops the helper.
func (w *Windows) Disable(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.proc != 0 {
		_ = windows.TerminateProcess(w.proc, 0)
		windows.CloseHandle(w.proc)
		w.proc = 0
	}
	if w.link != nil {
		w.link.Close()
		w.link = nil
	}
	return nil
}

// DialVNC is the helper's next connection.
func (w *Windows) DialVNC(ctx context.Context) (net.Conn, error) {
	w.mu.Lock()
	link := w.link
	w.mu.Unlock()
	if link == nil {
		return nil, errors.New("screen sharing isn't running")
	}
	return link.Dial(ctx)
}

// Showing waits for the helper to end: it exits when the person clicks OK on its "end session"
// message. That counts as ending the session at the computer.
func (w *Windows) Showing(ctx context.Context, user, requester string) bool {
	w.mu.Lock()
	proc := w.proc
	w.mu.Unlock()
	if proc == 0 {
		<-ctx.Done()
		return false
	}
	for ctx.Err() == nil {
		if ev, _ := windows.WaitForSingleObject(proc, 500); ev == windows.WAIT_OBJECT_0 {
			return ctx.Err() == nil
		}
	}
	return false
}

// startInSession runs exe as the console session's user, on their desktop, with no console window.
func startInSession(exe string, args []string) (windows.Handle, error) {
	sid := consoleSession()
	if sid == 0xFFFFFFFF {
		return 0, errors.New("nobody is signed in")
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sid, &tok); err != nil {
		return 0, fmt.Errorf("the signed-in person's token: %w", err)
	}
	defer tok.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, err
	}
	defer dup.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, dup, false); err != nil {
		return 0, err
	}
	defer windows.DestroyEnvironmentBlock(env)
	cmd := windows.ComposeCommandLine(append([]string{exe}, args...))
	cmdp, _ := windows.UTF16PtrFromString(cmd)
	exep, _ := windows.UTF16PtrFromString(exe)
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desk}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(dup, exep, cmdp, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT|noWindow, env, nil, &si, &pi); err != nil {
		return 0, fmt.Errorf("starting the screen-sharing helper: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}
