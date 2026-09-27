package assist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

// Run executes a command and returns its combined output.
type Run func(ctx context.Context, name string, args ...string) (string, error)

// ExecRun is Run with os/exec.
func ExecRun(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

const vncAddr = "127.0.0.1:5900"

// DialVNC connects to the Mac's own Screen Sharing (the relay can reach nothing else).
func DialVNC(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", vncAddr)
}

// Mac is Remote Assist's macOS side: prompts in the signed-in person's session, and Screen Sharing
// through launchd. The agent runs as root.
type Mac struct {
	Run Run
}

// ConsoleUser is who is signed in at the screen ("" at the login window).
func (m Mac) ConsoleUser(ctx context.Context) string {
	out, err := m.Run(ctx, "stat", "-f", "%Su", "/dev/console")
	u := strings.TrimSpace(out)
	if err != nil || u == "" || u == "root" || strings.HasPrefix(u, "_") || strings.ContainsAny(u, " /") {
		return ""
	}
	return u
}

// asUser runs osascript in user's GUI session. The text goes in as arguments, never into the
// script, so nothing in it is interpreted.
func (m Mac) asUser(ctx context.Context, username string, script []string, argv ...string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	args := []string{"asuser", u.Uid, "sudo", "-u", username, "osascript"}
	for _, line := range script {
		args = append(args, "-e", line)
	}
	return m.Run(ctx, "launchctl", append(args, argv...)...)
}

// Ask shows "Allow / Don't Allow", defaulting to Don't Allow.
func (m Mac) Ask(ctx context.Context, username, requester, reason string, timeout time.Duration) (Answer, error) {
	msg := fmt.Sprintf("%s from your IT team wants to see and control your screen to help you.\n\nReason: %s\n\nThey can see everything on your screen until you end the session.", requester, reason)
	ctx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()
	out, err := m.asUser(ctx, username, []string{
		"on run argv",
		fmt.Sprintf(`display dialog (item 1 of argv) with title "Remote Assist" buttons {"Don't Allow", "Allow"} default button "Don't Allow" with icon caution giving up after %d`, int(timeout.Seconds())),
		"end run",
	}, msg)
	switch {
	case strings.Contains(out, "gave up:true"):
		return NoAnswer, nil
	case strings.Contains(out, "button returned:Allow"):
		return Allowed, nil
	case strings.Contains(out, "button returned:Don't Allow"), strings.Contains(out, "(-128)"): // -128: cancelled
		return Declined, nil
	case err != nil:
		return Declined, fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	return Declined, nil
}

// Showing keeps an "End Session" prompt up; it comes back if dismissed some other way.
func (m Mac) Showing(ctx context.Context, username, requester string) bool {
	for ctx.Err() == nil {
		out, _ := m.asUser(ctx, username, []string{
			"on run argv",
			"with timeout of 86400 seconds", // not AppleScript's default two minutes
			`display dialog (item 1 of argv) with title "Remote Assist" buttons {"End Session"} default button "End Session" with icon caution`,
			"end timeout",
			"end run",
		}, requester+" can see your screen. Click End Session when you're done.")
		if strings.Contains(out, "button returned:End Session") {
			return true
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
	return false
}

// Notify shows a notification banner.
func (m Mac) Notify(username, title, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _ = m.asUser(ctx, username, []string{"on run argv", "display notification (item 2 of argv) with title (item 1 of argv)", "end run"}, title, body)
}

// On reports whether Screen Sharing is answering.
func (m Mac) On(ctx context.Context) bool {
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", vncAddr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

const sharingPlist = "/System/Library/LaunchDaemons/com.apple.screensharing.plist"

// Enable turns on Screen Sharing and waits for it to listen.
func (m Mac) Enable(ctx context.Context) error {
	if out, err := m.Run(ctx, "launchctl", "enable", "system/com.apple.screensharing"); err != nil {
		return fmt.Errorf("launchctl enable: %v: %s", err, strings.TrimSpace(out))
	}
	// Already loaded is fine (the bootstrap then fails, but the service is there).
	_, _ = m.Run(ctx, "launchctl", "bootstrap", "system", sharingPlist)
	for i := 0; i < 20; i++ {
		if m.On(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("Screen Sharing didn't start listening")
}

// Disable turns Screen Sharing back off.
func (m Mac) Disable(ctx context.Context) error {
	_, _ = m.Run(ctx, "launchctl", "bootout", "system/com.apple.screensharing")
	if out, err := m.Run(ctx, "launchctl", "disable", "system/com.apple.screensharing"); err != nil {
		return fmt.Errorf("launchctl disable: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}
