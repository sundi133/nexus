// Package desktop tells the person at the computer what the agent did, with the OS's own
// notifications: a Notification Center banner on macOS, a message box on Windows. The agent runs
// as root/SYSTEM, so it speaks in the signed-in person's session. Linux isn't supported yet.
package desktop

import (
	"context"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Run executes a command (faked in tests).
type Run func(ctx context.Context, name string, args ...string) error

// Notifier shows notifications, at most one per key per Every (a blocked app relaunched in a loop
// shouldn't flood the screen).
type Notifier struct {
	GOOS  string
	Run   Run
	Every time.Duration
	Now   func() time.Time
	// LookupUID finds a macOS account's UID (os/user by default).
	LookupUID func(name string) (string, error)

	mu   sync.Mutex
	last map[string]time.Time
}

func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// Notify shows title and body to user (the process owner). It returns whether it tried.
func (n *Notifier) Notify(key, username, title, body string) bool {
	now := time.Now
	if n.Now != nil {
		now = n.Now
	}
	n.mu.Lock()
	if n.last == nil {
		n.last = map[string]time.Time{}
	}
	if t, ok := n.last[key+"|"+username]; ok && now().Sub(t) < n.Every {
		n.mu.Unlock()
		return false
	}
	n.last[key+"|"+username] = now()
	n.mu.Unlock()
	title, body = clean(title, 100), clean(body, 300)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	go func() {
		defer cancel()
		switch n.GOOS {
		case "darwin":
			if username == "" || username == "root" || strings.HasPrefix(username, "_") {
				return
			}
			lookup := n.LookupUID
			if lookup == nil {
				lookup = func(name string) (string, error) {
					u, err := user.Lookup(name)
					if err != nil {
						return "", err
					}
					return u.Uid, nil
				}
			}
			uid, err := lookup(username)
			if err != nil {
				return
			}
			// The text goes in as arguments, never into the script: nothing in it is interpreted.
			_ = n.Run(ctx, "launchctl", "asuser", uid, "sudo", "-u", username, "osascript",
				"-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, body)
		case "windows":
			// msg reaches every signed-in session from SYSTEM; the text is one argument.
			_ = n.Run(ctx, "msg", "*", "/TIME:30", title+": "+body)
		}
	}()
	return true
}

// Default is a Notifier for this OS.
func Default(run Run) *Notifier {
	return &Notifier{GOOS: runtime.GOOS, Run: run, Every: 10 * time.Minute}
}
