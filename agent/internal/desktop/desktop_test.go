package desktop

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type calls struct {
	mu  sync.Mutex
	got [][]string
}

func (c *calls) run(_ context.Context, name string, args ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, append([]string{name}, args...))
	return nil
}
func (c *calls) wait(t *testing.T, n int) [][]string {
	for i := 0; i < 200; i++ {
		c.mu.Lock()
		l := len(c.got)
		c.mu.Unlock()
		if l >= n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]string(nil), c.got...)
}

func TestMacNotificationRunsInTheUsersSessionWithTextAsArguments(t *testing.T) {
	c := &calls{}
	now := time.Unix(1_800_000_000, 0)
	n := &Notifier{GOOS: "darwin", Run: c.run, Every: 10 * time.Minute, Now: func() time.Time { return now }, LookupUID: func(string) (string, error) { return "501", nil }}
	evil := `Chess" & do shell script "rm -rf ~"`
	if !n.Notify("rule-1", "alice", "Blocked by your organization", evil) {
		t.Fatal("didn't notify")
	}
	got := c.wait(t, 1)
	cmd := strings.Join(got[0], " ")
	if !strings.HasPrefix(cmd, "launchctl asuser 501 sudo -u alice osascript") || got[0][len(got[0])-1] != evil {
		t.Fatalf("%q", got[0])
	}
	for _, a := range got[0] {
		if strings.Contains(a, "display notification") && strings.Contains(a, "rm -rf") {
			t.Fatal("the text ended up in the script")
		}
	}
	// Relaunched within 10 minutes: quiet. Another app, or later: shown.
	if n.Notify("rule-1", "alice", "t", "b") {
		t.Fatal("notified again too soon")
	}
	if !n.Notify("rule-2", "alice", "t", "b") {
		t.Fatal("a different rule was suppressed")
	}
	now = now.Add(11 * time.Minute)
	if !n.Notify("rule-1", "alice", "t", "b") {
		t.Fatal("still suppressed after the interval")
	}
	// System accounts get nothing.
	n.Notify("rule-3", "root", "t", "b")
	n.Notify("rule-4", "_windowserver", "t", "b")
	if l := len(c.wait(t, 3)); l != 3 {
		t.Fatalf("%d calls", l)
	}
}

func TestWindowsUsesMsg(t *testing.T) {
	c := &calls{}
	n := &Notifier{GOOS: "windows", Run: c.run, Every: time.Minute}
	n.Notify("r", "", "Blocked", "Chess was closed")
	got := c.wait(t, 1)
	if strings.Join(got[0][:3], " ") != "msg * /TIME:30" || got[0][3] != "Blocked: Chess was closed" {
		t.Fatalf("%q", got[0])
	}
}
