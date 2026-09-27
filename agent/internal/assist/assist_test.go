package assist

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/votal-ai/nexus/agent/internal/wsock"
)

const sid = "0199a0e2-0000-7000-8000-000000000001"

type fakeSharing struct {
	mu               sync.Mutex
	on               bool
	enabled, disable int
}

func (f *fakeSharing) On(context.Context) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.on }
func (f *fakeSharing) Enable(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled++
	f.on = true
	return nil
}
func (f *fakeSharing) Disable(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disable++
	f.on = false
	return nil
}

type reports struct {
	mu  sync.Mutex
	got []string
}

func (r *reports) add(_ context.Context, id, state, detail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, state+": "+detail)
	return nil
}
func (r *reports) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.got...)
}

func deps(t *testing.T, answer Answer, rep *reports, sh *fakeSharing) Deps {
	return Deps{
		GOOS:        "darwin",
		ConsoleUser: func(context.Context) string { return "jo" },
		Ask: func(_ context.Context, u, requester, reason string, _ time.Duration) (Answer, error) {
			if u != "jo" || requester != "ann@example.com" || reason != "VPN broken" {
				t.Errorf("asked %q about %q/%q", u, requester, reason)
			}
			return answer, nil
		},
		Showing: func(ctx context.Context, _, _ string) bool { <-ctx.Done(); return false },
		Notify:  func(string, string, string) {},
		Sharing: sh,
		Report:  rep.add,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Retry:   10 * time.Millisecond,
	}
}

func start(t *testing.T, r *Runner) {
	raw, _ := json.Marshal(map[string]any{"session_id": sid, "requester": "ann@example.com", "reason": "VPN\nbroken", "minutes": 30})
	if _, _, err := r.Action(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}

func wait(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func (r *Runner) idle() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.active == "" }

func TestAllowedSessionRelaysScreenSharing(t *testing.T) {
	// The Mac's Screen Sharing: says hello, and remembers what the viewer sent.
	vnc, _ := net.Listen("tcp", "127.0.0.1:0")
	defer vnc.Close()
	fromViewer := make(chan string, 1)
	go func() {
		c, err := vnc.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("RFB 003.889\n"))
		buf := make([]byte, 100)
		n, _ := c.Read(buf)
		fromViewer <- string(buf[:n])
		c.Close()
	}()
	// The relay: the first tunnel carries one viewer, the next is refused (the session ended).
	fromMac := make(chan string, 1)
	var tunnels int
	var mu sync.Mutex
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tunnels++
		n := tunnels
		mu.Unlock()
		if n > 1 {
			http.Error(w, "over", http.StatusGone)
			return
		}
		c, err := wsock.Accept(w, r)
		if err != nil {
			return
		}
		_ = c.WriteMessage(wsock.OpText, []byte("open"))
		_, data, _ := c.ReadMessage()
		fromMac <- string(data)
		_ = c.WriteMessage(wsock.OpBinary, []byte("RFB 003.008\n"))
		time.Sleep(50 * time.Millisecond)
		c.CloseCode(1000, "viewer left")
	}))
	defer relay.Close()

	rep, sh := &reports{}, &fakeSharing{}
	d := deps(t, Allowed, rep, sh)
	d.DialVNC = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", vnc.Addr().String())
	}
	d.Open = func(ctx context.Context, id string) (Tunnel, error) {
		c, err := wsock.Dial(ctx, "ws"+strings.TrimPrefix(relay.URL, "http")+"/"+id, nil)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	r := &Runner{D: d}
	start(t, r)
	if got := <-fromMac; got != "RFB 003.889\n" {
		t.Fatalf("relay got %q from the Mac", got)
	}
	if got := <-fromViewer; got != "RFB 003.008\n" {
		t.Fatalf("Screen Sharing got %q from the viewer", got)
	}
	wait(t, r.idle)
	if got := rep.list(); len(got) != 1 || got[0] != "accepted: Allowed by jo" {
		t.Fatalf("reports: %v", got)
	}
	if sh.enabled != 1 || sh.disable != 1 {
		t.Fatalf("Screen Sharing should be turned on for the session and back off: %+v", sh)
	}
}

func TestDeclinedOrUnanswered(t *testing.T) {
	for answer, want := range map[Answer]string{Declined: "declined: Declined by jo", NoAnswer: "declined: jo didn't answer"} {
		rep, sh := &reports{}, &fakeSharing{}
		r := &Runner{D: deps(t, answer, rep, sh)}
		start(t, r)
		wait(t, r.idle)
		if got := rep.list(); len(got) != 1 || got[0] != want || sh.enabled != 0 {
			t.Fatalf("%v: %v (sharing %+v)", answer, got, sh)
		}
	}
}

func TestEndedAtTheMacAndAlreadyOn(t *testing.T) {
	rep, sh := &reports{}, &fakeSharing{on: true}
	d := deps(t, Allowed, rep, sh)
	d.Showing = func(context.Context, string, string) bool { time.Sleep(30 * time.Millisecond); return true }
	d.Open = func(ctx context.Context, _ string) (Tunnel, error) { <-ctx.Done(); return nil, ctx.Err() }
	r := &Runner{D: d}
	start(t, r)
	wait(t, r.idle)
	if got := rep.list(); len(got) != 2 || got[1] != "ended: Ended by jo" {
		t.Fatalf("reports: %v", got)
	}
	if sh.enabled != 0 || sh.disable != 0 || !sh.on {
		t.Fatalf("Screen Sharing was already on, so it's left alone: %+v", sh)
	}
}

func TestRefusals(t *testing.T) {
	rep := &reports{}
	d := deps(t, Allowed, rep, &fakeSharing{})
	d.GOOS = "windows"
	if _, _, err := (&Runner{D: d}).Action(context.Background(), json.RawMessage(`{"session_id":"`+sid+`"}`)); err == nil {
		t.Fatal("Windows isn't supported yet")
	}
	d.GOOS = "darwin"
	if _, _, err := (&Runner{D: d}).Action(context.Background(), json.RawMessage(`{"session_id":"../x"}`)); err == nil {
		t.Fatal("a malformed session ID must be refused")
	}
	d.ConsoleUser = func(context.Context) string { return "" }
	r := &Runner{D: d}
	start(t, r)
	wait(t, r.idle)
	if got := rep.list(); len(got) != 1 || !strings.HasPrefix(got[0], "failed: Nobody is signed in") {
		t.Fatalf("reports: %v", got)
	}
	// One session at a time.
	block := make(chan struct{})
	d.ConsoleUser = func(context.Context) string { <-block; return "" }
	r = &Runner{D: d}
	start(t, r)
	if _, _, err := r.Action(context.Background(), json.RawMessage(`{"session_id":"`+sid+`"}`)); err == nil || !strings.Contains(err.Error(), "another") {
		t.Fatalf("want 'another session', got %v", err)
	}
	close(block)
	wait(t, r.idle)
}

func TestMacPromptPassesTextAsArguments(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	var calls [][]string
	out := "button returned:Allow, gave up:false"
	m := Mac{Run: func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		return out, nil
	}}
	a, err := m.Ask(context.Background(), me.Username, `ann" & do shell script "id`, "help", time.Minute)
	if err != nil || a != Allowed {
		t.Fatalf("%v %v", a, err)
	}
	last := calls[0][len(calls[0])-1]
	if !strings.Contains(last, `ann" & do shell script "id`) {
		t.Fatalf("the requester should be a plain argument, got %q", last)
	}
	for _, arg := range calls[0][:len(calls[0])-1] {
		if strings.Contains(arg, "do shell script") {
			t.Fatalf("text leaked into the script: %q", arg)
		}
	}
	out = "button returned:, gave up:true"
	if a, _ := m.Ask(context.Background(), me.Username, "x", "y", time.Minute); a != NoAnswer {
		t.Fatalf("gave up should be no answer, got %v", a)
	}
	out = "execution error: User canceled. (-128)"
	if a, _ := m.Ask(context.Background(), me.Username, "x", "y", time.Minute); a != Declined {
		t.Fatalf("cancel should be declined, got %v", a)
	}

}
