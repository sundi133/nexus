// Package assist is Remote Assist on the device: when Nexus asks (a signed command), the person
// at the Mac is asked to allow it; if they do, macOS Screen Sharing is turned on and tunnelled to
// the Nexus relay, one connection per viewer, until the session ends. Then Screen Sharing is put
// back the way it was.
package assist

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/votal-ai/nexus/agent/internal/wsock"
)

// Tunnel is one websocket to the relay.
type Tunnel interface {
	ReadMessage() (byte, []byte, error)
	WriteMessage(op byte, data []byte) error
	Close() error
}

// Answer is what the person at the Mac chose.
type Answer int

const (
	Declined Answer = iota
	Allowed
	NoAnswer
)

// Deps are the pieces that touch the OS or the network (faked in tests).
type Deps struct {
	GOOS        string
	ConsoleUser func(ctx context.Context) string
	// Ask shows the approval prompt to user and waits up to timeout.
	Ask func(ctx context.Context, user, requester, reason string, timeout time.Duration) (Answer, error)
	// Showing keeps an "End session" prompt up while the session runs; it returns when the person
	// clicks it (true) or ctx ends (false).
	Showing func(ctx context.Context, user, requester string) bool
	Notify  func(user, title, body string)
	Sharing ScreenSharing
	DialVNC func(ctx context.Context) (net.Conn, error)
	Open    func(ctx context.Context, sessionID string) (Tunnel, error)
	Report  func(ctx context.Context, sessionID, state, detail string) error
	Log     *slog.Logger
	// AskFor is how long the person has to answer (60 s by default).
	AskFor time.Duration
	// Retry is the pause between failed tunnel attempts (2 s by default).
	Retry time.Duration
}

// ScreenSharing turns macOS Screen Sharing on and off.
type ScreenSharing interface {
	On(ctx context.Context) bool
	Enable(ctx context.Context) error
	Disable(ctx context.Context) error
}

type args struct {
	SessionID string `json:"session_id"`
	Requester string `json:"requester"`
	Reason    string `json:"reason"`
	Minutes   int    `json:"minutes"`
}

var idRe = regexp.MustCompile(`^[0-9a-f-]{36}$`)

// Runner runs at most one session at a time.
type Runner struct {
	D Deps

	mu     sync.Mutex
	active string
	cancel context.CancelFunc
}

// Action is the "remote_assist" command: it checks the request and starts the session in the
// background (the person has a minute to answer, and the check-in loop shouldn't wait for them).
func (r *Runner) Action(_ context.Context, raw json.RawMessage) (string, json.RawMessage, error) {
	var a args
	if err := json.Unmarshal(raw, &a); err != nil || !idRe.MatchString(a.SessionID) {
		return "", nil, errors.New("malformed Remote Assist request")
	}
	if r.D.GOOS != "darwin" {
		return "", nil, errors.New("Remote Assist works on Macs for now")
	}
	if a.Minutes <= 0 || a.Minutes > 120 {
		a.Minutes = 60
	}
	r.mu.Lock()
	if r.active != "" {
		r.mu.Unlock()
		return "", nil, errors.New("another Remote Assist session is running on this Mac")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.Minutes)*time.Minute+5*time.Minute)
	r.active, r.cancel = a.SessionID, cancel
	r.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			r.mu.Lock()
			r.active, r.cancel = "", nil
			r.mu.Unlock()
		}()
		r.run(ctx, a)
	}()
	return "Asking the person at the Mac", nil, nil
}

func clean(s string, max int) string {
	s = strings.Map(func(c rune) rune {
		if c < 32 {
			return ' '
		}
		return c
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return strings.TrimSpace(s)
}

func (r *Runner) report(ctx context.Context, id, state, detail string) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	err := r.D.Report(rctx, id, state, detail)
	if err != nil {
		r.D.Log.Warn("remote assist: couldn't report", "state", state, "err", err)
	}
	return err
}

func (r *Runner) run(ctx context.Context, a args) {
	log := r.D.Log.With("session", a.SessionID)
	requester, reason := clean(a.Requester, 200), clean(a.Reason, 300)
	user := r.D.ConsoleUser(ctx)
	if user == "" {
		_ = r.report(ctx, a.SessionID, "failed", "Nobody is signed in to the Mac to allow it")
		return
	}
	askFor := r.D.AskFor
	if askFor == 0 {
		askFor = time.Minute
	}
	answer, err := r.D.Ask(ctx, user, requester, reason, askFor)
	switch {
	case err != nil:
		_ = r.report(ctx, a.SessionID, "failed", "Couldn't ask: "+err.Error())
		return
	case answer == Declined:
		_ = r.report(ctx, a.SessionID, "declined", "Declined by "+user)
		return
	case answer == NoAnswer:
		_ = r.report(ctx, a.SessionID, "declined", user+" didn't answer")
		return
	}

	// Screen Sharing: turned on only for the session, and back off afterwards if it was off.
	wasOn := r.D.Sharing.On(ctx)
	if !wasOn {
		if err := r.D.Sharing.Enable(ctx); err != nil {
			_ = r.report(ctx, a.SessionID, "failed", "Couldn't turn on Screen Sharing: "+err.Error())
			return
		}
	}
	defer func() {
		if !wasOn {
			if err := r.D.Sharing.Disable(context.WithoutCancel(ctx)); err != nil {
				log.Warn("remote assist: couldn't turn Screen Sharing back off", "err", err)
			}
		}
		r.D.Notify(user, "Remote Assist ended", requester+" can no longer see your screen.")
	}()
	if err := r.report(ctx, a.SessionID, "accepted", "Allowed by "+user); err != nil {
		return // withdrawn or expired meanwhile
	}
	log.Info("remote assist: allowed", "user", user, "requester", requester)

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		if r.D.Showing(ctx, user, requester) {
			log.Info("remote assist: ended at the Mac")
			_ = r.report(ctx, a.SessionID, "ended", "Ended by "+user)
			stop()
		}
	}()
	r.tunnels(ctx, a.SessionID)
}

// tunnels keeps one idle tunnel open until the relay says the session is over.
func (r *Runner) tunnels(ctx context.Context, id string) {
	retry := r.D.Retry
	if retry == 0 {
		retry = 2 * time.Second
	}
	failures := 0
	for ctx.Err() == nil {
		t, err := r.D.Open(ctx, id)
		if err != nil {
			var he *wsock.HTTPError
			if errors.As(err, &he) && (he.Status == 410 || he.Status == 401 || he.Status == 404) {
				r.D.Log.Info("remote assist: session over", "status", he.Status)
				return
			}
			if failures++; failures > 60 {
				_ = r.report(ctx, id, "failed", "Lost the connection to Nexus")
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
			continue
		}
		failures = 0
		r.serve(ctx, t)
	}
}

// serve waits for "open", then pipes the tunnel to the Mac's Screen Sharing until either side ends.
func (r *Runner) serve(ctx context.Context, t Tunnel) {
	defer t.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() { // a session ending closes the tunnel mid-read
		select {
		case <-ctx.Done():
			t.Close()
		case <-finished:
		}
	}()
	op, msg, err := t.ReadMessage()
	if err != nil || op != wsock.OpText || string(msg) != "open" {
		return
	}
	vnc, err := r.D.DialVNC(ctx)
	if err != nil {
		r.D.Log.Warn("remote assist: Screen Sharing isn't answering", "err", err)
		return
	}
	defer vnc.Close()
	done := make(chan struct{}, 2)
	go func() { // Mac → viewer
		buf := make([]byte, 64<<10)
		for {
			n, err := vnc.Read(buf)
			if n > 0 {
				if werr := t.WriteMessage(wsock.OpBinary, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() { // viewer → Mac
		for {
			op, data, err := t.ReadMessage()
			if err != nil {
				break
			}
			if op == wsock.OpBinary {
				if _, err := vnc.Write(data); err != nil {
					break
				}
			}
		}
		done <- struct{}{}
	}()
	<-done
}
