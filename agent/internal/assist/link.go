package assist

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"time"

	"github.com/votal-ai/nexus/agent/internal/rfb"
)

// Link joins the agent (a service, which can't see the desktop) to its screen-sharing helper
// running in the signed-in person's session: the helper dials in on loopback and proves it's the
// one the agent started with a one-time secret; each proven connection serves one viewer.
type Link struct {
	ln     net.Listener
	secret []byte
	conns  chan net.Conn
}

// NewLink listens on a random loopback port.
func NewLink() (*Link, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &Link{ln: ln, secret: make([]byte, 32), conns: make(chan net.Conn, 2)}
	_, _ = rand.Read(l.secret)
	go l.accept()
	return l, nil
}

func (l *Link) Addr() string   { return l.ln.Addr().String() }
func (l *Link) Secret() string { return hex.EncodeToString(l.secret) }

func (l *Link) accept() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, len(l.secret))
			if _, err := io.ReadFull(c, got); err != nil || subtle.ConstantTimeCompare(got, l.secret) != 1 {
				c.Close() // not our helper
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			select {
			case l.conns <- c:
			default:
				c.Close() // enough waiting already
			}
		}()
	}
}

// Dial returns the next connection from the helper (an RFB server), waiting up to 15 seconds.
func (l *Link) Dial(ctx context.Context) (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(15 * time.Second):
		return nil, errors.New("the screen-sharing helper isn't answering")
	}
}

func (l *Link) Close() error {
	err := l.ln.Close()
	for {
		select {
		case c := <-l.conns:
			c.Close()
		default:
			return err
		}
	}
}

// RunHelper is the helper's side: it keeps a connection waiting at the agent and serves the
// screen on it, one viewer at a time, until the agent goes away.
func RunHelper(ctx context.Context, addr, secretHex string, screen rfb.Screen, name string) error {
	secret, err := hex.DecodeString(secretHex)
	if err != nil || len(secret) != 32 {
		return errors.New("bad helper secret")
	}
	failures := 0
	for ctx.Err() == nil {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			if failures++; failures > 5 {
				return err // the agent's session is over
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			continue
		}
		failures = 0
		if _, err := c.Write(secret); err != nil {
			c.Close()
			continue
		}
		_ = rfb.Serve(ctx, c, screen, name)
		c.Close()
	}
	return ctx.Err()
}
