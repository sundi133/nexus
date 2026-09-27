package assist

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type oneColour struct{}

func (oneColour) Size() (int, int)         { return 4, 4 }
func (oneColour) Capture(dst []byte) error { return nil }
func (oneColour) Pointer(int, int, uint8)  {}
func (oneColour) Key(uint32, bool)         {}

func TestLinkServesTheHelpersScreenAndRefusesStrangers(t *testing.T) {
	l, err := NewLink()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A stranger on loopback without the secret gets nothing.
	stranger, _ := net.Dial("tcp", l.Addr())
	_, _ = stranger.Write(make([]byte, 32))
	_ = stranger.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stranger.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection without the secret was served")
	}

	go func() { _ = RunHelper(ctx, l.Addr(), l.Secret(), oneColour{}, "ana-pc") }()
	for round := 0; round < 2; round++ { // one viewer after another
		c, err := l.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ver := make([]byte, 12)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(bufio.NewReader(c), ver); err != nil || string(ver) != "RFB 003.008\n" {
			t.Fatalf("round %d: %q %v", round, ver, err)
		}
		c.Close()
	}
	if err := RunHelper(ctx, l.Addr(), "short", oneColour{}, "x"); err == nil {
		t.Fatal("a bad secret should be refused")
	}
}
