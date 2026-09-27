package rfb

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeScreen struct {
	mu      sync.Mutex
	w, h    int
	px      []byte
	pointer [][3]int
	keys    [][2]uint32
}

func newScreen(w, h int) *fakeScreen {
	s := &fakeScreen{w: w, h: h, px: make([]byte, w*h*4)}
	for i := 0; i < w*h; i++ {
		s.px[i*4], s.px[i*4+1], s.px[i*4+2] = 10, 20, 30 // B, G, R
	}
	return s
}
func (s *fakeScreen) Size() (int, int) { return s.w, s.h }
func (s *fakeScreen) Capture(dst []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy(dst, s.px)
	return nil
}
func (s *fakeScreen) set(x, y int, b, g, r byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := (y*s.w + x) * 4
	s.px[i], s.px[i+1], s.px[i+2] = b, g, r
}
func (s *fakeScreen) Pointer(x, y int, buttons uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pointer = append(s.pointer, [3]int{x, y, int(buttons)})
}
func (s *fakeScreen) Key(k uint32, down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := uint32(0)
	if down {
		d = 1
	}
	s.keys = append(s.keys, [2]uint32{k, d})
}

// client is a viewer that asks for R, G, B, X bytes and zlib, as noVNC does.
type client struct {
	t    *testing.T
	c    net.Conn
	r    *bufio.Reader
	w, h int
	zin  bytes.Buffer
	zr   io.ReadCloser
}

func dial(t *testing.T, conn net.Conn) *client {
	cl := &client{t: t, c: conn, r: bufio.NewReader(conn)}
	ver := make([]byte, 12)
	cl.read(ver)
	if string(ver) != "RFB 003.008\n" {
		t.Fatalf("version %q", ver)
	}
	cl.write([]byte("RFB 003.008\n"))
	types := make([]byte, 2)
	cl.read(types)
	if types[0] != 1 || types[1] != 1 {
		t.Fatalf("security types %v", types)
	}
	cl.write([]byte{1})
	res := make([]byte, 4)
	cl.read(res)
	cl.write([]byte{1}) // shared
	init := make([]byte, 24)
	cl.read(init)
	cl.w, cl.h = int(binary.BigEndian.Uint16(init)), int(binary.BigEndian.Uint16(init[2:]))
	name := make([]byte, binary.BigEndian.Uint32(init[20:]))
	cl.read(name)
	// SetPixelFormat: 32 bpp, R at shift 0, G 8, B 16 (bytes R, G, B, X).
	pf := pixelFormat{bpp: 32, depth: 24, trueColour: true, rMax: 255, gMax: 255, bMax: 255, rShift: 0, gShift: 8, bShift: 16}
	cl.write(append([]byte{0, 0, 0, 0}, pf.bytes()...))
	cl.write([]byte{2, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 0}) // SetEncodings: zlib, raw
	return cl
}

func (cl *client) read(b []byte) {
	cl.t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(cl.r, b); err != nil {
		cl.t.Fatal(err)
	}
}
func (cl *client) write(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatal(err)
	}
}
func (cl *client) request(incremental bool) {
	b := []byte{3, 0}
	if incremental {
		b[1] = 1
	}
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(cl.w))
	b = binary.BigEndian.AppendUint16(b, uint16(cl.h))
	cl.write(b)
}

type rect struct {
	x, y, w, h int
	px         []byte
}

func (cl *client) update() []rect {
	hdr := make([]byte, 4)
	cl.read(hdr)
	if hdr[0] != 0 {
		cl.t.Fatalf("message type %d", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	var out []rect
	for i := 0; i < n; i++ {
		rh := make([]byte, 12)
		cl.read(rh)
		r := rect{x: int(binary.BigEndian.Uint16(rh)), y: int(binary.BigEndian.Uint16(rh[2:])), w: int(binary.BigEndian.Uint16(rh[4:])), h: int(binary.BigEndian.Uint16(rh[6:]))}
		if enc := int32(binary.BigEndian.Uint32(rh[8:])); enc != encZlib {
			cl.t.Fatalf("encoding %d", enc)
		}
		l := make([]byte, 4)
		cl.read(l)
		chunk := make([]byte, binary.BigEndian.Uint32(l))
		cl.read(chunk)
		cl.zin.Write(chunk)
		if cl.zr == nil {
			zr, err := zlib.NewReader(&cl.zin)
			if err != nil {
				cl.t.Fatal(err)
			}
			cl.zr = zr
		}
		r.px = make([]byte, r.w*r.h*4)
		if _, err := io.ReadFull(cl.zr, r.px); err != nil {
			cl.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestServesChangedTilesCompressedAndForwardsInput(t *testing.T) {
	screen := newScreen(150, 70) // 3x2 tiles, the edge ones partial
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, a, screen, "ana-pc") }()
	cl := dial(t, b)
	if cl.w != 150 || cl.h != 70 {
		t.Fatalf("size %dx%d", cl.w, cl.h)
	}

	cl.request(false)
	full := cl.update()
	if len(full) != 6 {
		t.Fatalf("a full update is every tile: got %d", len(full))
	}
	if p := full[0].px[:4]; !bytes.Equal(p, []byte{30, 20, 10, 0}) {
		t.Fatalf("pixel in the viewer's format (R, G, B, X): %v", p)
	}

	// One pixel changes in the bottom-right tile: only that tile is sent.
	screen.set(140, 65, 1, 2, 3)
	cl.request(true)
	inc := cl.update()
	if len(inc) != 1 || inc[0].x != 128 || inc[0].y != 64 || inc[0].w != 22 || inc[0].h != 6 {
		t.Fatalf("incremental update: %+v", inc)
	}
	i := ((65-64)*22 + (140 - 128)) * 4
	if !bytes.Equal(inc[0].px[i:i+3], []byte{3, 2, 1}) {
		t.Fatalf("changed pixel: %v", inc[0].px[i:i+3])
	}

	// Mouse and keyboard reach the screen.
	cl.write([]byte{5, 1, 0, 40, 0, 30})
	cl.write([]byte{4, 1, 0, 0, 0, 0, 0, 0x61})
	cl.write([]byte{4, 0, 0, 0, 0, 0, 0, 0x61})
	cl.request(true) // and nothing changed: an (eventually) empty update
	if got := cl.update(); len(got) != 0 {
		t.Fatalf("expected no tiles, got %d", len(got))
	}
	screen.mu.Lock()
	ptr, keys := screen.pointer, screen.keys
	screen.mu.Unlock()
	if len(ptr) != 1 || ptr[0] != [3]int{40, 30, 1} || len(keys) != 2 || keys[0] != [2]uint32{0x61, 1} || keys[1] != [2]uint32{0x61, 0} {
		t.Fatalf("input: %v %v", ptr, keys)
	}
	b.Close()
	if err := <-done; err != nil && err != io.ErrClosedPipe {
		t.Logf("server ended: %v", err)
	}
}

func TestRefusesUnsupportedPixelFormats(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), a, newScreen(10, 10), "x") }()
	cl := dial(t, b)
	_ = cl
	// 16 bpp isn't served.
	pf := pixelFormat{bpp: 16, depth: 16, trueColour: true, rMax: 31, gMax: 63, bMax: 31}
	go func() { _, _ = b.Write(append([]byte{0, 0, 0, 0}, pf.bytes()...)) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server kept going")
	}
}
