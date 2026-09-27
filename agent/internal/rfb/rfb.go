// Package rfb is a small RFB (VNC) server, for Remote Assist on Windows, where the OS has no VNC
// server to tunnel to. It serves one Screen: the framebuffer in 64-pixel tiles, sending only the
// tiles that changed, zlib-compressed when the viewer takes it (noVNC does); and the viewer's
// keyboard and mouse. There's no RFB authentication: the connection only ever comes through the
// Nexus relay, which has already checked who's viewing and that the person at the computer agreed.
package rfb

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Screen is what's being shared.
type Screen interface {
	// Size is the framebuffer's size in pixels.
	Size() (w, h int)
	// Capture fills dst (w*h*4 bytes, rows top to bottom) with the screen as B, G, R, X bytes.
	Capture(dst []byte) error
	// Pointer moves the mouse to (x, y) with the given buttons down (bit 0 left, 1 middle, 2 right,
	// 3/4 wheel up/down).
	Pointer(x, y int, buttons uint8)
	// Key presses or releases an X11 keysym.
	Key(keysym uint32, down bool)
}

const (
	tile          = 64
	encRaw        = 0
	encZlib       = 6
	pollEvery     = 80 * time.Millisecond
	maxQuietWait  = 2 * time.Second
	maxFrameBytes = 64 << 20
)

type pixelFormat struct {
	bpp, depth             uint8
	bigEndian, trueColour  bool
	rMax, gMax, bMax       uint16
	rShift, gShift, bShift uint8
}

// The server's native format: little-endian B, G, R, X, which is how Windows captures.
var native = pixelFormat{bpp: 32, depth: 24, trueColour: true, rMax: 255, gMax: 255, bMax: 255, rShift: 16, gShift: 8, bShift: 0}

func (p pixelFormat) bytes() []byte {
	b := make([]byte, 16)
	b[0], b[1] = p.bpp, p.depth
	if p.bigEndian {
		b[2] = 1
	}
	if p.trueColour {
		b[3] = 1
	}
	binary.BigEndian.PutUint16(b[4:], p.rMax)
	binary.BigEndian.PutUint16(b[6:], p.gMax)
	binary.BigEndian.PutUint16(b[8:], p.bMax)
	b[10], b[11], b[12] = p.rShift, p.gShift, p.bShift
	return b
}

func readPixelFormat(b []byte) pixelFormat {
	return pixelFormat{bpp: b[0], depth: b[1], bigEndian: b[2] != 0, trueColour: b[3] != 0, rMax: binary.BigEndian.Uint16(b[4:]), gMax: binary.BigEndian.Uint16(b[6:]), bMax: binary.BigEndian.Uint16(b[8:]), rShift: b[10], gShift: b[11], bShift: b[12]}
}

type request struct {
	incremental bool
	x, y, w, h  int
}

type server struct {
	rw     io.ReadWriter
	screen Screen
	w, h   int

	mu      sync.Mutex
	pf      pixelFormat
	zlibOK  bool
	pending *request
	wake    chan struct{}

	prev []byte
	cur  []byte
	zbuf bytes.Buffer
	zw   *zlib.Writer
}

// Serve speaks RFB 3.8 (also 3.3 and 3.7) on conn until either side ends it.
func Serve(ctx context.Context, conn io.ReadWriteCloser, screen Screen, name string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	s := &server{rw: conn, screen: screen, pf: native, wake: make(chan struct{}, 1)}
	br := bufio.NewReader(conn)
	if err := s.handshake(br, name); err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- s.readLoop(br) }()
	go func() { errc <- s.writeLoop(ctx) }()
	err := <-errc
	cancel()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (s *server) handshake(br *bufio.Reader, name string) error {
	if _, err := io.WriteString(s.rw, "RFB 003.008\n"); err != nil {
		return err
	}
	ver := make([]byte, 12)
	if _, err := io.ReadFull(br, ver); err != nil {
		return err
	}
	var minor int
	if _, err := fmt.Sscanf(string(ver), "RFB 003.%03d\n", &minor); err != nil {
		return fmt.Errorf("not an RFB client: %q", ver)
	}
	if minor >= 7 {
		// One security type: None. The relay in front of this is the authentication.
		if _, err := s.rw.Write([]byte{1, 1}); err != nil {
			return err
		}
		choice, err := br.ReadByte()
		if err != nil {
			return err
		}
		if choice != 1 {
			return fmt.Errorf("client chose security type %d", choice)
		}
		if minor >= 8 {
			if _, err := s.rw.Write([]byte{0, 0, 0, 0}); err != nil {
				return err
			}
		}
	} else if _, err := s.rw.Write([]byte{0, 0, 0, 1}); err != nil {
		return err
	}
	if _, err := br.ReadByte(); err != nil { // ClientInit: shared flag
		return err
	}
	s.w, s.h = s.screen.Size()
	if s.w <= 0 || s.h <= 0 || s.w > 16384 || s.h > 16384 || s.w*s.h*4 > maxFrameBytes {
		return fmt.Errorf("unusable screen size %dx%d", s.w, s.h)
	}
	s.prev = make([]byte, s.w*s.h*4)
	s.cur = make([]byte, s.w*s.h*4)
	init := make([]byte, 4, 24+len(name))
	binary.BigEndian.PutUint16(init[0:], uint16(s.w))
	binary.BigEndian.PutUint16(init[2:], uint16(s.h))
	init = append(init, native.bytes()...)
	init = binary.BigEndian.AppendUint32(init, uint32(len(name)))
	init = append(init, name...)
	_, err := s.rw.Write(init)
	return err
}

func (s *server) readLoop(br *bufio.Reader) error {
	for {
		t, err := br.ReadByte()
		if err != nil {
			return err
		}
		switch t {
		case 0: // SetPixelFormat
			b := make([]byte, 19)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			pf := readPixelFormat(b[3:])
			if pf.bpp != 32 || !pf.trueColour || pf.rMax != 255 || pf.gMax != 255 || pf.bMax != 255 {
				return fmt.Errorf("unsupported pixel format (%d bpp)", pf.bpp)
			}
			s.mu.Lock()
			s.pf = pf
			s.mu.Unlock()
		case 2: // SetEncodings
			b := make([]byte, 3)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			n := int(binary.BigEndian.Uint16(b[1:]))
			encs := make([]byte, 4*n)
			if _, err := io.ReadFull(br, encs); err != nil {
				return err
			}
			zl := false
			for i := 0; i < n; i++ {
				if int32(binary.BigEndian.Uint32(encs[4*i:])) == encZlib {
					zl = true
				}
			}
			s.mu.Lock()
			s.zlibOK = zl
			s.mu.Unlock()
		case 3: // FramebufferUpdateRequest
			b := make([]byte, 9)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			r := request{incremental: b[0] != 0, x: int(binary.BigEndian.Uint16(b[1:])), y: int(binary.BigEndian.Uint16(b[3:])), w: int(binary.BigEndian.Uint16(b[5:])), h: int(binary.BigEndian.Uint16(b[7:]))}
			s.mu.Lock()
			// A full request isn't downgraded by a later incremental one.
			if s.pending == nil || !r.incremental {
				s.pending = &r
			}
			s.mu.Unlock()
			select {
			case s.wake <- struct{}{}:
			default:
			}
		case 4: // KeyEvent
			b := make([]byte, 7)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			s.screen.Key(binary.BigEndian.Uint32(b[3:]), b[0] != 0)
		case 5: // PointerEvent
			b := make([]byte, 5)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			x, y := int(binary.BigEndian.Uint16(b[1:])), int(binary.BigEndian.Uint16(b[3:]))
			s.screen.Pointer(min(x, s.w-1), min(y, s.h-1), b[0])
		case 6: // ClientCutText: not shared (the clipboard stays on each side)
			b := make([]byte, 7)
			if _, err := io.ReadFull(br, b); err != nil {
				return err
			}
			n := int64(binary.BigEndian.Uint32(b[3:]))
			if n > 1<<20 {
				return errors.New("clipboard text too large")
			}
			if _, err := io.CopyN(io.Discard, br, n); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported RFB message %d", t)
		}
	}
}

func (s *server) writeLoop(ctx context.Context) error {
	sent := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.wake:
		}
		s.mu.Lock()
		r := s.pending
		s.pending = nil
		s.mu.Unlock()
		if r == nil {
			continue
		}
		full := !r.incremental || !sent
		var rects [][4]int
		deadline := time.Now().Add(maxQuietWait)
		for {
			if err := s.screen.Capture(s.cur); err != nil {
				return err
			}
			if w, h := s.screen.Size(); w != s.w || h != s.h {
				return errors.New("the screen size changed: reconnect")
			}
			rects = s.changed(*r, full)
			if len(rects) > 0 || time.Now().After(deadline) {
				break
			}
			// Nothing changed yet: look again shortly, unless a full update is asked for meanwhile.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pollEvery):
			case <-s.wake:
				s.mu.Lock()
				if s.pending != nil && !s.pending.incremental {
					full = true
					s.pending = nil
				}
				s.mu.Unlock()
			}
		}
		if err := s.send(rects); err != nil {
			return err
		}
		// What the viewer now has: only the tiles sent (a partial request leaves the rest pending).
		for _, r := range rects {
			for row := r[1]; row < r[1]+r[3]; row++ {
				i := (row*s.w + r[0]) * 4
				copy(s.prev[i:i+r[2]*4], s.cur[i:i+r[2]*4])
			}
		}
		sent = true
	}
}

// changed lists the tiles inside the requested region that differ from what was last sent.
func (s *server) changed(r request, full bool) [][4]int {
	x0, y0 := max(0, r.x), max(0, r.y)
	x1, y1 := min(s.w, r.x+r.w), min(s.h, r.y+r.h)
	var out [][4]int
	for ty := y0; ty < y1; ty += tile {
		for tx := x0; tx < x1; tx += tile {
			w, h := min(tile, x1-tx), min(tile, y1-ty)
			if full || s.differs(tx, ty, w, h) {
				out = append(out, [4]int{tx, ty, w, h})
			}
		}
	}
	return out
}

func (s *server) differs(x, y, w, h int) bool {
	for row := y; row < y+h; row++ {
		i := (row*s.w + x) * 4
		if !bytes.Equal(s.cur[i:i+w*4], s.prev[i:i+w*4]) {
			return true
		}
	}
	return false
}

// pixels copies a rectangle out of cur in the client's pixel format.
func (s *server) pixels(x, y, w, h int, pf pixelFormat) []byte {
	out := make([]byte, 0, w*h*4)
	for row := y; row < y+h; row++ {
		src := s.cur[(row*s.w+x)*4 : (row*s.w+x+w)*4]
		for i := 0; i < len(src); i += 4 {
			b, g, r := uint32(src[i]), uint32(src[i+1]), uint32(src[i+2])
			v := r<<pf.rShift | g<<pf.gShift | b<<pf.bShift
			if pf.bigEndian {
				out = binary.BigEndian.AppendUint32(out, v)
			} else {
				out = binary.LittleEndian.AppendUint32(out, v)
			}
		}
	}
	return out
}

func (s *server) send(rects [][4]int) error {
	s.mu.Lock()
	pf, useZlib := s.pf, s.zlibOK
	s.mu.Unlock()
	msg := []byte{0, 0}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rects)))
	for _, r := range rects {
		msg = binary.BigEndian.AppendUint16(msg, uint16(r[0]))
		msg = binary.BigEndian.AppendUint16(msg, uint16(r[1]))
		msg = binary.BigEndian.AppendUint16(msg, uint16(r[2]))
		msg = binary.BigEndian.AppendUint16(msg, uint16(r[3]))
		px := s.pixels(r[0], r[1], r[2], r[3], pf)
		if !useZlib {
			msg = binary.BigEndian.AppendUint32(msg, encRaw)
			msg = append(msg, px...)
			continue
		}
		// One zlib stream for the whole connection, flushed after each rectangle.
		if s.zw == nil {
			s.zw = zlib.NewWriter(&s.zbuf)
		}
		s.zbuf.Reset()
		if _, err := s.zw.Write(px); err != nil {
			return err
		}
		if err := s.zw.Flush(); err != nil {
			return err
		}
		msg = binary.BigEndian.AppendUint32(msg, encZlib)
		msg = binary.BigEndian.AppendUint32(msg, uint32(s.zbuf.Len()))
		msg = append(msg, s.zbuf.Bytes()...)
	}
	_, err := s.rw.Write(msg)
	return err
}
