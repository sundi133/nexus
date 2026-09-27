// Package wsock is a small WebSocket (RFC 6455) client, enough for the Remote Assist tunnel:
// binary and text messages, ping/pong and close. The agent has no other dependencies to pull one in
// for. Accept serves the other side, for tests.
package wsock

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	OpText   = 1
	OpBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10

	maxMessage = 16 << 20
	magic      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// HTTPError is a refused upgrade: the server answered with a status instead of switching.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("websocket refused: HTTP %d %s", e.Status, e.Body)
}

// Conn is one WebSocket connection. Reads come from one goroutine; writes may come from several.
type Conn struct {
	c      net.Conn
	r      *bufio.Reader
	client bool // clients mask what they send
	wmu    sync.Mutex
	closed bool
}

func accept(key string) string {
	h := sha1.Sum([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Dial opens a WebSocket to a ws:// or wss:// URL with extra request headers.
func Dial(ctx context.Context, rawURL string, header http.Header) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	var d net.Dialer
	var c net.Conn
	switch u.Scheme {
	case "wss":
		c, err = (&tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", host)
	case "ws":
		c, err = d.DialContext(ctx, "tcp", host)
	default:
		return nil, fmt.Errorf("not a websocket URL: %s", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	key := base64.StdEncoding.EncodeToString(nonce)
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: u.Path, RawQuery: u.RawQuery}, Host: u.Host, Header: http.Header{}, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	r := bufio.NewReader(c)
	res, err := http.ReadResponse(r, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2000))
		c.Close()
		return nil, &HTTPError{Status: res.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if res.Header.Get("Sec-WebSocket-Accept") != accept(key) {
		c.Close()
		return nil, errors.New("websocket handshake: bad Sec-WebSocket-Accept")
	}
	_ = c.SetDeadline(time.Time{})
	return &Conn{c: c, r: r, client: true}, nil
}

// Accept upgrades a server-side HTTP request (for tests).
func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return nil, errors.New("not a websocket request")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("can't hijack")
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept(key) + "\r\n\r\n")
	if err := rw.Flush(); err != nil {
		c.Close()
		return nil, err
	}
	return &Conn{c: c, r: rw.Reader}, nil
}

func (c *Conn) writeFrame(op byte, data []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	hdr := []byte{0x80 | op, 0}
	n := len(data)
	switch {
	case n < 126:
		hdr[1] = byte(n)
	case n <= 0xffff:
		hdr[1] = 126
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr[1] = 127
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	payload := data
	if c.client {
		hdr[1] |= 0x80
		mask := make([]byte, 4)
		_, _ = rand.Read(mask)
		hdr = append(hdr, mask...)
		payload = make([]byte, n)
		for i := range data {
			payload[i] = data[i] ^ mask[i%4]
		}
	}
	if _, err := c.c.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

// WriteMessage sends one text or binary message.
func (c *Conn) WriteMessage(op byte, data []byte) error { return c.writeFrame(op, data) }

// ReadMessage returns the next text or binary message, answering pings on the way. A close from
// the other side comes back as io.EOF.
func (c *Conn) ReadMessage() (byte, []byte, error) {
	var msg []byte
	var msgOp byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.r, h[:]); err != nil {
			return 0, nil, err
		}
		fin, op, masked := h[0]&0x80 != 0, h[0]&0x0f, h[1]&0x80 != 0
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.r, b[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.r, b[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > maxMessage || uint64(len(msg))+n > maxMessage {
			return 0, nil, errors.New("websocket message too large")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.r, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(c.r, data); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range data {
				data[i] ^= mask[i%4]
			}
		}
		switch op {
		case opPing:
			_ = c.writeFrame(opPong, data)
			continue
		case opPong:
			continue
		case opClose:
			_ = c.writeFrame(opClose, data) // echo it, as the protocol asks
			c.Close()
			return 0, nil, io.EOF
		case 0: // continuation
		default:
			msgOp = op
		}
		msg = append(msg, data...)
		if fin {
			return msgOp, msg, nil
		}
	}
}

// CloseCode is a normal close (1000) sent before the connection is dropped.
func (c *Conn) CloseCode(code uint16, reason string) {
	_ = c.writeFrame(opClose, append(binary.BigEndian.AppendUint16(nil, code), reason...))
	c.Close()
}

// Close drops the connection.
func (c *Conn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.c.Close()
}
