package wsock

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "NexusDevice x" {
			http.Error(w, "session over", http.StatusGone)
			return
		}
		c, err := Accept(w, r)
		if err != nil {
			return
		}
		_ = c.writeFrame(opPing, []byte("hi")) // the client answers pings by itself
		for {
			op, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			if string(data) == "bye" {
				c.CloseCode(1000, "done")
				return
			}
			_ = c.WriteMessage(op, data)
		}
	}))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Dial(ctx, url, http.Header{})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 410 {
		t.Fatalf("want a 410 refusal, got %v", err)
	}

	c, err := Dial(ctx, url, http.Header{"Authorization": {"NexusDevice x"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{5, 200, 70_000} { // each length encoding
		msg := bytes.Repeat([]byte{7}, size)
		if err := c.WriteMessage(OpBinary, msg); err != nil {
			t.Fatal(err)
		}
		op, got, err := c.ReadMessage()
		if err != nil || op != OpBinary || !bytes.Equal(got, msg) {
			t.Fatalf("size %d: op %d, %d bytes, %v", size, op, len(got), err)
		}
	}
	_ = c.WriteMessage(OpText, []byte("bye"))
	if _, _, err := c.ReadMessage(); err != io.EOF {
		t.Fatalf("want EOF after the server closes, got %v", err)
	}
}
