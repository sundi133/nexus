package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agent/releases/0.2.0/bin":
			_, _ = w.Write([]byte("binary"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	body, err := c.Download(ctx, "/v1/agent/releases/0.2.0/bin", 100)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != "binary" {
		t.Fatalf("got %q", data)
	}
	if _, err := c.Download(ctx, "/v1/agent/releases/0.2.0/bin", 3); err == nil {
		t.Error("larger than promised: accepted")
	}
	if _, err := c.Download(ctx, "/missing", 100); err == nil {
		t.Error("404 accepted")
	}
	for _, p := range []string{"https://evil.example.com/x", "//evil.example.com/x", "relative"} {
		if _, err := c.Download(ctx, p, 100); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}
