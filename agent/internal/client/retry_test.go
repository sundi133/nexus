package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/votal-ai/nexus/agent/internal/identity"
)

func TestBusyServerRetryAfter(t *testing.T) {
	var header string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", header)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":503,"code":"busy","title":"The server is busy"}`))
	}))
	defer srv.Close()
	key, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, key, "dev_1")
	if err != nil {
		t.Fatal(err)
	}
	for ra, want := range map[string]time.Duration{"17": 17 * time.Second, "": 0, "soon": 0, "99999": 10 * time.Minute} {
		header = ra
		err := c.Events(context.Background(), map[string]any{})
		if got := RetryAfter(err); got != want {
			t.Errorf("Retry-After %q: got %s, want %s (err %v)", ra, got, want, err)
		}
	}
}
