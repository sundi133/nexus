// Package local is the agent's loopback server for browser device trust.
//
// The Nexus console (and only the Nexus console) asks it to sign a one-time
// nonce with the device key, proving to the server that the browser session
// is running on this enrolled device. It listens on 127.0.0.1 only and
// answers only the enrolled web origin: browsers set Origin themselves, so
// another website can't obtain an attestation, and the origin is part of the
// signed statement so the server can check it too.
package local

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/votal-ai/nexus/agent/internal/identity"
)

// Addr is fixed so the console knows where to find the agent.
const Addr = "127.0.0.1:47823"

type Server struct {
	Key      *identity.Key
	DeviceID string
	// Origin returns the one web origin allowed to ask (it can change on check-in).
	Origin func() string
	Log    *slog.Logger
	Now    func() time.Time
}

var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// DNS rebinding: a hostile name resolving to 127.0.0.1 would carry its own Host.
	if host, _, _ := net.SplitHostPort(r.Host); host != "127.0.0.1" && host != "localhost" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	origin := r.Header.Get("Origin")
	allowed := s.Origin()
	if allowed == "" || origin != allowed {
		s.Log.Warn("refused local request", "origin", origin, "path", r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Vary", "Origin")
	h.Set("Cache-Control", "no-store")

	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		// Chrome's Private Network Access: a public site reaching loopback must be explicitly allowed.
		if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
			h.Set("Access-Control-Allow-Private-Network", "true")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
		writeJSON(w, http.StatusOK, map[string]any{"device_id": s.DeviceID})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/attest":
		var in struct {
			Nonce string `json:"nonce"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		if err := dec.Decode(&in); err != nil || !nonceRE.MatchString(in.Nonce) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid nonce"})
			return
		}
		att, err := s.Key.Attest(s.DeviceID, in.Nonce, origin, s.now())
		if err != nil {
			s.Log.Error("attestation failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing failed"})
			return
		}
		s.Log.Info("attested device to the console", "origin", origin)
		writeJSON(w, http.StatusOK, map[string]string{"device_id": s.DeviceID, "attestation": att})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Listen binds the loopback address. Another agent instance (or anything
// else) holding the port is reported, not fatal: check-ins still work.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", Addr)
	if err != nil && strings.Contains(err.Error(), "address already in use") {
		return nil, errors.New("port 47823 is in use (is another nexus-agent running?); browser device checks will be unavailable")
	}
	return ln, err
}

// Serve runs until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	err := srv.Serve(ln)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
