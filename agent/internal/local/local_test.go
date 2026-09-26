package local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/votal-ai/nexus/agent/internal/identity"
)

const console = "https://nexus.example.com"

func newServer(t *testing.T) (*Server, *identity.Key) {
	t.Helper()
	k, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Key: k, DeviceID: "01a0d373-e8d6-735c-8ada-62ed92e2c142",
		Origin: func() string { return console },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return time.Unix(1_700_000_000, 0) },
	}, k
}

func do(s *Server, method, host, origin, body string, hdr map[string]string) *httptest.ResponseRecorder {
	return doPath(s, method, host, "/v1/attest", origin, body, hdr)
}

func doPath(s *Server, method, host, path, origin, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// verify checks an ES256 JWS against the key the way the server does, and returns its parts.
func verify(t *testing.T, k *identity.Key, tok string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	enc := base64.RawURLEncoding
	jwk, _ := k.PublicJWK()
	x, _ := enc.DecodeString(jwk.X)
	y, _ := enc.DecodeString(jwk.Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	sig, _ := enc.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
	h, _ := enc.DecodeString(parts[0])
	c, _ := enc.DecodeString(parts[1])
	_ = json.Unmarshal(h, &header)
	_ = json.Unmarshal(c, &claims)
	return
}

func TestAttestsForTheConsole(t *testing.T) {
	s, k := newServer(t)
	nonce := "c2FtcGxlLW5vbmNlLTMyLWJ5dGVzLWxvbmctZW5vdWdo"
	rec := do(s, http.MethodPost, Addr, console, `{"nonce":"`+nonce+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != console {
		t.Fatalf("ACAO = %q", got)
	}
	var out struct{ DeviceID, Attestation string }
	_ = json.Unmarshal(rec.Body.Bytes(), &struct {
		DeviceID    *string `json:"device_id"`
		Attestation *string `json:"attestation"`
	}{&out.DeviceID, &out.Attestation})
	if out.DeviceID != s.DeviceID {
		t.Fatalf("device_id = %q", out.DeviceID)
	}
	h, c := verify(t, k, out.Attestation)
	if h["kid"] != s.DeviceID || h["typ"] != "nexus-device+jwt" || h["alg"] != "ES256" {
		t.Fatalf("header %v", h)
	}
	if c["aud"] != "nexus-device-attest" || c["nonce"] != nonce || c["origin"] != console {
		t.Fatalf("claims %v", c)
	}
	if c["exp"].(float64)-c["iat"].(float64) != 60 {
		t.Fatalf("lifetime %v", c)
	}
}

func TestRefusesOtherOrigins(t *testing.T) {
	s, _ := newServer(t)
	body := `{"nonce":"c2FtcGxlLW5vbmNlLTMyLWJ5dGVz"}`
	for _, origin := range []string{"", "https://evil.example.com", "https://nexus.example.com.evil.com", "http://nexus.example.com", "null"} {
		if rec := do(s, http.MethodPost, Addr, origin, body, nil); rec.Code != http.StatusForbidden {
			t.Errorf("origin %q: status %d", origin, rec.Code)
		} else if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("origin %q got CORS headers", origin)
		}
	}
}

func TestRefusesBeforeTheOriginIsKnown(t *testing.T) {
	s, _ := newServer(t)
	s.Origin = func() string { return "" } // enrolled with an older server that didn't say
	if rec := do(s, http.MethodPost, Addr, "", `{"nonce":"c2FtcGxlLW5vbmNlLTMyLWJ5dGVz"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRefusesRebindingHosts(t *testing.T) {
	s, _ := newServer(t)
	if rec := do(s, http.MethodPost, "attacker.example.com:47823", console, `{"nonce":"c2FtcGxlLW5vbmNlLTMyLWJ5dGVz"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := do(s, http.MethodPost, "localhost:47823", console, `{"nonce":"c2FtcGxlLW5vbmNlLTMyLWJ5dGVz"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("localhost: status %d", rec.Code)
	}
}

func TestPreflightAllowsPrivateNetworkAccess(t *testing.T) {
	s, _ := newServer(t)
	rec := do(s, http.MethodOptions, Addr, console, "", map[string]string{
		"Access-Control-Request-Method":          "POST",
		"Access-Control-Request-Private-Network": "true",
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	for k, want := range map[string]string{
		"Access-Control-Allow-Origin":          console,
		"Access-Control-Allow-Private-Network": "true",
		"Access-Control-Allow-Headers":         "Content-Type",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if rec := do(s, http.MethodOptions, Addr, "https://evil.example.com", "", map[string]string{"Access-Control-Request-Private-Network": "true"}); rec.Code != http.StatusForbidden {
		t.Fatalf("hostile preflight: status %d", rec.Code)
	}
}

func TestRejectsBadNonces(t *testing.T) {
	s, _ := newServer(t)
	for _, body := range []string{`{}`, `{"nonce":"short"}`, `{"nonce":"has spaces and / slashes!!!!"}`, `not json`, `{"nonce":"` + strings.Repeat("a", 2000) + `"}`} {
		if rec := do(s, http.MethodPost, Addr, console, body, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%.30q: status %d", body, rec.Code)
		}
	}
}

func TestStatus(t *testing.T) {
	s, _ := newServer(t)
	rec := doPath(s, http.MethodGet, Addr, "/v1/status", console, "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), s.DeviceID) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}
