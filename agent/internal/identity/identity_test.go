package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestProofVerifiesWithPublicKey(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"hello":"world"}`)
	tok, err := k.Proof("0190-device", "POST", "/v1/agent/checkin", body, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(parts))
	}
	enc := base64.RawURLEncoding
	sig, _ := enc.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("ES256 signature must be 64 bytes, got %d", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&k.priv.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify")
	}

	var claims map[string]any
	raw, _ := enc.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &claims)
	sum := sha256.Sum256(body)
	if claims["bsh"] != enc.EncodeToString(sum[:]) || claims["htu"] != "/v1/agent/checkin" || claims["aud"] != "nexus-agent" {
		t.Fatalf("unexpected claims: %v", claims)
	}
	if claims["exp"].(float64)-claims["iat"].(float64) > 300 {
		t.Fatal("lifetime must stay within the server's 5 minute limit")
	}
	var header map[string]any
	rawH, _ := enc.DecodeString(parts[0])
	_ = json.Unmarshal(rawH, &header)
	if header["kid"] != "0190-device" || header["typ"] != "nexus-device+jwt" {
		t.Fatalf("unexpected header: %v", header)
	}
}

func TestEnrollProofEmbedsPublicKeyAndPEMRoundTrips(t *testing.T) {
	k, _ := Generate()
	tok, err := k.Proof("", "POST", "/v1/agent/enroll", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		JWK JWK `json:"jwk"`
		Kid string
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	_ = json.Unmarshal(raw, &header)
	want, _ := k.PublicJWK()
	if header.JWK != want || header.Kid != "" || len(want.X) != 43 || len(want.Y) != 43 {
		t.Fatalf("header jwk %+v, want %+v", header.JWK, want)
	}
	pemBytes, _ := k.MarshalPEM()
	back, err := ParsePEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := back.PublicJWK(); got != want {
		t.Fatal("key changed after PEM round trip")
	}
}
