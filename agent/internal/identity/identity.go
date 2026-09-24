// Package identity holds the device's key pair and produces request proofs.
//
// The device key (ECDSA P-256) is generated on the device and never leaves it.
// Every API request carries a short-lived ES256 JWT that binds the request's
// method, path and body hash to that key (see apps/api/src/devices/agent-api.ts).
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const (
	audience = "nexus-agent"
	jwtType  = "nexus-device+jwt"
	lifetime = 2 * time.Minute
)

type Key struct{ priv *ecdsa.PrivateKey }

// JWK is the public key in the form the server registers (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func Generate() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

func (k *Key) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParsePEM(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("device key: not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("device key: expected an ECDSA P-256 key")
	}
	return &Key{priv: priv}, nil
}

func (k *Key) PublicJWK() (JWK, error) {
	pub, err := k.priv.PublicKey.ECDH()
	if err != nil {
		return JWK{}, err
	}
	raw := pub.Bytes() // 0x04 || X (32) || Y (32)
	if len(raw) != 65 {
		return JWK{}, fmt.Errorf("unexpected public key length %d", len(raw))
	}
	enc := base64.RawURLEncoding
	return JWK{Kty: "EC", Crv: "P-256", X: enc.EncodeToString(raw[1:33]), Y: enc.EncodeToString(raw[33:])}, nil
}

// Proof builds the NexusDevice proof for one request. For enrollment pass
// deviceID == "" and the public key is embedded in the header instead.
func (k *Key) Proof(deviceID, method, path string, body []byte, now time.Time) (string, error) {
	header := map[string]any{"alg": "ES256", "typ": jwtType}
	if deviceID == "" {
		jwk, err := k.PublicJWK()
		if err != nil {
			return "", err
		}
		header["jwk"] = jwk
	} else {
		header["kid"] = deviceID
	}
	sum := sha256.Sum256(body)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{
		"aud": audience,
		"htm": method,
		"htu": path,
		"bsh": base64.RawURLEncoding.EncodeToString(sum[:]),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
	}
	return k.sign(header, claims)
}

// Attest signs a browser's device-trust nonce, bound to the web origin that
// asked, so the server can tie a sign-in session to this device. Only the
// agent's loopback server calls this, and only for the enrolled web origin.
func (k *Key) Attest(deviceID, nonce, origin string, now time.Time) (string, error) {
	return k.sign(
		map[string]any{"alg": "ES256", "typ": jwtType, "kid": deviceID},
		map[string]any{"aud": "nexus-device-attest", "nonce": nonce, "origin": origin, "iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix()},
	)
}

func (k *Key) sign(header, claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		return "", err
	}
	// JWS ES256 signatures are the fixed-width concatenation R || S (RFC 7518 §3.4), not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + enc.EncodeToString(sig), nil
}
