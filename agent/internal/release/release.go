// Package release defines signed agent releases (DEV-07).
//
// Each artifact (one binary per OS/arch) is signed on its own with an Ed25519
// release key held by the Nexus release pipeline, never by the API server.
// The agent verifies against public keys compiled into it, so a compromised
// server or CDN can offer an update but can't make the agent run code the
// release key didn't sign.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Artifact is one downloadable binary in a release.
type Artifact struct {
	OS        string `json:"os"`   // GOOS
	Arch      string `json:"arch"` // GOARCH
	File      string `json:"file"`
	SHA256    string `json:"sha256"` // hex
	Size      int64  `json:"size"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64 Ed25519 over Statement()
}

// Manifest is release.json, written next to the artifacts.
type Manifest struct {
	Version     string     `json:"version"`
	PublishedAt string     `json:"published_at"`
	Notes       string     `json:"notes"`
	Artifacts   []Artifact `json:"artifacts"`
}

// Statement is exactly what the release key signs for one artifact.
func Statement(version, goos, goarch, sha256hex string, size int64) []byte {
	return []byte(fmt.Sprintf("nexus-agent-release-v1\n%s\n%s/%s\n%s\n%d", version, goos, goarch, strings.ToLower(sha256hex), size))
}

// KeyID names a public key: the first 8 bytes of its SHA-256, hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParseKeys reads comma-separated base64 raw Ed25519 public keys.
func ParseKeys(s string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid release public key %q", part)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

func Sign(priv ed25519.PrivateKey, version, goos, goarch, sha256hex string, size int64) (keyID, sig string) {
	pub := priv.Public().(ed25519.PublicKey)
	return KeyID(pub), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Statement(version, goos, goarch, sha256hex, size)))
}

var ErrUntrusted = errors.New("release signature is not from a trusted release key")

// Verify checks an artifact's signature for a version against trusted keys.
func Verify(keys []ed25519.PublicKey, version string, a Artifact) error {
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrUntrusted
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil || len(a.SHA256) != 64 {
		return fmt.Errorf("invalid sha256 %q", a.SHA256)
	}
	msg := Statement(version, a.OS, a.Arch, a.SHA256, a.Size)
	for _, k := range keys {
		if KeyID(k) == a.KeyID && ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return ErrUntrusted
}

// Compare orders versions like 1.2.3 and 1.2.3-rc.1 (a pre-release sorts
// before its release). It returns -1, 0 or 1; unparseable versions sort first.
func Compare(a, b string) int {
	pa, preA, okA := parse(a)
	pb, preB, okB := parse(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case preA == preB:
		return 0
	case preA == "":
		return 1
	case preB == "":
		return -1
	}
	return strings.Compare(preA, preB)
}

func parse(v string) ([3]int, string, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, "", false
		}
		out[i] = n
	}
	return out, pre, true
}

// Offer is what the server sends in a check-in when this device should update.
type Offer struct {
	Version   string `json:"version"`
	URL       string `json:"url"` // path on the Nexus server
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Result is what the agent reports back about an update attempt.
type Result struct {
	Version string `json:"version"`
	State   string `json:"state"` // installed | failed | rolled_back
	Error   string `json:"error,omitempty"`
}
