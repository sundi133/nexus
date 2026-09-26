package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	kid, sig := Sign(priv, "1.2.0", "darwin", "arm64", sum, 1234)
	a := Artifact{OS: "darwin", Arch: "arm64", SHA256: sum, Size: 1234, KeyID: kid, Signature: sig}
	if err := Verify([]ed25519.PublicKey{other, pub}, "1.2.0", a); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Anything the signature covers can't be changed.
	for name, mut := range map[string]func(*Artifact, *string){
		"version":   func(_ *Artifact, v *string) { *v = "1.3.0" },
		"os":        func(a *Artifact, _ *string) { a.OS = "linux" },
		"arch":      func(a *Artifact, _ *string) { a.Arch = "amd64" },
		"hash":      func(a *Artifact, _ *string) { a.SHA256 = "0" + sum[1:] },
		"size":      func(a *Artifact, _ *string) { a.Size = 1235 },
		"untrusted": func(a *Artifact, _ *string) { a.KeyID = KeyID(other) },
	} {
		b, v := a, "1.2.0"
		mut(&b, &v)
		if err := Verify([]ed25519.PublicKey{other, pub}, v, b); err == nil {
			t.Errorf("%s: tampered artifact accepted", name)
		}
	}
	if err := Verify([]ed25519.PublicKey{other}, "1.2.0", a); err == nil {
		t.Error("signature from an unknown key accepted")
	}
}

func TestParseKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b := base64.StdEncoding.EncodeToString(pub)
	keys, err := ParseKeys(" " + b + ", ," + b)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys=%d err=%v", len(keys), err)
	}
	if _, err := ParseKeys("bm90LWEta2V5"); err == nil {
		t.Error("short key accepted")
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.2.0", -1},
		{"0.10.0", "0.9.9", 1},
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"0.1.0-dev", "0.1.0", -1},
		{"0.1.0-dev", "0.2.0", -1},
		{"garbage", "0.0.1", -1},
		{"2.0.0", "", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
