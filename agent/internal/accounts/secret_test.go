package accounts

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

// Encrypted by the server's algorithm in Node (apps/api/src/devices/local-accounts.ts) to the device
// key 0x11 × 32, for device "dev-1", person "user-1", version 3.
const vector = "ReBm1DF_9tA5HoyPdJuaUUJFltr1UxG83K07Kn3qGmjj0j9KVIx4baniyYjlq6fhio_I5QOUtGYWa44zC-nLlkySOkkrT6KGxYEdGJG2UXKybPIBmnv2LuUP3Vxn2vsWTloZW0m9cBrxwrSmf-FiyJac3X30vRkOvIF_"

func TestOpensWhatTheServerSealed(t *testing.T) {
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if PublicKey(k) != "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM" {
		t.Fatalf("public key %s", PublicKey(k))
	}
	s, err := Open(k, "dev-1", "user-1", 3, vector)
	if err != nil || s.Password != "correct horse battery staple" || s.Old != "Tr0ub4dor&3" {
		t.Fatalf("%+v %v", s, err)
	}
	// Bound to device, person and version: moved anywhere else, it doesn't open.
	for _, c := range [][3]any{{"dev-2", "user-1", 3}, {"dev-1", "user-2", 3}, {"dev-1", "user-1", 4}} {
		if _, err := Open(k, c[0].(string), c[1].(string), c[2].(int), vector); err == nil {
			t.Fatalf("opened for %v", c)
		}
	}
	other, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if _, err := Open(other, "dev-1", "user-1", 3, vector); err == nil {
		t.Fatal("another device's key opened it")
	}
}

func TestKeyIsCreatedOnceAndKeptPrivate(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateKey(dir)
	if err != nil || PublicKey(a) != PublicKey(b) {
		t.Fatal("a second load made a new key")
	}
}
