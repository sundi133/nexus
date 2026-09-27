package accounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The device's encryption key: X25519, separate from its signing identity, created on first run
// and kept in the state folder (readable by root/SYSTEM only). The server encrypts people's
// passwords to it, so only this device can read them.

const keyFile = "encryption.key"

var b64 = base64.RawURLEncoding

// LoadOrCreateKey reads the device's X25519 key, creating it the first time.
func LoadOrCreateKey(dir string) (*ecdh.PrivateKey, error) {
	p := filepath.Join(dir, keyFile)
	if raw, err := os.ReadFile(p); err == nil {
		if b, derr := b64.DecodeString(string(raw)); derr == nil {
			return ecdh.X25519().NewPrivateKey(b)
		}
		return nil, errors.New("the encryption key file is damaged")
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(b64.EncodeToString(k.Bytes())), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// PublicKey is what the agent reports: the X25519 public key, base64url.
func PublicKey(k *ecdh.PrivateKey) string { return b64.EncodeToString(k.PublicKey().Bytes()) }

// Secret is a person's password (and, after a change, the one it replaced).
type Secret struct {
	Password string `json:"password"`
	Old      string `json:"old,omitempty"`
}

const info = "nexus-password-v1"

// hkdf32 is HKDF-SHA256 (RFC 5869) producing one 32-byte key.
func hkdf32(secret, salt []byte) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	exp := hmac.New(sha256.New, prk)
	exp.Write([]byte(info))
	exp.Write([]byte{1})
	return exp.Sum(nil)
}

// Open decrypts a password the server encrypted to this device:
// base64url(ephemeral public key 32 ‖ nonce 12 ‖ AES-256-GCM ciphertext+tag), with the key from
// HKDF(X25519(device, ephemeral), salt = ephemeral ‖ device public key), bound to device, person and version.
func Open(k *ecdh.PrivateKey, deviceID, userID string, version int, ct string) (Secret, error) {
	raw, err := b64.DecodeString(ct)
	if err != nil || len(raw) < 32+12+16 {
		return Secret{}, errors.New("malformed password envelope")
	}
	eph, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return Secret{}, err
	}
	shared, err := k.ECDH(eph)
	if err != nil {
		return Secret{}, err
	}
	block, _ := aes.NewCipher(hkdf32(shared, append(append([]byte{}, raw[:32]...), k.PublicKey().Bytes()...)))
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, raw[32:44], raw[44:], []byte(fmt.Sprintf("%s|%s|%d", deviceID, userID, version)))
	if err != nil {
		return Secret{}, errors.New("the password envelope doesn't open with this device's key")
	}
	var s Secret
	if json.Unmarshal(plain, &s) != nil || s.Password == "" {
		return Secret{}, errors.New("malformed password")
	}
	return s, nil
}
