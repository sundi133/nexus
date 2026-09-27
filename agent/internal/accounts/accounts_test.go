package accounts

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// seal is the server's side (as in the Node test vector), for tests.
func seal(t *testing.T, device *ecdh.PublicKey, deviceID, userID string, version int, s Secret) string {
	t.Helper()
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(device)
	block, _ := aes.NewCipher(hkdf32(shared, append(eph.PublicKey().Bytes(), device.Bytes()...)))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	plain, _ := json.Marshal(s)
	out := append(append(eph.PublicKey().Bytes(), nonce...), gcm.Seal(nil, nonce, plain, []byte(fmt.Sprintf("%s|%s|%d", deviceID, userID, version)))...)
	return b64.EncodeToString(out)
}

type user struct {
	enabled bool
	pw      string
	groups  map[string]bool
}

// linuxBox is a fake Linux device.
type linuxBox struct {
	users map[string]*user
	ran   []string
	stdin []string
}

func (b *linuxBox) sys() Sys {
	return Sys{GOOS: "linux", Run: func(_ context.Context, stdin, name string, args ...string) (string, error) {
		b.ran = append(b.ran, strings.Join(append([]string{name}, args...), " "))
		if stdin != "" {
			b.stdin = append(b.stdin, stdin)
		}
		last := ""
		if len(args) > 0 {
			last = args[len(args)-1]
		}
		switch name {
		case "getent":
			return "sudo:x:27:", nil
		case "id":
			u, ok := b.users[last]
			if !ok {
				return "id: no such user", errors.New("exit status 1")
			}
			if args[0] == "-nG" {
				g := []string{last}
				for k := range u.groups {
					g = append(g, k)
				}
				return strings.Join(g, " "), nil
			}
			return "1001", nil
		case "useradd":
			b.users[last] = &user{groups: map[string]bool{}}
		case "chpasswd":
			parts := strings.SplitN(strings.TrimSpace(stdin), ":", 2)
			b.users[parts[0]].pw = parts[1]
		case "usermod":
			switch args[0] {
			case "-aG":
				b.users[last].groups[args[1]] = true
			case "-U":
				b.users[last].enabled = true
			case "-L":
				b.users[last].enabled = false
			}
		case "gpasswd":
			delete(b.users[args[1]].groups, args[2])
		}
		return "", nil
	}}
}

func newManager(t *testing.T, b *linuxBox) (*Manager, *ecdh.PublicKey) {
	k, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	return &Manager{Sys: b.sys(), StateDir: t.TempDir(), DeviceID: "dev-1", Key: k}, k.PublicKey()
}

func TestAccountLifecycle(t *testing.T) {
	b := &linuxBox{users: map[string]*user{}}
	m, pub := newManager(t, b)
	ctx := context.Background()
	eve := Account{UserID: "u-eve", Username: "eve", FullName: "Eve Example", State: "active", Admin: true}

	// Created, but locked until a password arrives.
	st := m.Apply(ctx, []Account{eve})
	if st[0].Status != "waiting_password" || b.users["eve"].enabled || !b.users["eve"].groups["sudo"] {
		t.Fatalf("%+v %+v", st, b.users["eve"])
	}
	// The password arrives (the person signed in to Nexus): set, enabled.
	if ok, err := m.Offer("u-eve", 1, seal(t, pub, "dev-1", "u-eve", 1, Secret{Password: "s3cret pass"})); !ok || err != nil {
		t.Fatal(ok, err)
	}
	st = m.Apply(ctx, []Account{eve})
	if st[0].Status != "active" || st[0].PasswordVersion != 1 || b.users["eve"].pw != "s3cret pass" || !b.users["eve"].enabled {
		t.Fatalf("%+v %+v", st, b.users["eve"])
	}
	for _, c := range b.ran {
		if strings.Contains(c, "s3cret") {
			t.Fatalf("the password was on a command line: %s", c)
		}
	}
	// An older password (a replayed envelope) is ignored.
	if ok, _ := m.Offer("u-eve", 1, seal(t, pub, "dev-1", "u-eve", 1, Secret{Password: "old"})); ok {
		m.Apply(ctx, []Account{eve})
	}
	if b.users["eve"].pw != "s3cret pass" {
		t.Fatal("an old password replaced a newer one")
	}
	// Admin rights follow the policy.
	eve.Admin = false
	m.Apply(ctx, []Account{eve})
	if b.users["eve"].groups["sudo"] {
		t.Fatal("still an admin")
	}
	// Leaving the company: disabled, not deleted.
	eve.State = "disabled"
	if st = m.Apply(ctx, []Account{eve}); st[0].Status != "disabled" || b.users["eve"].enabled {
		t.Fatalf("%+v", st)
	}
	// Removed from the policy altogether: disabled too.
	eve.State = "active"
	m.Apply(ctx, []Account{eve})
	if !b.users["eve"].enabled {
		t.Fatal("not re-enabled")
	}
	m.Apply(ctx, nil)
	if b.users["eve"].enabled || b.users["eve"] == nil {
		t.Fatal("an unbound account stayed enabled (or was deleted)")
	}
}

func TestExistingAccountsNeedTakeOverAndSystemAccountsAreRefused(t *testing.T) {
	b := &linuxBox{users: map[string]*user{"bob": {enabled: true, pw: "his own", groups: map[string]bool{}}}}
	m, pub := newManager(t, b)
	ctx := context.Background()
	bob := Account{UserID: "u-bob", Username: "bob", State: "active"}
	if st := m.Apply(ctx, []Account{bob}); st[0].Status != "failed" || !strings.Contains(st[0].Detail, "take over") {
		t.Fatalf("%+v", st)
	}
	bob.TakeOver = true
	// Taken over: stays usable with its own password until Nexus has one.
	if st := m.Apply(ctx, []Account{bob}); st[0].Status != "active" || !b.users["bob"].enabled || b.users["bob"].pw != "his own" {
		t.Fatalf("%+v", st)
	}
	m.Offer("u-bob", 2, seal(t, pub, "dev-1", "u-bob", 2, Secret{Password: "company pw"}))
	if m.Apply(ctx, []Account{bob}); b.users["bob"].pw != "company pw" {
		t.Fatal("password not synced")
	}
	// Another person can't take the name.
	if st := m.Apply(ctx, []Account{{UserID: "u-mallory", Username: "bob", State: "active", TakeOver: true}}); st[0].Status != "failed" {
		t.Fatalf("%+v", st)
	}
	for _, n := range []string{"root", "Administrator", "systemd-network", "-rf", "a b"} {
		if st := m.Apply(ctx, []Account{{UserID: "x", Username: n, State: "active", TakeOver: true}}); st[0].Status != "failed" {
			t.Fatalf("%s: %+v", n, st)
		}
	}
	// An envelope for another device doesn't open.
	if _, err := m.Offer("u-bob", 3, seal(t, pub, "dev-2", "u-bob", 3, Secret{Password: "x"})); err == nil {
		t.Fatal("opened another device's envelope")
	}
}

func TestSecretsGoThroughStdinOnEveryOS(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		var calls []string
		var stdins []string
		s := Sys{GOOS: goos, Run: func(_ context.Context, stdin, name string, args ...string) (string, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			stdins = append(stdins, stdin)
			return "ok", nil
		}}
		if err := s.setPassword(context.Background(), "eve", Secret{Password: "p@ss word", Old: "older"}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(calls, "\n"), "p@ss") || !strings.Contains(stdins[0], "p@ss word") {
			t.Fatalf("%s: %q %q", goos, calls, stdins)
		}
		if goos == "darwin" && !strings.Contains(stdins[0], `"old":"older"`) {
			t.Fatal("macOS didn't get the old password (keychain and FileVault follow a change, not a reset)")
		}
	}
}
