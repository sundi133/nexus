package command

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func sign(t *testing.T, priv ed25519.PrivateKey, c Claims) string {
	t.Helper()
	h := b64.EncodeToString([]byte(`{"alg":"EdDSA","typ":"nexus-command+jwt"}`))
	p, _ := json.Marshal(c)
	body := h + "." + b64.EncodeToString(p)
	return body + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(body)))
}

func setup(t *testing.T) (*Runner, ed25519.PrivateKey, *[]string) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ran := &[]string{}
	r := &Runner{
		StateDir: t.TempDir(),
		DeviceID: "dev-1",
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Exec: map[string]Executor{
			"lock": func(context.Context) (string, error) { *ran = append(*ran, "lock"); return "locked", nil },
		},
	}
	if err := r.Pin(b64.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	return r, priv, ran
}

func TestRunsOnlyValidCommandsOnce(t *testing.T) {
	r, priv, ran := setup(t)
	exp := time.Now().Add(time.Hour).Unix()
	good := Signed{ID: "c1", JWS: sign(t, priv, Claims{ID: "c1", Device: "dev-1", Action: "lock", Exp: exp})}
	res := r.Handle(context.Background(), []Signed{good})
	if len(res) != 1 || res[0].Status != "done" || res[0].Output != "locked" {
		t.Fatalf("got %+v", res)
	}
	// Replayed: ignored, not run again.
	if res := r.Handle(context.Background(), []Signed{good}); len(res) != 0 || len(*ran) != 1 {
		t.Fatalf("replay ran: %+v %v", res, *ran)
	}
}

func TestRefusesWhatIsNotForUs(t *testing.T) {
	r, priv, ran := setup(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	exp := time.Now().Add(time.Hour).Unix()
	tampered := sign(t, priv, Claims{ID: "c3", Device: "dev-1", Action: "lock", Exp: exp})
	parts := strings.Split(tampered, ".")
	p, _ := json.Marshal(Claims{ID: "c3", Device: "dev-1", Action: "restart", Exp: exp})
	parts[1] = b64.EncodeToString(p)
	cases := map[string]Signed{
		"bad command signature":          {ID: "c2", JWS: sign(t, other, Claims{ID: "c2", Device: "dev-1", Action: "lock", Exp: exp})},
		"bad command signature (edited)": {ID: "c3", JWS: strings.Join(parts, ".")},
		"another device":                 {ID: "c4", JWS: sign(t, priv, Claims{ID: "c4", Device: "dev-2", Action: "lock", Exp: exp})},
		"expired":                        {ID: "c5", JWS: sign(t, priv, Claims{ID: "c5", Device: "dev-1", Action: "lock", Exp: time.Now().Add(-time.Minute).Unix()})},
		"ID mismatch":                    {ID: "c6", JWS: sign(t, priv, Claims{ID: "c7", Device: "dev-1", Action: "lock", Exp: exp})},
	}
	for name, s := range cases {
		res := r.Handle(context.Background(), []Signed{s})
		if len(res) != 1 || res[0].Status != "failed" || !strings.HasPrefix(res[0].Output, "refused") {
			t.Errorf("%s: got %+v", name, res)
		}
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %v", *ran)
	}
	// Unknown action: verified, but nothing to run.
	res := r.Handle(context.Background(), []Signed{{ID: "c8", JWS: sign(t, priv, Claims{ID: "c8", Device: "dev-1", Action: "wipe", Exp: exp})}})
	if res[0].Status != "failed" || res[0].Output != "this agent can't wipe" {
		t.Fatalf("got %+v", res)
	}
}

func TestPinsTheFirstKeyOnly(t *testing.T) {
	r, _, _ := setup(t)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := r.Pin(b64.EncodeToString(pub2)); err == nil {
		t.Fatal("a different key was accepted")
	}
	if err := r.Pin("not-a-key"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLiveQueryRunsTheSignedSQL(t *testing.T) {
	r, priv, _ := setup(t)
	var got string
	r.ArgExec = map[string]ArgExecutor{"osquery": func(_ context.Context, args json.RawMessage) (string, json.RawMessage, error) {
		got = string(args)
		return "1 rows", json.RawMessage(`{"rows":[{"a":"1"}]}`), nil
	}}
	exp := time.Now().Add(time.Hour).Unix()
	args := json.RawMessage(`{"sql":"SELECT 1"}`)
	res := r.Handle(context.Background(), []Signed{{ID: "q1", JWS: sign(t, priv, Claims{ID: "q1", Device: "dev-1", Action: "osquery", Args: args, Exp: exp})}})
	if len(res) != 1 || res[0].Status != "done" || string(res[0].Data) != `{"rows":[{"a":"1"}]}` || got != `{"sql":"SELECT 1"}` {
		t.Fatalf("got %+v, ran with %s", res, got)
	}
	// Swapping the SQL breaks the signature.
	jws := sign(t, priv, Claims{ID: "q2", Device: "dev-1", Action: "osquery", Args: args, Exp: exp})
	parts := strings.Split(jws, ".")
	p, _ := json.Marshal(Claims{ID: "q2", Device: "dev-1", Action: "osquery", Args: json.RawMessage(`{"sql":"SELECT * FROM shadow"}`), Exp: exp})
	parts[1] = b64.EncodeToString(p)
	if res := r.Handle(context.Background(), []Signed{{ID: "q2", JWS: strings.Join(parts, ".")}}); res[0].Status != "failed" || got != `{"sql":"SELECT 1"}` {
		t.Fatalf("edited SQL ran: %+v", res)
	}
}

func TestQueryActionWithoutOsquery(t *testing.T) {
	_, _, err := QueryAction(func() string { return "" })(context.Background(), json.RawMessage(`{"sql":"SELECT 1"}`))
	if err == nil || err.Error() != "osquery isn't installed on this device" {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := QueryAction(func() string { return "/bin/true" })(context.Background(), json.RawMessage(`{"sql":"SELECT * FROM curl"}`)); err == nil || !strings.Contains(err.Error(), "curl") {
		t.Fatalf("denied table ran: %v", err)
	}
}
