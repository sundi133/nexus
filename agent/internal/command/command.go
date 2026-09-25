// Package command runs actions the Nexus server asks for (lock, restart,
// refresh), but only when they carry a valid signature from the
// organization's command key, which the agent pins at enrollment (CMD-03).
package command

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Signed is a command as it arrives in a check-in response.
type Signed struct {
	ID  string `json:"id"`
	JWS string `json:"jws"`
}

// Result is reported on the next check-in.
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"` // done | failed
	Output string `json:"output"`
}

// Claims are what the server signed.
type Claims struct {
	ID     string `json:"jti"`
	Device string `json:"sub"`
	Action string `json:"act"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

const typ = "nexus-command+jwt"

var b64 = base64.RawURLEncoding

// Verify checks an EdDSA compact JWS against the pinned key, and that it's for this device and not expired.
func Verify(jws string, key ed25519.PublicKey, deviceID string, now time.Time) (*Claims, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed command")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	raw, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(raw, &hdr) != nil || hdr.Alg != "EdDSA" || hdr.Typ != typ {
		return nil, errors.New("unexpected command header")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("bad command signature")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed command payload")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil || c.ID == "" {
		return nil, errors.New("malformed command payload")
	}
	if c.Device != deviceID {
		return nil, fmt.Errorf("command is for another device")
	}
	if now.Unix() > c.Exp {
		return nil, fmt.Errorf("command expired")
	}
	return &c, nil
}

// Executor carries out one kind of action and says what happened.
type Executor func(ctx context.Context) (string, error)

// Runner verifies and runs commands, remembering which it has run.
type Runner struct {
	StateDir string
	DeviceID string
	Exec     map[string]Executor
	Log      *slog.Logger
	Now      func() time.Time
}

func (r *Runner) keyPath() string  { return filepath.Join(r.StateDir, "command.key") }
func (r *Runner) donePath() string { return filepath.Join(r.StateDir, "commands-done.json") }

// Pin stores the organization's command key the first time the agent sees it
// (at enrollment, or the first check-in for agents enrolled before commands
// existed) and refuses a different one later: a changed key means someone is
// trying to make this device obey another signer.
func (r *Runner) Pin(key string) error {
	if key == "" {
		return nil
	}
	if b, err := b64.DecodeString(key); err != nil || len(b) != ed25519.PublicKeySize {
		return errors.New("server sent an invalid command key")
	}
	cur, err := os.ReadFile(r.keyPath())
	if err == nil {
		if strings.TrimSpace(string(cur)) != key {
			return errors.New("server's command key differs from the one pinned at enrollment; ignoring its commands")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(r.keyPath(), []byte(key), 0o600)
}

func (r *Runner) key() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(r.keyPath())
	if err != nil {
		return nil, errors.New("no command key pinned yet")
	}
	return b64.DecodeString(strings.TrimSpace(string(raw)))
}

func (r *Runner) done() map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(r.donePath())
	if err != nil {
		return out
	}
	var ids []string
	_ = json.Unmarshal(raw, &ids)
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func (r *Runner) remember(ids map[string]bool, id string) {
	ids[id] = true
	list := make([]string, 0, len(ids))
	for k := range ids {
		list = append(list, k)
	}
	if len(list) > 500 { // expiry bounds replays anyway; keep the file small
		list = list[len(list)-500:]
	}
	data, _ := json.Marshal(list)
	_ = os.WriteFile(r.donePath(), data, 0o600)
}

// Handle runs each valid, new command and returns what to report. Invalid
// commands are reported as failed (with why) but never run.
func (r *Runner) Handle(ctx context.Context, cmds []Signed) []Result {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	key, kerr := r.key()
	seen := r.done()
	var out []Result
	for _, s := range cmds {
		if seen[s.ID] {
			continue // already ran (and reported); a replay is ignored
		}
		if kerr != nil {
			out = append(out, Result{ID: s.ID, Status: "failed", Output: kerr.Error()})
			continue
		}
		c, err := Verify(s.JWS, key, r.DeviceID, now())
		if err != nil || c.ID != s.ID {
			if err == nil {
				err = errors.New("command ID mismatch")
			}
			r.Log.Warn("refused a command", "id", s.ID, "err", err)
			out = append(out, Result{ID: s.ID, Status: "failed", Output: "refused: " + err.Error()})
			continue
		}
		r.remember(seen, c.ID) // before running: a crash mid-action must not repeat it
		exec, ok := r.Exec[c.Action]
		if !ok {
			out = append(out, Result{ID: c.ID, Status: "failed", Output: fmt.Sprintf("this agent can't %s", c.Action)})
			continue
		}
		r.Log.Info("running command", "id", c.ID, "action", c.Action)
		msg, err := exec(ctx)
		if err != nil {
			out = append(out, Result{ID: c.ID, Status: "failed", Output: err.Error()})
		} else {
			out = append(out, Result{ID: c.ID, Status: "done", Output: msg})
		}
	}
	return out
}
