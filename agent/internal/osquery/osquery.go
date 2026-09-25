// Package osquery runs osquery SQL on the device: a scheduled inventory pack
// and live queries from signed commands. It uses osquery's shell one query at
// a time (no daemon, no extension socket), so it works alongside an osqueryd
// that an MDM or another tool already runs.
package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Where osquery's installers put the shell. NEXUS_OSQUERY_PATH overrides.
func candidates(goos string) []string {
	switch goos {
	case "darwin":
		return []string{"/usr/local/bin/osqueryi", "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd", "/opt/homebrew/bin/osqueryi"}
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return []string{filepath.Join(pf, "osquery", "osqueryi.exe"), filepath.Join(pf, "osquery", "osqueryd", "osqueryd.exe")}
	}
	return []string{"/usr/bin/osqueryi", "/opt/osquery/bin/osqueryi", "/usr/local/bin/osqueryi", "/opt/osquery/bin/osqueryd", "/usr/bin/osqueryd"}
}

// Locate returns the osquery binary to use, or "" when osquery isn't installed.
func Locate() string {
	if p := os.Getenv("NEXUS_OSQUERY_PATH"); p != "" {
		return p
	}
	for _, p := range candidates(runtime.GOOS) {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

const maxOutput = 8 << 20

// Runner executes queries with one osquery binary.
type Runner struct {
	Bin     string
	Timeout time.Duration
}

func (r Runner) args(extra ...string) []string {
	var a []string
	// osqueryd acts as the shell with -S; osqueryi is the shell already.
	if strings.HasPrefix(strings.ToLower(filepath.Base(r.Bin)), "osqueryd") {
		a = append(a, "-S")
	}
	return append(a, extra...)
}

// Version is osquery's version ("5.13.1"), or "" if it can't be run.
func (r Runner) Version(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.Bin, r.args("--version")...).Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// Rows are osquery's JSON output: every value is a string.
type Rows []map[string]string

// Query runs one statement and returns at most maxRows rows.
func (r Runner) Query(ctx context.Context, sql string, maxRows int) (Rows, bool, error) {
	rows, _, truncated, err := r.QueryColumns(ctx, sql, maxRows)
	return rows, truncated, err
}

// QueryColumns is Query that also returns the column names, in the order osquery wrote them
// (its JSON output sorts them by name).
func (r Runner) QueryColumns(ctx context.Context, sql string, maxRows int) (Rows, []string, bool, error) {
	if err := CheckSQL(sql); err != nil {
		return nil, nil, false, err
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A private, throwaway database: never touch (or lock) a running osqueryd's.
	db, err := os.MkdirTemp("", "nexus-osq-")
	if err != nil {
		return nil, nil, false, err
	}
	defer os.RemoveAll(db)
	cmd := exec.CommandContext(ctx, r.Bin, r.args("--json", "--disable_extensions=true", "--disable_events=true", "--database_path="+filepath.Join(db, "db"), sql)...)
	cmd.WaitDelay = 2 * time.Second // a killed query mustn't hang on a pipe a child still holds
	var stderr bytes.Buffer
	out := &capped{max: maxOutput}
	cmd.Stdout, cmd.Stderr = out, &stderr
	werr := cmd.Run()
	if ctx.Err() != nil {
		return nil, nil, false, fmt.Errorf("the query took longer than %s", timeout)
	}
	if out.over {
		return nil, nil, false, errors.New("the query returned too much data; add a LIMIT or narrow the columns")
	}
	data := out.buf.Bytes()
	if werr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = werr.Error()
		}
		return nil, nil, false, errors.New(cleanError(msg))
	}
	var rows Rows
	if err := json.Unmarshal(bytes.TrimSpace(data), &rows); err != nil {
		if len(bytes.TrimSpace(data)) == 0 {
			return Rows{}, []string{}, false, nil
		}
		return nil, nil, false, fmt.Errorf("unexpected osquery output: %.200s", data)
	}
	truncated := false
	if maxRows > 0 && len(rows) > maxRows {
		rows, truncated = rows[:maxRows], true
	}
	return rows, columnOrder(data), truncated, nil
}

// columnOrder reads the first row's keys in the order osquery wrote them.
func columnOrder(data []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return []string{}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return []string{}
	}
	cols := []string{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			break
		}
		cols = append(cols, fmt.Sprint(k))
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			break
		}
	}
	return cols
}

// capped keeps at most max bytes and notes whether there was more.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil // keep draining so osquery isn't blocked writing
	}
	return c.buf.Write(p)
}

// cleanError keeps osquery's own message ("Error: no such table: foo") and drops log noise.
func cleanError(msg string) string {
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Error") || strings.Contains(line, "no such") || strings.Contains(line, "syntax error") {
			return line
		}
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// ---- What queries may do ----------------------------------------------------------------

// Tables that would turn a read-only query into network egress, file-content reads
// (plist, augeas: config files can hold tokens) or password-hash collection (shadow).
// The server refuses them too; the agent checks again because it trusts only the signature.
var denied = regexp.MustCompile(`(?i)\b(curl|curl_certificate|carves|carve|yara|yara_events|plist|augeas|shadow|attach|pragma|detach)\b`)
var leading = regexp.MustCompile(`(?is)^\s*(?:--[^\n]*\n\s*|/\*.*?\*/\s*)*(select|with)\b`)

// CheckSQL accepts one SELECT (or WITH … SELECT) statement that avoids the denied tables.
func CheckSQL(sql string) error {
	s := strings.TrimSpace(sql)
	s = strings.TrimSuffix(s, ";")
	if s == "" {
		return errors.New("empty query")
	}
	if len(s) > 10_000 {
		return errors.New("the query is too long")
	}
	if !leading.MatchString(s) {
		return errors.New("only SELECT queries are allowed")
	}
	if strings.Contains(stripStrings(s), ";") {
		return errors.New("one statement at a time")
	}
	if m := denied.FindString(s); m != "" {
		return fmt.Errorf("%q isn't allowed in Nexus queries", strings.ToLower(m))
	}
	return nil
}

// stripStrings blanks out quoted literals, so a ';' inside a string isn't a second statement.
func stripStrings(s string) string {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
		case c == '\'' || c == '"':
			quote = c
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
