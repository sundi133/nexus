//go:build !windows

package command

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func runScript(t *testing.T, a ScriptArgs) (string, map[string]any, error) {
	t.Helper()
	raw, _ := json.Marshal(a)
	msg, data, err := ScriptAction(t.TempDir())(context.Background(), raw)
	var d map[string]any
	_ = json.Unmarshal(data, &d)
	return msg, d, err
}

func TestScriptRunsAndReports(t *testing.T) {
	msg, d, err := runScript(t, ScriptArgs{Shell: "sh", Script: "echo hello; echo oops >&2"})
	if err != nil || !strings.HasPrefix(msg, "exit 0") || !strings.Contains(d["output"].(string), "hello") || !strings.Contains(d["output"].(string), "oops") {
		t.Fatalf("%q %v %v", msg, d, err)
	}
	_, d, err = runScript(t, ScriptArgs{Shell: "sh", Script: "echo partial; exit 3"})
	if err == nil || d["exit_code"].(float64) != 3 || !strings.Contains(d["output"].(string), "partial") {
		t.Fatalf("failure not reported with its output: %v %v", d, err)
	}
}

func TestScriptLimits(t *testing.T) {
	// A timeout ends the whole process tree, and says so.
	msg, d, err := runScript(t, ScriptArgs{Shell: "sh", Script: "sleep 30 & sleep 30", Timeout: 1})
	if err == nil || d["timed_out"] != true || !strings.Contains(msg, "time limit") {
		t.Fatalf("%q %v %v", msg, d, err)
	}
	// Output is capped.
	_, d, _ = runScript(t, ScriptArgs{Shell: "sh", Script: "yes | head -c 200000"})
	if d["truncated"] != true || len(d["output"].(string)) != scriptMaxOutput {
		t.Fatalf("output not capped: %d %v", len(d["output"].(string)), d["truncated"])
	}
	if _, _, err := runScript(t, ScriptArgs{Shell: "cmd.exe", Script: "dir"}); err == nil {
		t.Fatal("unknown shell accepted")
	}
}
