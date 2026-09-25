package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/votal-ai/nexus/agent/internal/osquery"
)

const (
	queryMaxRows  = 1000
	queryMaxBytes = 1 << 20
)

// QueryAction runs a live osquery query from a signed command. The SQL is part
// of what the organization's key signed, and is checked again here.
func QueryAction(locate func() string) ArgExecutor {
	return func(ctx context.Context, args json.RawMessage) (string, json.RawMessage, error) {
		var a struct {
			SQL string `json:"sql"`
		}
		if json.Unmarshal(args, &a) != nil || a.SQL == "" {
			return "", nil, errors.New("the command has no query")
		}
		bin := locate()
		if bin == "" {
			return "", nil, errors.New("osquery isn't installed on this device")
		}
		rows, truncated, err := osquery.Runner{Bin: bin, Timeout: 60 * time.Second}.Query(ctx, a.SQL, queryMaxRows)
		if err != nil {
			return "", nil, err
		}
		data, err := json.Marshal(map[string]any{"rows": rows, "truncated": truncated})
		if err != nil {
			return "", nil, err
		}
		if len(data) > queryMaxBytes {
			return "", nil, fmt.Errorf("the result is larger than %d KB; select fewer columns or add a LIMIT", queryMaxBytes>>10)
		}
		msg := fmt.Sprintf("%d rows", len(rows))
		if truncated {
			msg += fmt.Sprintf(" (first %d)", queryMaxRows)
		}
		return msg, data, nil
	}
}
