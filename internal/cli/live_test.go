package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// TestLive runs read-only commands against a real account. It is skipped
// unless EYALSEC_LIVE=1 and EYALSEC_API_KEY are set (EYALSEC_URL optional):
//
//	EYALSEC_LIVE=1 EYALSEC_API_KEY=es2_... go test ./internal/cli -run TestLive -v
func TestLive(t *testing.T) {
	if os.Getenv("EYALSEC_LIVE") != "1" || os.Getenv("EYALSEC_API_KEY") == "" {
		t.Skip("set EYALSEC_LIVE=1 and EYALSEC_API_KEY to run against a real account")
	}
	for _, args := range [][]string{
		{"whoami"},
		{"machines", "list", "-o", "json"},
		{"events", "list", "--limit", "5"},
		{"events", "list", "--limit", "5", "-o", "csv"},
		{"events", "stats"},
		{"events", "count"},
		{"events", "names"},
		{"runs", "list", "--limit", "5"},
		{"events", "export", "--format", "json", "--from", "2026-01-01"},
	} {
		var out, errb bytes.Buffer
		app := &App{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Env: os.Getenv}
		if code := app.Run(context.Background(), args); code != 0 {
			t.Errorf("%v: exit %d: %s", args, code, errb.String())
			continue
		}
		t.Logf("%v: %d bytes of output", args, out.Len())
	}
}
