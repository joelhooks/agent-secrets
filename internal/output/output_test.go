package output

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestSuccessEnvelopeShape(t *testing.T) {
	resp := Success("secrets status", map[string]interface{}{"running": true}, ActionStatus())

	if !resp.OK {
		t.Fatalf("expected OK=true")
	}
	if resp.Command != "secrets status" {
		t.Fatalf("unexpected command: %q", resp.Command)
	}
	if resp.Result == nil {
		t.Fatalf("expected result to be set")
	}
	if len(resp.NextActions) != 1 {
		t.Fatalf("expected one next action")
	}
	if resp.NextActions[0].Description == "" || resp.NextActions[0].Command == "" {
		t.Fatalf("action should include description and command")
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonText := string(encoded)
	if strings.Contains(jsonText, `"success"`) || strings.Contains(jsonText, `"data"`) || strings.Contains(jsonText, `"actions"`) {
		t.Fatalf("legacy envelope fields leaked into json: %s", jsonText)
	}
}

func TestErrorEnvelopeIncludesCodeAndFix(t *testing.T) {
	userErr := types.NewUserError(
		"Failed to connect to daemon",
		"Daemon is required for lease operations.",
		"Start the daemon with: secrets serve &",
		"secrets --help",
	)

	resp := Error("secrets lease", userErr, ActionStatus())

	if resp.OK {
		t.Fatalf("expected OK=false")
	}
	if resp.Error == nil {
		t.Fatalf("expected error detail")
	}
	if resp.Error.Message == "" {
		t.Fatalf("expected error message")
	}
	if resp.Error.Code == "" {
		t.Fatalf("expected error code")
	}
	if resp.Fix == "" {
		t.Fatalf("expected fix suggestion")
	}
	if resp.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}

func TestRawFormatterReadsResult(t *testing.T) {
	formatter := &RawFormatter{}
	resp := Response{
		OK:      true,
		Command: "secrets lease",
		Result:  "secret-value",
	}

	output := captureStdout(t, func() {
		if err := formatter.Format(resp); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	if strings.TrimSpace(output) != "secret-value" {
		t.Fatalf("unexpected raw output: %q", output)
	}
}

func TestPrintAlwaysOutputsJSON(t *testing.T) {
	resp := Response{
		OK:      false,
		Command: "secrets lease",
		Error: &ErrorDetail{
			Message: "daemon unavailable",
			Code:    "daemon_unavailable",
		},
		Fix: "start the daemon with: secrets serve &",
	}

	out := captureStdout(t, func() {
		Print(resp)
	})

	if !strings.Contains(out, `"ok": false`) {
		t.Fatalf("expected json output, got %q", out)
	}

	var decoded Response
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("failed to parse json output: %v", err)
	}
	if decoded.Fix != "start the daemon with: secrets serve &" {
		t.Fatalf("unexpected fix field in json output: %q", decoded.Fix)
	}
}

func TestErrorMsgIncludesGenericCode(t *testing.T) {
	resp := ErrorMsg("secrets init", "bad input")
	if resp.Error == nil {
		t.Fatalf("expected error detail")
	}
	if resp.Error.Code == "" {
		t.Fatalf("expected non-empty error code")
	}
}

func TestErrorWithCodeUsesMappedCode(t *testing.T) {
	resp := ErrorWithCode("secrets env", errors.New("timed out"), types.ExitTimeout)
	if resp.Error == nil {
		t.Fatalf("expected error detail")
	}
	if resp.Error.Code != "timeout" {
		t.Fatalf("expected timeout code, got %q", resp.Error.Code)
	}
}

func TestActionLeaseIncludesJSONFlag(t *testing.T) {
	action := ActionLease("github_token")
	if !strings.Contains(action.Command, "--json") {
		t.Fatalf("expected lease action to include --json, got %q", action.Command)
	}
}

func TestActionLeaseWithTTLIncludesJSONFlag(t *testing.T) {
	action := ActionLeaseWithTTL("github_token", "30m")
	if !strings.Contains(action.Command, "--json") {
		t.Fatalf("expected lease with ttl action to include --json, got %q", action.Command)
	}
	if !strings.Contains(action.Command, "--ttl 30m") {
		t.Fatalf("expected lease with ttl action to include ttl, got %q", action.Command)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	return string(out)
}
