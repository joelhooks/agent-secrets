package output

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestJSONFormatterOutputsExpectedEnvelope(t *testing.T) {
	formatter := &JSONFormatter{}
	resp := Success(
		"secrets status",
		map[string]bool{"running": true},
		ActionStatus(),
	)

	out := captureStdout(t, func() {
		if err := formatter.Format(resp); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}

	if decoded["ok"] != true {
		t.Fatalf("expected ok=true, got %#v", decoded["ok"])
	}
	if decoded["success"] != true {
		t.Fatalf("expected success=true, got %#v", decoded["success"])
	}
	if decoded["command"] != "secrets status" {
		t.Fatalf("unexpected command: %#v", decoded["command"])
	}
	if _, ok := decoded["result"]; !ok {
		t.Fatalf("expected result in envelope: %s", out)
	}
	if _, ok := decoded["next_actions"]; !ok {
		t.Fatalf("expected next_actions in envelope: %s", out)
	}
}

func TestJSONFormatterSuccessMirrorsOK(t *testing.T) {
	formatter := &JSONFormatter{}
	resp := Response{
		OK:      true,
		Success: false,
		Command: "secrets status",
	}

	out := captureStdout(t, func() {
		if err := formatter.Format(resp); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}
	if decoded["success"] != true {
		t.Fatalf("expected success to mirror ok=true, got %#v", decoded["success"])
	}
}

func TestJSONFormatterOmitsEmptyFields(t *testing.T) {
	formatter := &JSONFormatter{}
	resp := Response{
		OK:      true,
		Success: true,
		Command: "secrets status",
	}

	out := captureStdout(t, func() {
		if err := formatter.Format(resp); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	if strings.Contains(out, `"result": null`) || strings.Contains(out, `"error": null`) {
		t.Fatalf("unexpected null field in json output: %s", out)
	}
	if strings.Contains(out, `"result"`) || strings.Contains(out, `"error"`) {
		t.Fatalf("expected empty fields to be omitted: %s", out)
	}
	if strings.Contains(out, `"fix"`) || strings.Contains(out, `"next_actions"`) {
		t.Fatalf("expected empty optional fields to be omitted: %s", out)
	}
}

func TestJSONFormatterErrorIncludesFix(t *testing.T) {
	formatter := &JSONFormatter{}
	resp := ErrorWithFix(
		"secrets add",
		errors.New("secret already exists"),
		"Use secrets update github_token",
		ActionHelp("update"),
	)

	out := captureStdout(t, func() {
		if err := formatter.Format(resp); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	var decoded struct {
		OK    bool        `json:"ok"`
		Error ErrorDetail `json:"error"`
		Fix   string      `json:"fix"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}

	if decoded.OK {
		t.Fatalf("expected ok=false")
	}
	if decoded.Error.Message == "" || decoded.Error.Code == "" {
		t.Fatalf("expected structured error details, got %#v", decoded.Error)
	}
	if decoded.Fix != "Use secrets update github_token" {
		t.Fatalf("expected fix field in error response, got %q", decoded.Fix)
	}
}
