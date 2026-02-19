package output

import (
	"strings"
	"testing"
)

func TestRawFormatterOutputsStringValueOnly(t *testing.T) {
	formatter := &RawFormatter{}
	out := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK:      true,
			Command: "secrets lease",
			Result:  "shhh-secret",
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	if strings.TrimSpace(out) != "shhh-secret" {
		t.Fatalf("unexpected raw string output: %q", out)
	}
}

func TestRawFormatterHandlesMapAndSliceResults(t *testing.T) {
	formatter := &RawFormatter{}

	mapOutput := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK: true,
			Result: map[string]interface{}{
				"name":  "github_token",
				"value": "abc123",
			},
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	mapLines := splitNonEmptyLines(mapOutput)
	if len(mapLines) != 2 {
		t.Fatalf("expected 2 lines for map values, got %d: %q", len(mapLines), mapOutput)
	}
	if !containsLine(mapLines, "github_token") || !containsLine(mapLines, "abc123") {
		t.Fatalf("expected map values only, got %q", mapLines)
	}

	sliceOutput := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK:     true,
			Result: []interface{}{"one", "two", "three"},
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	sliceLines := splitNonEmptyLines(sliceOutput)
	if len(sliceLines) != 3 {
		t.Fatalf("expected 3 lines for []interface{}, got %d: %q", len(sliceLines), sliceOutput)
	}
	if sliceLines[0] != "one" || sliceLines[1] != "two" || sliceLines[2] != "three" {
		t.Fatalf("unexpected slice output lines: %#v", sliceLines)
	}
}

func TestRawFormatterHandlesDefaultTypesAndNil(t *testing.T) {
	formatter := &RawFormatter{}

	// []string is handled by formatRawValue slice reflection path.
	sliceReflectionOutput := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK:     true,
			Result: []string{"a", "b", "c"},
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})
	if strings.TrimSpace(sliceReflectionOutput) != "a b c" {
		t.Fatalf("unexpected []string output: %q", sliceReflectionOutput)
	}

	mapReflectionOutput := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK:     true,
			Result: map[string]string{"user": "joel"},
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})
	if !strings.Contains(strings.TrimSpace(mapReflectionOutput), "user=joel") {
		t.Fatalf("unexpected map reflection output: %q", mapReflectionOutput)
	}

	intOutput := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK:     true,
			Result: 42,
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})
	if strings.TrimSpace(intOutput) != "42" {
		t.Fatalf("unexpected int output: %q", intOutput)
	}

	nilOutput := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK:     true,
			Result: nil,
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})
	if strings.TrimSpace(nilOutput) != "" {
		t.Fatalf("expected no output for nil result, got %q", nilOutput)
	}
}

func TestRawFormatterOutputsErrorMessageAndFix(t *testing.T) {
	formatter := &RawFormatter{}
	out := captureStdout(t, func() {
		if err := formatter.Format(Response{
			OK: false,
			Error: &ErrorDetail{
				Message: "lease not found",
				Code:    "not_found",
			},
			Fix: "Check active leases: secrets status",
		}); err != nil {
			t.Fatalf("format failed: %v", err)
		}
	})

	lines := splitNonEmptyLines(out)
	if len(lines) != 2 {
		t.Fatalf("expected error and fix lines, got %d: %q", len(lines), out)
	}
	if lines[0] != "lease not found" {
		t.Fatalf("unexpected error line: %q", lines[0])
	}
	if lines[1] != "Check active leases: secrets status" {
		t.Fatalf("unexpected fix line: %q", lines[1])
	}
}

func splitNonEmptyLines(out string) []string {
	raw := strings.Split(out, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

func containsLine(lines []string, target string) bool {
	for _, line := range lines {
		if line == target {
			return true
		}
	}
	return false
}
