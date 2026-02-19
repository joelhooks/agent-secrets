package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRootCommandDoesNotExposeLegacyOutputFlags(t *testing.T) {
	humanFlag := rootCmd.PersistentFlags().Lookup("human")
	if humanFlag == nil {
		t.Fatalf("expected --human flag to exist for backward compatibility")
	}
	if !humanFlag.Hidden {
		t.Fatalf("expected --human flag to be hidden")
	}

	outputFlag := rootCmd.PersistentFlags().Lookup("output")
	if outputFlag == nil {
		t.Fatalf("expected --output flag to exist for backward compatibility")
	}
	if !outputFlag.Hidden {
		t.Fatalf("expected --output flag to be hidden")
	}
}

func TestRootCommandNoArgsOutputsCommandTreeJSON(t *testing.T) {
	restore := setRootTestGlobals()
	defer restore()

	out := captureRootStdout(t, func() {
		rootCmd.SetArgs([]string{})
		rootCmd.SetOut(io.Discard)
		rootCmd.SetErr(io.Discard)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("Execute failed: %v", err)
		}
	})

	var resp struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Result  struct {
			Description string `json:"description"`
			Version     string `json:"version"`
			Commands    []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Usage       string `json:"usage"`
			} `json:"commands"`
		} `json:"result"`
		NextActions []struct {
			Command     string `json:"command"`
			Description string `json:"description"`
		} `json:"next_actions"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}

	if !resp.OK {
		t.Fatalf("expected ok=true, got false")
	}
	if resp.Command != "secrets" {
		t.Fatalf("expected command=secrets, got %q", resp.Command)
	}
	if resp.Result.Description != "Portable credential management for AI agents" {
		t.Fatalf("unexpected description: %q", resp.Result.Description)
	}
	if resp.Result.Version == "" {
		t.Fatalf("expected non-empty version")
	}
	if len(resp.Result.Commands) < 15 {
		t.Fatalf("expected at least 15 commands, got %d", len(resp.Result.Commands))
	}

	hasList := false
	hasUpdate := false
	hasDelete := false
	for _, c := range resp.Result.Commands {
		if c.Name == "list" {
			hasList = true
		}
		if c.Name == "update" {
			hasUpdate = true
		}
		if c.Name == "delete" {
			hasDelete = true
		}
	}
	if !hasList {
		t.Fatalf("expected command tree to include list command")
	}
	if !hasUpdate {
		t.Fatalf("expected command tree to include update command")
	}
	if !hasDelete {
		t.Fatalf("expected command tree to include delete command")
	}

	if len(resp.NextActions) != 3 {
		t.Fatalf("expected 3 next_actions, got %d", len(resp.NextActions))
	}
	if resp.NextActions[0].Command != "secrets status" {
		t.Fatalf("expected first next action to be secrets status, got %q", resp.NextActions[0].Command)
	}
}

func TestRootCommandLegacyFlagsWarnOnStderr(t *testing.T) {
	restore := setRootTestGlobals()
	defer restore()

	var out string
	errOut := captureRootStderr(t, func() {
		out = captureRootStdout(t, func() {
			rootCmd.SetArgs([]string{"--human", "--output", "json"})
			rootCmd.SetOut(io.Discard)
			rootCmd.SetErr(io.Discard)
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("Execute failed: %v", err)
			}
		})
	})

	var resp struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true when legacy flags are used")
	}

	if !strings.Contains(errOut, "WARNING: --human is deprecated and ignored. JSON output is always enabled. Will be removed in v0.6.0") {
		t.Fatalf("expected --human deprecation warning, got %q", errOut)
	}
	if !strings.Contains(errOut, "WARNING: --output is deprecated and ignored. JSON output is always enabled. Will be removed in v0.6.0") {
		t.Fatalf("expected --output deprecation warning, got %q", errOut)
	}
}

func setRootTestGlobals() func() {
	origNoUpdateCheck := noUpdateCheck
	noUpdateCheck = true
	return func() {
		noUpdateCheck = origNoUpdateCheck
	}
}

func captureRootStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = origStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout failed: %v", err)
	}
	return string(out)
}

func captureRootStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = origStderr

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr failed: %v", err)
	}
	return string(out)
}
