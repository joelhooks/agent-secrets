package main

import (
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestRootCommandDoesNotExposeLegacyOutputFlags(t *testing.T) {
	if rootCmd.PersistentFlags().Lookup("human") != nil {
		t.Fatalf("expected --human flag to be removed")
	}

	if rootCmd.PersistentFlags().Lookup("output") != nil {
		t.Fatalf("expected --output flag to be removed")
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
