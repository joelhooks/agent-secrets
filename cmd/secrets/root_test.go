package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/spf13/cobra"
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

func TestRootCommandRegistersExpectedSubcommands(t *testing.T) {
	expected := []string{
		"init",
		"add",
		"list",
		"update",
		"delete",
		"lease",
		"revoke",
		"audit",
		"status",
		"health",
		"scan",
		"cleanup",
		"env",
		"exec",
		"version",
		"self-update",
	}

	registered := make(map[string]struct{})
	for _, c := range rootCmd.Commands() {
		registered[c.Name()] = struct{}{}
	}

	for _, name := range expected {
		if _, ok := registered[name]; !ok {
			t.Fatalf("expected subcommand %q to be registered", name)
		}
	}
}

func TestLeaseCommandDefaultOutputIsRawAndJSONOutputsEnvelope(t *testing.T) {
	rawSocket := startLeaseRPCServer(t, daemon.LeaseResult{
		LeaseID:   "lease-raw",
		Value:     "raw-value",
		ExpiresAt: time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC),
	})
	restoreRaw := setLeaseTestGlobals(rawSocket)
	rawOutput := captureLeaseStdout(t, func() {
		if err := leaseCmd.RunE(leaseCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})
	restoreRaw()

	if rawOutput != "raw-value" {
		t.Fatalf("expected raw output by default, got %q", rawOutput)
	}

	jsonSocket := startLeaseRPCServer(t, daemon.LeaseResult{
		LeaseID:   "lease-json",
		Value:     "json-value",
		ExpiresAt: time.Date(2026, 2, 19, 12, 5, 0, 0, time.UTC),
	})
	restoreJSON := setLeaseTestGlobals(jsonSocket)
	defer restoreJSON()

	restoreJSONFlag := setLeaseFlag(t, "json", "true")
	defer restoreJSONFlag()

	jsonOutput := captureLeaseStdout(t, func() {
		if err := leaseCmd.RunE(leaseCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	var resp struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(jsonOutput), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, jsonOutput)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true for --json output")
	}
	if resp.Command != "secrets lease" {
		t.Fatalf("expected command=secrets lease, got %q", resp.Command)
	}
}

func TestLeaseCommandParsesRawTTLAndClientIDFlags(t *testing.T) {
	restoreTTL := setLeaseFlag(t, "ttl", "45m")
	defer restoreTTL()

	restoreClientID := setLeaseFlag(t, "client-id", "agent-test")
	defer restoreClientID()

	restoreRaw := setLeaseFlag(t, "raw", "true")
	defer restoreRaw()

	if leaseTTL != "45m" {
		t.Fatalf("expected lease ttl to be parsed as 45m, got %q", leaseTTL)
	}
	if leaseClientID != "agent-test" {
		t.Fatalf("expected lease client-id to be parsed as agent-test, got %q", leaseClientID)
	}
	if !leaseRaw {
		t.Fatalf("expected --raw to be accepted and parsed")
	}
}

func TestAddCommandFlagsParsed(t *testing.T) {
	restoreValueFlag := setCommandFlag(t, addCmd, "value", "secret-value")
	defer restoreValueFlag()

	restoreRotateViaFlag := setCommandFlag(t, addCmd, "rotate-via", "op run --secret")
	defer restoreRotateViaFlag()

	if addValue != "secret-value" {
		t.Fatalf("expected --value to be parsed into addValue, got %q", addValue)
	}
	if addRotateVia != "op run --secret" {
		t.Fatalf("expected --rotate-via to be parsed into addRotateVia, got %q", addRotateVia)
	}
}

func TestDeleteCommandArgsAndFlags(t *testing.T) {
	if err := deleteCmd.Args(deleteCmd, []string{}); err == nil {
		t.Fatalf("expected delete command to require a name argument")
	}
	if err := deleteCmd.Args(deleteCmd, []string{"github_token"}); err != nil {
		t.Fatalf("expected delete command to accept one argument, got %v", err)
	}

	foundRM := false
	for _, alias := range deleteCmd.Aliases {
		if alias == "rm" {
			foundRM = true
			break
		}
	}
	if !foundRM {
		t.Fatalf("expected delete command aliases to include rm")
	}

	restoreForceFlag := setCommandFlag(t, deleteCmd, "force", "false")
	defer restoreForceFlag()
	if deleteForce {
		t.Fatalf("expected --force flag value to be parsed")
	}
}

func TestRootCommandDeprecatedFlagsAreAccepted(t *testing.T) {
	restoreHumanFlag := setPersistentRootFlag(t, "human", "true")
	defer restoreHumanFlag()

	restoreOutputFlag := setPersistentRootFlag(t, "output", "json")
	defer restoreOutputFlag()
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

func setPersistentRootFlag(t *testing.T, name, value string) func() {
	t.Helper()

	flag := rootCmd.PersistentFlags().Lookup(name)
	if flag == nil {
		t.Fatalf("expected root persistent flag %q to exist", name)
	}

	origValue := flag.Value.String()
	origChanged := flag.Changed
	if err := rootCmd.PersistentFlags().Set(name, value); err != nil {
		t.Fatalf("failed to set root persistent flag %q: %v", name, err)
	}

	return func() {
		_ = rootCmd.PersistentFlags().Set(name, origValue)
		flag.Changed = origChanged
	}
}

func setCommandFlag(t *testing.T, cmd *cobra.Command, name, value string) func() {
	t.Helper()

	flag := cmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("expected flag %q to exist", name)
	}

	origValue := flag.Value.String()
	origChanged := flag.Changed
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("failed to set flag %q: %v", name, err)
	}

	return func() {
		_ = cmd.Flags().Set(name, origValue)
		flag.Changed = origChanged
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
