package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestSuccessEnvelopeShape(t *testing.T) {
	resp := Success("secrets status", map[string]interface{}{"running": true}, ActionStatus())

	if !resp.OK {
		t.Fatalf("expected OK=true")
	}
	if !resp.Success {
		t.Fatalf("expected Success=true")
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
	if !strings.Contains(jsonText, `"success":true`) {
		t.Fatalf("expected success alias in json: %s", jsonText)
	}
	if strings.Contains(jsonText, `"data"`) || strings.Contains(jsonText, `"actions"`) {
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
	if resp.Success {
		t.Fatalf("expected Success=false")
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
	if !strings.Contains(out, `"success": false`) {
		t.Fatalf("expected success alias in json output, got %q", out)
	}

	var decoded Response
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("failed to parse json output: %v", err)
	}
	if decoded.Fix != "start the daemon with: secrets serve &" {
		t.Fatalf("unexpected fix field in json output: %q", decoded.Fix)
	}
	if decoded.Success != decoded.OK {
		t.Fatalf("expected success to mirror ok, got success=%t ok=%t", decoded.Success, decoded.OK)
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

func TestErrorInfersDaemonFix(t *testing.T) {
	resp := Error("secrets status", errors.New("failed to connect to daemon at /tmp/agent-secrets.sock: connect: connection refused (is the daemon running?)"))
	if resp.Fix != "Start the daemon: secrets serve &" {
		t.Fatalf("expected daemon fix, got %q", resp.Fix)
	}
}

func TestErrorInfersStoreNotInitializedFix(t *testing.T) {
	resp := Error("secrets lease", fmt.Errorf("failed to acquire lease: %w", types.ErrStoreNotInitialized))
	if resp.Fix != "Initialize the store: secrets init" {
		t.Fatalf("expected store init fix, got %q", resp.Fix)
	}
}

func TestErrorInfersPermissionFix(t *testing.T) {
	resp := Error("secrets serve", &store.PermissionError{
		Path:     "/tmp/identity.age",
		Current:  0644,
		Expected: 0600,
	})
	if resp.Fix != "Check file permissions on ~/.agent-secrets/ or use --skip-permission-check" {
		t.Fatalf("expected permission fix, got %q", resp.Fix)
	}
}

func TestErrorInfersSocketTimeoutFix(t *testing.T) {
	resp := Error("secrets status", errors.New("daemon unresponsive (timeout after 5s)"))
	if resp.Fix != "Daemon may be overloaded. Check: secrets health" {
		t.Fatalf("expected timeout fix, got %q", resp.Fix)
	}
}

func TestErrorInfersSecretExistsFix(t *testing.T) {
	resp := Error("secrets add", errors.New("failed to add secret: RPC error -32000: secret \"github_token\": secret already exists"))
	if resp.Fix != "Use a different name, or update the existing secret" {
		t.Fatalf("expected secret-exists fix, got %q", resp.Fix)
	}
}

func TestErrorInfersLeaseNotFoundFix(t *testing.T) {
	resp := Error("secrets revoke", errors.New("failed to revoke lease: RPC error -32002: lease not found"))
	if resp.Fix != "Check active leases: secrets status" {
		t.Fatalf("expected lease-not-found fix, got %q", resp.Fix)
	}
}

func TestErrorMsgWithFixUsesProvidedFix(t *testing.T) {
	resp := ErrorMsgWithFix("secrets add", "secret value cannot be empty", "Provide a value via --value, stdin pipe, or interactive prompt")
	if resp.Fix != "Provide a value via --value, stdin pipe, or interactive prompt" {
		t.Fatalf("expected provided fix, got %q", resp.Fix)
	}
}

func TestErrorMsgInfersEmptyValueFix(t *testing.T) {
	resp := ErrorMsg("secrets add", "secret value cannot be empty")
	if resp.Fix != "Provide a value via --value, stdin pipe, or interactive prompt" {
		t.Fatalf("expected empty-value fix, got %q", resp.Fix)
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

func TestDeprecationWarningPrintsToStderr(t *testing.T) {
	out := captureStderr(t, func() {
		DeprecationWarning("WARNING: deprecated flag")
	})

	if !strings.Contains(out, "WARNING: deprecated flag") {
		t.Fatalf("expected warning in stderr, got %q", out)
	}
}

func TestErrorEnvelopeShapeIncludesFixAndNextActions(t *testing.T) {
	resp := Error("secrets lease", types.ErrSecretNotFound, ActionStatus(), ActionHelp("lease"))

	if resp.OK {
		t.Fatalf("expected OK=false")
	}
	if resp.Success {
		t.Fatalf("expected Success=false")
	}
	if resp.Command != "secrets lease" {
		t.Fatalf("unexpected command: %q", resp.Command)
	}
	if resp.Error == nil {
		t.Fatalf("expected error detail")
	}
	if resp.Error.Message == "" || resp.Error.Code == "" {
		t.Fatalf("expected structured error fields, got %#v", resp.Error)
	}
	if resp.Fix == "" {
		t.Fatalf("expected fix field")
	}
	if len(resp.NextActions) != 2 {
		t.Fatalf("expected two next actions, got %d", len(resp.NextActions))
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded["fix"] == "" {
		t.Fatalf("expected fix in serialized response: %s", string(encoded))
	}
	if _, ok := decoded["next_actions"]; !ok {
		t.Fatalf("expected next_actions in serialized response: %s", string(encoded))
	}
}

func TestErrorWithFixPopulatesFixField(t *testing.T) {
	resp := ErrorWithFix("secrets add", types.ErrSecretExists, "Use `secrets update github_token` instead.")

	if resp.Fix != "Use `secrets update github_token` instead." {
		t.Fatalf("expected explicit fix to be used, got %q", resp.Fix)
	}
}

func TestSuccessAndErrorSuccessAliasMirrorsOK(t *testing.T) {
	successResp := Success("secrets status", map[string]bool{"running": true})
	if successResp.Success != successResp.OK {
		t.Fatalf("expected Success to mirror OK for success response")
	}

	errorResp := ErrorMsg("secrets add", "invalid input")
	if errorResp.Success != errorResp.OK {
		t.Fatalf("expected Success to mirror OK for error response")
	}
}

func TestSuccessNextActionsSerialization(t *testing.T) {
	resp := Success(
		"secrets add",
		map[string]string{"name": "github_token"},
		ActionLease("github_token"),
		ActionStatus(),
	)

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded struct {
		NextActions []Action `json:"next_actions"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(decoded.NextActions) != 2 {
		t.Fatalf("expected two serialized next actions, got %d", len(decoded.NextActions))
	}
	if decoded.NextActions[0].Command == "" || decoded.NextActions[1].Command == "" {
		t.Fatalf("expected command strings in next actions: %#v", decoded.NextActions)
	}
}

func TestErrorMsgWithCodeUsesMappedCode(t *testing.T) {
	resp := ErrorMsgWithCode("secrets lease", "timed out", types.ExitTimeout)
	if resp.Error == nil {
		t.Fatalf("expected error detail")
	}
	if resp.Error.Code != "timeout" {
		t.Fatalf("expected timeout code, got %q", resp.Error.Code)
	}
}

func TestErrorWithCodeHandlesNilError(t *testing.T) {
	resp := ErrorWithCode("secrets lease", nil, types.ExitGenericError)
	if resp.Error == nil {
		t.Fatalf("expected error detail")
	}
	if resp.Error.Message != "unknown error" {
		t.Fatalf("expected unknown error message, got %q", resp.Error.Message)
	}
}

func TestErrorInfersDaemonFixFromSentinel(t *testing.T) {
	resp := Error("secrets status", types.ErrDaemonNotRunning)
	if resp.Fix != "Start the daemon: secrets serve &" {
		t.Fatalf("expected daemon fix, got %q", resp.Fix)
	}
}

func TestActionBuildersReturnExpectedCommands(t *testing.T) {
	cases := []struct {
		name   string
		action Action
		cmd    string
	}{
		{name: "init", action: ActionInit(), cmd: "secrets init"},
		{name: "add default", action: ActionAdd(""), cmd: "secrets add <name>"},
		{name: "add named", action: ActionAdd("github_token"), cmd: "secrets add github_token"},
		{name: "add rotation", action: ActionAddWithRotation(), cmd: "secrets add <name> --rotate-via '<command>'"},
		{name: "lease default", action: ActionLease(""), cmd: "secrets lease <name> --json"},
		{name: "lease named", action: ActionLease("github_token"), cmd: "secrets lease github_token --json"},
		{name: "lease ttl", action: ActionLeaseWithTTL("github_token", "30m"), cmd: "secrets lease github_token --ttl 30m --json"},
		{name: "revoke", action: ActionRevoke("lease-123"), cmd: "secrets revoke lease-123"},
		{name: "revoke all", action: ActionRevokeAll(), cmd: "secrets revoke --all"},
		{name: "status", action: ActionStatus(), cmd: "secrets status"},
		{name: "audit", action: ActionAudit(), cmd: "secrets audit"},
		{name: "audit tail", action: ActionAuditTail(25), cmd: "secrets audit --tail 25"},
		{name: "update", action: ActionUpdate(), cmd: "secrets self-update"},
		{name: "help", action: ActionHelp("lease"), cmd: "secrets lease --help"},
		{name: "scan", action: ActionScan(), cmd: "secrets scan"},
		{name: "scan path default", action: ActionScanPath(""), cmd: "secrets scan <path>"},
		{name: "scan path", action: ActionScanPath("./cmd"), cmd: "secrets scan ./cmd"},
		{name: "import secret", action: ActionImportSecret("github_token", ""), cmd: "secrets add github_token"},
		{name: "import secret from env", action: ActionImportSecret("github_token", ".env"), cmd: "secrets add github_token --from-env .env"},
		{name: "env", action: ActionEnv(), cmd: "secrets env"},
		{name: "env force", action: ActionEnvForce(), cmd: "secrets env --force"},
		{name: "exec default", action: ActionExec(""), cmd: "secrets exec -- <command>"},
		{name: "exec cmd", action: ActionExec("npm run deploy"), cmd: "secrets exec -- npm run deploy"},
		{name: "cleanup", action: ActionCleanup(), cmd: "secrets cleanup"},
	}

	for _, tc := range cases {
		if tc.action.Command != tc.cmd {
			t.Fatalf("%s: expected command %q, got %q", tc.name, tc.cmd, tc.action.Command)
		}
	}
}

func TestActionsAfterAddReturnsContextualActions(t *testing.T) {
	actions := ActionsAfterAdd("github_token")
	if len(actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(actions))
	}
	if actions[0].Command != "secrets lease github_token --json" {
		t.Fatalf("unexpected first action: %#v", actions[0])
	}
	if actions[1].Command != "secrets lease github_token --ttl 30m --json" {
		t.Fatalf("unexpected second action: %#v", actions[1])
	}
}

func TestActionsAfterLeaseReturnsContextualActions(t *testing.T) {
	actions := ActionsAfterLease("lease-123", "github_token")
	if len(actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(actions))
	}
	if actions[0].Command != "secrets revoke lease-123" {
		t.Fatalf("unexpected first action: %#v", actions[0])
	}
	if actions[1].Command != "secrets lease github_token --json" {
		t.Fatalf("unexpected second action: %#v", actions[1])
	}
}

func TestActionsWhenEmptyAndNotInitialized(t *testing.T) {
	empty := ActionsWhenEmpty()
	if len(empty) != 2 {
		t.Fatalf("expected 2 empty-state actions, got %d", len(empty))
	}
	if empty[0].Command != "secrets add <name>" {
		t.Fatalf("unexpected empty-state action: %#v", empty[0])
	}

	notInit := ActionsWhenNotInitialized()
	if len(notInit) != 1 {
		t.Fatalf("expected one not-initialized action, got %d", len(notInit))
	}
	if notInit[0].Command != "secrets init" {
		t.Fatalf("unexpected not-initialized action: %#v", notInit[0])
	}
}

func TestActionsAfterInitAndForSecrets(t *testing.T) {
	afterInit := ActionsAfterInit()
	if len(afterInit) != 3 {
		t.Fatalf("expected 3 after-init actions, got %d", len(afterInit))
	}

	forSecrets := ActionsForSecrets([]string{"github_token", "vercel_token"})
	if len(forSecrets) != 2 {
		t.Fatalf("expected 2 actions for secrets, got %d", len(forSecrets))
	}
	if forSecrets[0].Command != "secrets lease github_token --json" {
		t.Fatalf("unexpected command: %q", forSecrets[0].Command)
	}
	if forSecrets[1].Command != "secrets lease vercel_token --json" {
		t.Fatalf("unexpected command: %q", forSecrets[1].Command)
	}
}

func TestActionsAfterScanAndAfterEnv(t *testing.T) {
	whenFound := ActionsAfterScan(2)
	if len(whenFound) != 3 {
		t.Fatalf("expected 3 actions when scan finds secrets, got %d", len(whenFound))
	}
	if whenFound[0].Command != "secrets add " {
		t.Fatalf("unexpected first scan action command: %q", whenFound[0].Command)
	}

	whenEmpty := ActionsAfterScan(0)
	if len(whenEmpty) != 2 {
		t.Fatalf("expected 2 actions when scan finds none, got %d", len(whenEmpty))
	}
	if whenEmpty[0].Command != "secrets scan <path>" {
		t.Fatalf("unexpected empty scan action: %q", whenEmpty[0].Command)
	}

	afterEnv := ActionsAfterEnv(".env")
	if len(afterEnv) != 3 {
		t.Fatalf("expected 3 after-env actions, got %d", len(afterEnv))
	}
	if afterEnv[0].Command != "secrets exec -- <command>" {
		t.Fatalf("unexpected first env action: %q", afterEnv[0].Command)
	}
}

func TestBuildEnvExportEscapesSingleQuotes(t *testing.T) {
	export := BuildEnvExport("API_TOKEN", "it's-secret")
	if export != "export API_TOKEN='it'\\''s-secret'" {
		t.Fatalf("unexpected export: %q", export)
	}
}

func TestDeprecationWarningWritesOnlyToStderrAndTrims(t *testing.T) {
	stdout := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			DeprecationWarning("   WARNING: --raw is deprecated   ")
		})
	})
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}

	stderr := captureStderr(t, func() {
		DeprecationWarning("   WARNING: --raw is deprecated   ")
	})
	if strings.TrimSpace(stderr) != "WARNING: --raw is deprecated" {
		t.Fatalf("unexpected deprecation warning format: %q", stderr)
	}

	blank := captureStderr(t, func() {
		DeprecationWarning("   ")
	})
	if strings.TrimSpace(blank) != "" {
		t.Fatalf("expected blank warning to produce no output, got %q", blank)
	}
}

func TestPrintFallsBackToStderrWhenStdoutWriteFails(t *testing.T) {
	origStdout := os.Stdout
	origStderr := os.Stderr

	_, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe failed: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe failed: %v", err)
	}

	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter

	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}

	Print(Success("secrets status", map[string]bool{"running": true}))

	os.Stdout = origStdout
	os.Stderr = origStderr
	_ = stderrWriter.Close()

	errOutput, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("failed to read stderr: %v", err)
	}
	if !strings.Contains(string(errOutput), "Error formatting output:") {
		t.Fatalf("expected print fallback error, got %q", string(errOutput))
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

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	return string(out)
}
