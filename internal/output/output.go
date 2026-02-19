// Package output provides HATEOAS-style responses for the secrets CLI.
// All output is JSON for agent consumption.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/types"
)

// Action represents a possible next action (HATEOAS-style).
type Action struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// ErrorDetail contains structured error metadata.
type ErrorDetail struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Response is the standard CLI response format.
type Response struct {
	OK          bool         `json:"ok"`
	Command     string       `json:"command"`
	Result      interface{}  `json:"result,omitempty"`
	Error       *ErrorDetail `json:"error,omitempty"`
	Fix         string       `json:"fix,omitempty"`
	NextActions []Action     `json:"next_actions,omitempty"`
	ExitCode    int          `json:"-"`
}

// UpdateInfo contains version update information for update checks.
type UpdateInfo struct {
	Available      bool   `json:"available"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Command        string `json:"command,omitempty"`
}

// Version info (set by ldflags).
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Print outputs the response in JSON.
func Print(r Response) {
	if err := printJSON(r); err != nil {
		// Fallback to simple error print if formatting fails.
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
	}
}

// Success creates a successful response.
func Success(command string, result interface{}, actions ...Action) Response {
	return Response{
		OK:          true,
		Command:     command,
		Result:      result,
		NextActions: actions,
		ExitCode:    types.ExitSuccess,
	}
}

// Error creates an error response with appropriate exit code.
func Error(command string, err error, actions ...Action) Response {
	exitCode := types.ExitCodeFromError(err)
	errorDetail, fix := buildErrorDetail(err, exitCode)

	return Response{
		OK:          false,
		Command:     command,
		Error:       errorDetail,
		Fix:         fix,
		NextActions: actions,
		ExitCode:    exitCode,
	}
}

// ErrorMsg creates an error response from a string.
func ErrorMsg(command, msg string, actions ...Action) Response {
	exitCode := types.ExitGenericError
	fix := inferFix(nil, msg, defaultFix)
	return Response{
		OK:      false,
		Command: command,
		Error: &ErrorDetail{
			Message: msg,
			Code:    types.ErrorCodeFromExitCode(exitCode),
		},
		Fix:         fix,
		NextActions: actions,
		ExitCode:    exitCode,
	}
}

// ErrorWithCode creates an error response with a specific exit code.
func ErrorWithCode(command string, err error, exitCode int, actions ...Action) Response {
	errorDetail, fix := buildErrorDetail(err, exitCode)

	return Response{
		OK:          false,
		Command:     command,
		Error:       errorDetail,
		Fix:         fix,
		NextActions: actions,
		ExitCode:    exitCode,
	}
}

// ErrorMsgWithCode creates an error response from a string with specific exit code.
func ErrorMsgWithCode(command, msg string, exitCode int, actions ...Action) Response {
	fix := inferFix(nil, msg, defaultFix)
	return Response{
		OK:      false,
		Command: command,
		Error: &ErrorDetail{
			Message: msg,
			Code:    types.ErrorCodeFromExitCode(exitCode),
		},
		Fix:         fix,
		NextActions: actions,
		ExitCode:    exitCode,
	}
}

// Fatal prints an error response and exits with the appropriate exit code.
func Fatal(r Response) {
	Print(r)
	if r.ExitCode != 0 {
		os.Exit(r.ExitCode)
	}
	os.Exit(types.ExitGenericError)
}

// FatalError prints an error and exits with the appropriate exit code.
func FatalError(command string, err error, actions ...Action) {
	Fatal(Error(command, err, actions...))
}

// FatalMsg prints an error message and exits with generic error code.
func FatalMsg(command, msg string, actions ...Action) {
	Fatal(ErrorMsg(command, msg, actions...))
}

func printJSON(r Response) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

const defaultFix = "Review the error details and run `secrets --help` for usage."

const (
	fixDaemonNotRunning    = "Start the daemon: secrets serve &"
	fixSecretNotFound      = "Check available secrets: secrets status"
	fixSecretExists        = "Use a different name, or update the existing secret"
	fixLeaseNotFound       = "Check active leases: secrets status"
	fixEmptyValue          = "Provide a value via --value, stdin pipe, or interactive prompt"
	fixStoreNotInitialized = "Initialize the store: secrets init"
	fixPermissionError     = "Check file permissions on ~/.agent-secrets/ or use --skip-permission-check"
	fixSocketTimeout       = "Daemon may be overloaded. Check: secrets health"
)

func buildErrorDetail(err error, exitCode int) (*ErrorDetail, string) {
	if err == nil {
		return &ErrorDetail{
			Message: "unknown error",
			Code:    types.ErrorCodeFromExitCode(exitCode),
		}, defaultFix
	}

	message := strings.TrimSpace(err.Error())
	fix := defaultFix

	var userErr *types.UserError
	if errors.As(err, &userErr) {
		if userErr.What != "" {
			message = userErr.What
		}
		if userErr.Fix() != "" {
			fix = userErr.Fix()
		}
	}

	fix = inferFix(err, message, fix)

	return &ErrorDetail{
		Message: message,
		Code:    types.ErrorCodeFromExitCode(exitCode),
	}, fix
}

// ErrorWithFix creates an error response and forces a specific fix message.
func ErrorWithFix(command string, err error, fix string, actions ...Action) Response {
	resp := Error(command, err, actions...)
	if trimmed := strings.TrimSpace(fix); trimmed != "" {
		resp.Fix = trimmed
	}
	return resp
}

// ErrorMsgWithFix creates an error response from a string with an explicit fix.
func ErrorMsgWithFix(command, msg, fix string, actions ...Action) Response {
	resp := ErrorMsg(command, msg, actions...)
	if trimmed := strings.TrimSpace(fix); trimmed != "" {
		resp.Fix = trimmed
	}
	return resp
}

func inferFix(err error, message, fallback string) string {
	msg := strings.ToLower(strings.TrimSpace(message))
	if msg == "" && err != nil {
		msg = strings.ToLower(strings.TrimSpace(err.Error()))
	}

	switch {
	case isSocketTimeoutError(err, msg):
		return fixSocketTimeout
	case isPermissionError(err, msg):
		return fixPermissionError
	case errors.Is(err, types.ErrStoreNotInitialized), strings.Contains(msg, "store not initialized"):
		return fixStoreNotInitialized
	case errors.Is(err, types.ErrSecretNotFound), strings.Contains(msg, "secret not found"):
		return fixSecretNotFound
	case errors.Is(err, types.ErrSecretExists), strings.Contains(msg, "secret already exists"):
		return fixSecretExists
	case errors.Is(err, types.ErrLeaseNotFound), strings.Contains(msg, "lease not found"):
		return fixLeaseNotFound
	case strings.Contains(msg, "secret value cannot be empty"),
		strings.Contains(msg, "secret value is required"),
		strings.Contains(msg, "empty value"):
		return fixEmptyValue
	case isDaemonNotRunningError(err, msg):
		return fixDaemonNotRunning
	}

	return fallback
}

func isDaemonNotRunningError(err error, message string) bool {
	if errors.Is(err, types.ErrDaemonNotRunning) || errors.Is(err, types.ErrConnectionFailed) {
		return true
	}

	return strings.Contains(message, "failed to connect to daemon") ||
		strings.Contains(message, "is the daemon running") ||
		strings.Contains(message, "connection refused")
}

func isSocketTimeoutError(_ error, message string) bool {
	return strings.Contains(message, "daemon connection timeout") ||
		strings.Contains(message, "daemon unresponsive") ||
		(strings.Contains(message, "failed to connect to daemon") && strings.Contains(message, "timeout")) ||
		(strings.Contains(message, "daemon") && strings.Contains(message, "i/o timeout"))
}

func isPermissionError(_ error, message string) bool {
	return strings.Contains(message, "insecure permissions") ||
		strings.Contains(message, "key file has insecure permissions") ||
		strings.Contains(message, "permission denied") ||
		strings.Contains(message, "failed to set socket permissions")
}

// Common action builders.
func ActionInit() Action {
	return Action{
		Description: "Initialize the secrets store",
		Command:     "secrets init",
	}
}

func ActionAdd(name string) Action {
	cmd := "secrets add <name>"
	if name != "" {
		cmd = fmt.Sprintf("secrets add %s", name)
	}
	return Action{
		Description: "Add a new secret",
		Command:     cmd,
	}
}

func ActionAddWithRotation() Action {
	return Action{
		Description: "Add a secret with auto-rotation",
		Command:     "secrets add <name> --rotate-via '<command>'",
	}
}

func ActionLease(name string) Action {
	cmd := "secrets lease <name> --json"
	if name != "" {
		cmd = fmt.Sprintf("secrets lease %s --json", name)
	}
	return Action{
		Description: "Get a time-bounded lease for a secret (JSON response)",
		Command:     cmd,
	}
}

func ActionLeaseWithTTL(name, ttl string) Action {
	return Action{
		Description: fmt.Sprintf("Lease %s with custom TTL (JSON response)", name),
		Command:     fmt.Sprintf("secrets lease %s --ttl %s --json", name, ttl),
	}
}

func ActionRevoke(leaseID string) Action {
	return Action{
		Description: "Revoke a specific lease",
		Command:     fmt.Sprintf("secrets revoke %s", leaseID),
	}
}

func ActionRevokeAll() Action {
	return Action{
		Description: "KILLSWITCH: Revoke all active leases",
		Command:     "secrets revoke --all",
	}
}

func ActionStatus() Action {
	return Action{
		Description: "Check daemon status and active leases",
		Command:     "secrets status",
	}
}

func ActionAudit() Action {
	return Action{
		Description: "View the audit log",
		Command:     "secrets audit",
	}
}

func ActionAuditTail(n int) Action {
	return Action{
		Description: fmt.Sprintf("View last %d audit entries", n),
		Command:     fmt.Sprintf("secrets audit --tail %d", n),
	}
}

func ActionUpdate() Action {
	return Action{
		Description: "Update to the latest version",
		Command:     "secrets update",
	}
}

func ActionHelp(cmd string) Action {
	return Action{
		Description: fmt.Sprintf("Get help for %s", cmd),
		Command:     fmt.Sprintf("secrets %s --help", cmd),
	}
}

// SecretsList returns actions for available secrets.
func ActionsForSecrets(names []string) []Action {
	actions := make([]Action, 0, len(names))
	for _, name := range names {
		actions = append(actions, ActionLease(name))
	}
	return actions
}

// ActionsAfterInit returns suggested actions after initialization.
func ActionsAfterInit() []Action {
	return []Action{
		ActionAdd(""),
		ActionAddWithRotation(),
		ActionHelp("add"),
	}
}

// ActionsAfterAdd returns suggested actions after adding a secret.
func ActionsAfterAdd(name string) []Action {
	return []Action{
		ActionLease(name),
		ActionLeaseWithTTL(name, "30m"),
		ActionAdd(""),
		ActionStatus(),
	}
}

// ActionsAfterLease returns suggested actions after getting a lease.
func ActionsAfterLease(leaseID, secretName string) []Action {
	return []Action{
		ActionRevoke(leaseID),
		ActionLease(secretName),
		ActionStatus(),
		ActionRevokeAll(),
	}
}

// ActionsWhenEmpty returns actions when no secrets exist.
func ActionsWhenEmpty() []Action {
	return []Action{
		ActionAdd(""),
		ActionAddWithRotation(),
	}
}

// ActionsWhenNotInitialized returns actions when store isn't initialized.
func ActionsWhenNotInitialized() []Action {
	return []Action{
		ActionInit(),
	}
}

// BuildEnvExport formats a lease for shell export.
func BuildEnvExport(varName, value string) string {
	// Escape single quotes in value.
	escaped := strings.ReplaceAll(value, "'", "'\\''")
	return fmt.Sprintf("export %s='%s'", varName, escaped)
}

// ActionScan suggests running a scan to find hardcoded secrets.
func ActionScan() Action {
	return Action{
		Description: "Scan for hardcoded secrets in your repository",
		Command:     "secrets scan",
	}
}

// ActionScanPath suggests scanning a specific path.
func ActionScanPath(path string) Action {
	cmd := "secrets scan <path>"
	if path != "" {
		cmd = fmt.Sprintf("secrets scan %s", path)
	}
	return Action{
		Description: fmt.Sprintf("Scan %s for hardcoded secrets", path),
		Command:     cmd,
	}
}

// ActionImportSecret suggests importing a found secret to the secrets store.
func ActionImportSecret(name, envFile string) Action {
	var cmd string
	if envFile != "" {
		cmd = fmt.Sprintf("secrets add %s --from-env %s", name, envFile)
	} else {
		cmd = fmt.Sprintf("secrets add %s", name)
	}

	desc := fmt.Sprintf("Import %s into secrets store", name)
	if envFile != "" {
		desc = fmt.Sprintf("Import %s from %s", name, envFile)
	}

	return Action{
		Description: desc,
		Command:     cmd,
	}
}

// ActionsAfterScan returns contextual actions after scan completes.
func ActionsAfterScan(count int) []Action {
	if count == 0 {
		return []Action{
			ActionScanPath(""),
			ActionAdd(""),
		}
	}

	// When secrets are found, suggest import and rotation.
	return []Action{
		ActionImportSecret("", ""),
		ActionAddWithRotation(),
		ActionAudit(),
	}
}

// ActionEnv suggests generating .env file from secrets.
func ActionEnv() Action {
	return Action{
		Description: "Generate .env file from .secrets.json config",
		Command:     "secrets env",
	}
}

// ActionEnvForce suggests force-overwriting existing .env file.
func ActionEnvForce() Action {
	return Action{
		Description: "Force overwrite existing .env file",
		Command:     "secrets env --force",
	}
}

// ActionExec suggests running a command with secrets loaded.
func ActionExec(cmd string) Action {
	command := "secrets exec -- <command>"
	if cmd != "" {
		command = fmt.Sprintf("secrets exec -- %s", cmd)
	}
	return Action{
		Description: "Run command with secrets as environment variables",
		Command:     command,
	}
}

// ActionCleanup suggests removing expired lease env files.
func ActionCleanup() Action {
	return Action{
		Description: "Remove expired lease environment files",
		Command:     "secrets cleanup",
	}
}

// ActionsAfterEnv returns suggested actions after env file generation.
func ActionsAfterEnv(envFile string) []Action {
	return []Action{
		ActionExec(""),
		ActionCleanup(),
		ActionStatus(),
	}
}
