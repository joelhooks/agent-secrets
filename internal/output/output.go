// Package output provides HATEOAS-style responses for the secrets CLI.
// By default, all output is JSON for agent consumption.
// Use --human flag for human-readable output.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Action represents a possible next action (HATEOAS-style)
type Action struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Dangerous   bool   `json:"dangerous,omitempty"`
}

// Response is the standard CLI response format
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Actions []Action    `json:"actions,omitempty"`
	Update  *UpdateInfo `json:"update,omitempty"`
}

// UpdateInfo contains version update information
type UpdateInfo struct {
	Available      bool   `json:"available"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Command        string `json:"command,omitempty"`
}

// Global flag for human-readable output
var HumanMode bool

// Version info (set by ldflags)
var (
	Version = "dev"
	Commit  = "unknown"
)

// Print outputs the response in JSON (default) or human-readable format
func Print(r Response) {
	if HumanMode {
		printHuman(r)
	} else {
		printJSON(r)
	}
}

// Success creates a successful response
func Success(message string, data interface{}, actions ...Action) Response {
	return Response{
		Success: true,
		Message: message,
		Data:    data,
		Actions: actions,
	}
}

// Error creates an error response
func Error(err error, actions ...Action) Response {
	return Response{
		Success: false,
		Error:   err.Error(),
		Actions: actions,
	}
}

// ErrorMsg creates an error response from a string
func ErrorMsg(msg string, actions ...Action) Response {
	return Response{
		Success: false,
		Error:   msg,
		Actions: actions,
	}
}

func printJSON(r Response) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}

func printHuman(r Response) {
	if r.Success {
		if r.Message != "" {
			fmt.Printf("✓ %s\n", r.Message)
		}
		if r.Data != nil {
			printData(r.Data)
		}
	} else {
		fmt.Printf("✗ Error: %s\n", r.Error)
	}

	// Print update warning
	if r.Update != nil && r.Update.Available {
		fmt.Printf("\n⚠ Update available: %s → %s\n", r.Update.CurrentVersion, r.Update.LatestVersion)
		fmt.Printf("  Run: %s\n", r.Update.Command)
	}

	// Print available actions
	if len(r.Actions) > 0 {
		fmt.Println("\nNext steps:")
		for _, a := range r.Actions {
			prefix := "→"
			if a.Dangerous {
				prefix = "⚠"
			}
			fmt.Printf("  %s %s\n", prefix, a.Description)
			fmt.Printf("    $ %s\n", a.Command)
		}
	}
}

func printData(data interface{}) {
	switch v := data.(type) {
	case string:
		fmt.Println(v)
	case map[string]interface{}:
		for key, val := range v {
			fmt.Printf("  %s: %v\n", key, val)
		}
	default:
		// Fall back to JSON for complex types
		b, _ := json.MarshalIndent(data, "  ", "  ")
		fmt.Println(string(b))
	}
}

// Common action builders
func ActionInit() Action {
	return Action{
		Name:        "init",
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
		Name:        "add",
		Description: "Add a new secret",
		Command:     cmd,
	}
}

func ActionAddWithRotation() Action {
	return Action{
		Name:        "add_with_rotation",
		Description: "Add a secret with auto-rotation",
		Command:     "secrets add <name> --rotate-via '<command>'",
	}
}

func ActionLease(name string) Action {
	cmd := "secrets lease <name>"
	if name != "" {
		cmd = fmt.Sprintf("secrets lease %s", name)
	}
	return Action{
		Name:        "lease",
		Description: "Get a time-bounded lease for a secret",
		Command:     cmd,
	}
}

func ActionLeaseWithTTL(name, ttl string) Action {
	return Action{
		Name:        "lease_ttl",
		Description: fmt.Sprintf("Lease %s with custom TTL", name),
		Command:     fmt.Sprintf("secrets lease %s --ttl %s", name, ttl),
	}
}

func ActionRevoke(leaseID string) Action {
	return Action{
		Name:        "revoke",
		Description: "Revoke a specific lease",
		Command:     fmt.Sprintf("secrets revoke %s", leaseID),
	}
}

func ActionRevokeAll() Action {
	return Action{
		Name:        "revoke_all",
		Description: "KILLSWITCH: Revoke all active leases",
		Command:     "secrets revoke --all",
		Dangerous:   true,
	}
}

func ActionStatus() Action {
	return Action{
		Name:        "status",
		Description: "Check daemon status and active leases",
		Command:     "secrets status",
	}
}

func ActionAudit() Action {
	return Action{
		Name:        "audit",
		Description: "View the audit log",
		Command:     "secrets audit",
	}
}

func ActionAuditTail(n int) Action {
	return Action{
		Name:        "audit_tail",
		Description: fmt.Sprintf("View last %d audit entries", n),
		Command:     fmt.Sprintf("secrets audit --tail %d", n),
	}
}

func ActionUpdate() Action {
	return Action{
		Name:        "update",
		Description: "Update to the latest version",
		Command:     "secrets update",
	}
}

func ActionHelp(cmd string) Action {
	return Action{
		Name:        "help",
		Description: fmt.Sprintf("Get help for %s", cmd),
		Command:     fmt.Sprintf("secrets %s --help", cmd),
	}
}

// SecretsList returns actions for available secrets
func ActionsForSecrets(names []string) []Action {
	actions := make([]Action, 0, len(names))
	for _, name := range names {
		actions = append(actions, ActionLease(name))
	}
	return actions
}

// ActionsAfterInit returns suggested actions after initialization
func ActionsAfterInit() []Action {
	return []Action{
		ActionAdd(""),
		ActionAddWithRotation(),
		ActionHelp("add"),
	}
}

// ActionsAfterAdd returns suggested actions after adding a secret
func ActionsAfterAdd(name string) []Action {
	return []Action{
		ActionLease(name),
		ActionLeaseWithTTL(name, "30m"),
		ActionAdd(""),
		ActionStatus(),
	}
}

// ActionsAfterLease returns suggested actions after getting a lease
func ActionsAfterLease(leaseID, secretName string) []Action {
	return []Action{
		ActionRevoke(leaseID),
		ActionLease(secretName),
		ActionStatus(),
		ActionRevokeAll(),
	}
}

// ActionsWhenEmpty returns actions when no secrets exist
func ActionsWhenEmpty() []Action {
	return []Action{
		ActionAdd(""),
		ActionAddWithRotation(),
	}
}

// ActionsWhenNotInitialized returns actions when store isn't initialized
func ActionsWhenNotInitialized() []Action {
	return []Action{
		ActionInit(),
	}
}

// BuildEnvExport formats a lease for shell export
func BuildEnvExport(varName, value string) string {
	// Escape single quotes in value
	escaped := strings.ReplaceAll(value, "'", "'\\''")
	return fmt.Sprintf("export %s='%s'", varName, escaped)
}
