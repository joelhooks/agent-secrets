package types

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExitCodeFromError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: ExitSuccess},
		{name: "rotation timeout", err: ErrRotationTimeout, want: ExitTimeout},
		{name: "wrapped rotation timeout", err: fmt.Errorf("wrapped: %w", ErrRotationTimeout), want: ExitTimeout},
		{name: "daemon unavailable", err: ErrDaemonNotRunning, want: ExitDaemonUnavailable},
		{name: "wrapped daemon unavailable", err: fmt.Errorf("wrapped: %w", ErrDaemonNotRunning), want: ExitDaemonUnavailable},
		{name: "connection failed prefers daemon unavailable mapping", err: ErrConnectionFailed, want: ExitDaemonUnavailable},
		{name: "store corrupted", err: ErrStoreCorrupted, want: ExitDataError},
		{name: "wrapped store corrupted", err: fmt.Errorf("wrapped: %w", ErrStoreCorrupted), want: ExitDataError},
		{name: "socket exists", err: ErrSocketExists, want: ExitIOError},
		{name: "wrapped socket exists", err: fmt.Errorf("wrapped: %w", ErrSocketExists), want: ExitIOError},
		{name: "generic error fallback", err: errors.New("boom"), want: ExitGenericError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCodeFromError(tt.err); got != tt.want {
				t.Fatalf("ExitCodeFromError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestErrorCodeFromExitCode(t *testing.T) {
	tests := []struct {
		exitCode int
		want     string
	}{
		{ExitSuccess, "success"},
		{ExitMisuse, "misuse"},
		{ExitDataError, "data_error"},
		{ExitTimeout, "timeout"},
		{ExitIOError, "io_error"},
		{ExitProtocolError, "protocol_error"},
		{ExitDaemonUnavailable, "daemon_unavailable"},
		{ExitInternalError, "internal_error"},
		{999, "generic_error"},
	}

	for _, tt := range tests {
		if got := ErrorCodeFromExitCode(tt.exitCode); got != tt.want {
			t.Fatalf("ErrorCodeFromExitCode(%d) = %q, want %q", tt.exitCode, got, tt.want)
		}
	}
}

func TestUserError(t *testing.T) {
	userErr := NewUserError(
		"cannot connect to daemon",
		"commands requiring leases cannot run",
		"  Start daemon: secrets serve &  ",
		"secrets serve --help",
	)
	if userErr.What != "cannot connect to daemon" {
		t.Fatalf("What = %q", userErr.What)
	}
	if userErr.Why != "commands requiring leases cannot run" {
		t.Fatalf("Why = %q", userErr.Why)
	}
	if userErr.HelpRef != "secrets serve --help" {
		t.Fatalf("HelpRef = %q", userErr.HelpRef)
	}
	if userErr.Context == nil {
		t.Fatal("Context map should be initialized")
	}

	if got := userErr.Fix(); got != "Start daemon: secrets serve &" {
		t.Fatalf("Fix() = %q", got)
	}

	if ret := userErr.WithContext("socket", "/tmp/agent-secrets.sock"); ret != userErr {
		t.Fatal("WithContext should return the same pointer for chaining")
	}
	userErr.WithContext("client_id", "deploy-task")

	msg := userErr.Error()
	for _, want := range []string{
		"Error: cannot connect to daemon",
		"socket: /tmp/agent-secrets.sock",
		"client_id: deploy-task",
		"commands requiring leases cannot run",
		"Start daemon: secrets serve &",
		"See 'secrets serve --help' for more information.",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Error() output missing %q:\n%s", want, msg)
		}
	}
}

func TestStructuredErrorTypes(t *testing.T) {
	secretErr := NewSecretError("github_token", ErrSecretNotFound)
	if !errors.Is(secretErr, ErrSecretNotFound) {
		t.Fatal("SecretError should unwrap to ErrSecretNotFound")
	}
	if !strings.Contains(secretErr.Error(), `secret "github_token":`) {
		t.Fatalf("unexpected SecretError string: %q", secretErr.Error())
	}

	leaseErr := NewLeaseError("lease-1", "github_token", ErrLeaseExpired)
	if !errors.Is(leaseErr, ErrLeaseExpired) {
		t.Fatal("LeaseError should unwrap to ErrLeaseExpired")
	}
	if !strings.Contains(leaseErr.Error(), `lease "lease-1" for secret "github_token"`) {
		t.Fatalf("unexpected LeaseError string: %q", leaseErr.Error())
	}

	leaseErrNoID := NewLeaseError("", "github_token", ErrLeaseExpired)
	if !strings.Contains(leaseErrNoID.Error(), `lease for secret "github_token"`) {
		t.Fatalf("unexpected LeaseError without ID string: %q", leaseErrNoID.Error())
	}

	rotationErr := NewRotationError("github_token", "rotate.sh", "output", ErrRotationTimeout)
	if !errors.Is(rotationErr, ErrRotationTimeout) {
		t.Fatal("RotationError should unwrap to ErrRotationTimeout")
	}
	if rotationErr.Command != "rotate.sh" || rotationErr.Output != "output" {
		t.Fatalf("rotation context lost: %+v", rotationErr)
	}
	if !strings.Contains(rotationErr.Error(), `rotation of secret "github_token" failed`) {
		t.Fatalf("unexpected RotationError string: %q", rotationErr.Error())
	}
}

func TestErrAdapterNotAvailable(t *testing.T) {
	err := ErrAdapterNotAvailable{
		Adapter: "vercel",
		Reason:  "missing VERCEL_TOKEN",
	}

	if !errors.Is(err, ErrAdapterFailed) {
		t.Fatal("ErrAdapterNotAvailable should unwrap to ErrAdapterFailed")
	}
	if !strings.Contains(err.Error(), `adapter "vercel" not available`) {
		t.Fatalf("unexpected error string: %q", err.Error())
	}
}

func TestRPCErrorFromError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "secret not found", err: ErrSecretNotFound, want: RPCSecretNotFound},
		{name: "wrapped secret not found", err: fmt.Errorf("wrapped: %w", ErrSecretNotFound), want: RPCSecretNotFound},
		{name: "lease not found", err: ErrLeaseNotFound, want: RPCLeaseNotFound},
		{name: "lease expired", err: ErrLeaseExpired, want: RPCLeaseExpired},
		{name: "lease revoked", err: ErrLeaseRevoked, want: RPCLeaseExpired},
		{name: "rotation failed", err: ErrRotationFailed, want: RPCRotationFailed},
		{name: "rotation timeout", err: ErrRotationTimeout, want: RPCRotationFailed},
		{name: "encryption failed", err: ErrEncryptionFailed, want: RPCEncryptionError},
		{name: "decryption failed", err: ErrDecryptionFailed, want: RPCDecryptionError},
		{name: "unknown error", err: errors.New("boom"), want: RPCInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpcErr := RPCErrorFromError(tt.err)
			if rpcErr.Code != tt.want {
				t.Fatalf("RPCErrorFromError(%v).Code = %d, want %d", tt.err, rpcErr.Code, tt.want)
			}
			if rpcErr.Message != tt.err.Error() {
				t.Fatalf("RPCErrorFromError(%v).Message = %q, want %q", tt.err, rpcErr.Message, tt.err.Error())
			}
		})
	}
}

func TestErrorCodeConstants(t *testing.T) {
	if ExitSuccess != 0 || ExitGenericError != 1 || ExitMisuse != 2 {
		t.Fatalf("unexpected core exit code constants: success=%d generic=%d misuse=%d", ExitSuccess, ExitGenericError, ExitMisuse)
	}
	if ExitDataError != 64 || ExitTimeout != 65 || ExitIOError != 66 {
		t.Fatalf("unexpected sysexit constants: data=%d timeout=%d io=%d", ExitDataError, ExitTimeout, ExitIOError)
	}
	if RPCParseError != -32700 || RPCInvalidRequest != -32600 || RPCInternalError != -32603 {
		t.Fatalf("unexpected JSON-RPC constants: parse=%d invalid=%d internal=%d", RPCParseError, RPCInvalidRequest, RPCInternalError)
	}
	if RPCSecretNotFound != -32000 || RPCDecryptionError != -32005 {
		t.Fatalf("unexpected app RPC constants: secret=%d decrypt=%d", RPCSecretNotFound, RPCDecryptionError)
	}
}
