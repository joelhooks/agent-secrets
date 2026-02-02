// Package types defines shared types for the agent-secrets daemon.
package types

import (
	"errors"
	"fmt"
)

// Sentinel errors for the agent-secrets system.
var (
	// Store errors
	ErrSecretNotFound     = errors.New("secret not found")
	ErrSecretExists       = errors.New("secret already exists")
	ErrStoreNotInitialized = errors.New("store not initialized")
	ErrStoreCorrupted     = errors.New("store data corrupted")

	// Encryption errors
	ErrEncryptionFailed   = errors.New("encryption failed")
	ErrDecryptionFailed   = errors.New("decryption failed")
	ErrInvalidIdentity    = errors.New("invalid age identity")
	ErrIdentityNotFound   = errors.New("identity file not found")

	// Lease errors
	ErrLeaseNotFound      = errors.New("lease not found")
	ErrLeaseExpired       = errors.New("lease has expired")
	ErrLeaseRevoked       = errors.New("lease has been revoked")
	ErrInvalidTTL         = errors.New("invalid TTL duration")

	// Rotation errors
	ErrRotationFailed     = errors.New("rotation hook failed")
	ErrNoRotationHook     = errors.New("no rotation hook configured")
	ErrRotationTimeout    = errors.New("rotation hook timed out")

	// Killswitch errors
	ErrKillswitchActive   = errors.New("killswitch is active")

	// Daemon errors
	ErrDaemonNotRunning   = errors.New("daemon is not running")
	ErrDaemonAlreadyRunning = errors.New("daemon is already running")
	ErrSocketExists       = errors.New("socket file already exists")
	ErrConnectionFailed   = errors.New("connection to daemon failed")

	// Heartbeat errors
	ErrHeartbeatFailed    = errors.New("heartbeat check failed")
	ErrHeartbeatTimeout   = errors.New("heartbeat timed out")

	// Audit errors
	ErrAuditWriteFailed   = errors.New("failed to write audit entry")

	// Adapter errors
	ErrAdapterFailed      = errors.New("adapter operation failed")
)

// SecretError wraps an error with the secret name for context.
type SecretError struct {
	SecretName string
	Err        error
}

func (e *SecretError) Error() string {
	return fmt.Sprintf("secret %q: %v", e.SecretName, e.Err)
}

func (e *SecretError) Unwrap() error {
	return e.Err
}

// NewSecretError creates a new SecretError.
func NewSecretError(name string, err error) *SecretError {
	return &SecretError{SecretName: name, Err: err}
}

// LeaseError wraps an error with lease context.
type LeaseError struct {
	LeaseID    string
	SecretName string
	Err        error
}

func (e *LeaseError) Error() string {
	if e.LeaseID != "" {
		return fmt.Sprintf("lease %q for secret %q: %v", e.LeaseID, e.SecretName, e.Err)
	}
	return fmt.Sprintf("lease for secret %q: %v", e.SecretName, e.Err)
}

func (e *LeaseError) Unwrap() error {
	return e.Err
}

// NewLeaseError creates a new LeaseError.
func NewLeaseError(leaseID, secretName string, err error) *LeaseError {
	return &LeaseError{LeaseID: leaseID, SecretName: secretName, Err: err}
}

// RotationError wraps an error with rotation context.
type RotationError struct {
	SecretName string
	Command    string
	Output     string
	Err        error
}

func (e *RotationError) Error() string {
	return fmt.Sprintf("rotation of secret %q failed: %v", e.SecretName, e.Err)
}

func (e *RotationError) Unwrap() error {
	return e.Err
}

// NewRotationError creates a new RotationError.
func NewRotationError(secretName, command, output string, err error) *RotationError {
	return &RotationError{
		SecretName: secretName,
		Command:    command,
		Output:     output,
		Err:        err,
	}
}

// ErrAdapterNotAvailable indicates an adapter cannot be used.
type ErrAdapterNotAvailable struct {
	Adapter string
	Reason  string
}

func (e ErrAdapterNotAvailable) Error() string {
	return fmt.Sprintf("adapter %q not available: %s", e.Adapter, e.Reason)
}

func (e ErrAdapterNotAvailable) Unwrap() error {
	return ErrAdapterFailed
}

// RPCErrorFromError converts a Go error to an RPCError with appropriate code.
func RPCErrorFromError(err error) *RPCError {
	code := RPCInternalError

	switch {
	case errors.Is(err, ErrSecretNotFound):
		code = RPCSecretNotFound
	case errors.Is(err, ErrLeaseNotFound):
		code = RPCLeaseNotFound
	case errors.Is(err, ErrLeaseExpired), errors.Is(err, ErrLeaseRevoked):
		code = RPCLeaseExpired
	case errors.Is(err, ErrRotationFailed), errors.Is(err, ErrRotationTimeout):
		code = RPCRotationFailed
	case errors.Is(err, ErrEncryptionFailed):
		code = RPCEncryptionError
	case errors.Is(err, ErrDecryptionFailed):
		code = RPCDecryptionError
	}

	return &RPCError{
		Code:    code,
		Message: err.Error(),
	}
}
