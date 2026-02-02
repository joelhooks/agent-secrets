// Package types defines exit codes following standard Unix conventions.
package types

// Exit codes for the secrets CLI.
// These follow standard Unix/BSD sysexits.h conventions where applicable.
const (
	// ExitSuccess indicates the operation completed successfully.
	ExitSuccess = 0

	// ExitGenericError indicates a generic error occurred.
	// Use this when no more specific exit code applies.
	ExitGenericError = 1

	// ExitMisuse indicates the command was used incorrectly.
	// Examples: wrong arguments, invalid flags, mutually exclusive options.
	ExitMisuse = 2

	// ExitDataError indicates the input data format was invalid.
	// Examples: malformed JSON, corrupt encrypted data.
	ExitDataError = 64

	// ExitTimeout indicates an operation timed out.
	// Examples: rotation hook timeout, lease timeout.
	ExitTimeout = 65

	// ExitIOError indicates an I/O error occurred.
	// Examples: can't write to socket, can't create file.
	ExitIOError = 66

	// ExitProtocolError indicates an invalid RPC response or protocol violation.
	// Examples: malformed JSON-RPC response, unexpected message format.
	ExitProtocolError = 67

	// ExitDaemonUnavailable indicates the daemon is not running or unreachable.
	// Use this when the CLI can't connect to the Unix socket.
	ExitDaemonUnavailable = 69

	// ExitInternalError indicates an unexpected internal error.
	// Examples: panic recovered, invariant violation, unexpected nil.
	ExitInternalError = 70
)

// ExitCodeFromError returns the appropriate exit code for a given error.
// This maps internal errors to standard exit codes.
func ExitCodeFromError(err error) int {
	if err == nil {
		return ExitSuccess
	}

	switch {
	case IsRotationTimeout(err):
		return ExitTimeout
	case IsDaemonError(err):
		return ExitDaemonUnavailable
	case IsStoreCorrupted(err):
		return ExitDataError
	case IsConnectionError(err):
		return ExitIOError
	default:
		return ExitGenericError
	}
}

// Helper functions to check error types
func IsRotationTimeout(err error) bool {
	return err == ErrRotationTimeout
}

func IsDaemonError(err error) bool {
	return err == ErrDaemonNotRunning || err == ErrConnectionFailed
}

func IsStoreCorrupted(err error) bool {
	return err == ErrStoreCorrupted
}

func IsConnectionError(err error) bool {
	return err == ErrConnectionFailed || err == ErrSocketExists
}
