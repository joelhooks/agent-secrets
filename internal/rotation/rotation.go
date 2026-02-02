// Package rotation handles secret rotation hook execution.
package rotation

import (
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

// RotationConfig holds the configuration for a rotation hook.
type RotationConfig struct {
	Command    string        // Command to execute
	Timeout    time.Duration // Execution timeout
	LastRun    time.Time     // Last successful execution time
}

// RotationJob represents a rotation task for a specific secret.
type RotationJob struct {
	SecretName string
	Config     RotationConfig
}

// NewRotationJob creates a new rotation job from a secret.
func NewRotationJob(secret types.Secret, timeout time.Duration) *RotationJob {
	return &RotationJob{
		SecretName: secret.Name,
		Config: RotationConfig{
			Command:    secret.RotateVia,
			Timeout:    timeout,
			LastRun:    secret.LastRotated,
		},
	}
}
