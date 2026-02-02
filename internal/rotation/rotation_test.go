package rotation

import (
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestNewRotationJob(t *testing.T) {
	now := time.Now()
	secret := types.Secret{
		Name:        "github_token",
		RotateVia:   "gh auth refresh",
		LastRotated: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	timeout := 30 * time.Second
	job := NewRotationJob(secret, timeout)

	if job.SecretName != "github_token" {
		t.Errorf("expected secret name 'github_token', got %q", job.SecretName)
	}

	if job.Config.Command != "gh auth refresh" {
		t.Errorf("expected command 'gh auth refresh', got %q", job.Config.Command)
	}

	if job.Config.Timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, job.Config.Timeout)
	}

	if !job.Config.LastRun.Equal(now) {
		t.Errorf("expected last run %v, got %v", now, job.Config.LastRun)
	}
}

func TestRotationConfig(t *testing.T) {
	cfg := RotationConfig{
		Command: "echo test",
		Timeout: 5 * time.Second,
		LastRun: time.Now(),
	}

	if cfg.Command == "" {
		t.Error("expected command to be set")
	}

	if cfg.Timeout <= 0 {
		t.Error("expected timeout to be positive")
	}
}
