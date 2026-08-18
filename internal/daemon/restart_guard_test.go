package daemon

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestRestartGuardPersistsCooldownAcrossInstances(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	first := newRestartGuard(directory)
	first.now = func() time.Time { return now }
	if err := first.Reserve(); err != nil {
		t.Fatal(err)
	}

	second := newRestartGuard(directory)
	second.now = func() time.Time { return now.Add(5 * time.Second) }
	if err := second.Reserve(); err == nil || !strings.Contains(err.Error(), "cooling down") {
		t.Fatalf("Reserve() = %v, want persisted cooldown", err)
	}

	second.now = func() time.Time { return now.Add(31 * time.Second) }
	if err := second.Reserve(); err != nil {
		t.Fatalf("Reserve() after cooldown = %v", err)
	}
}

func TestRestartGuardReleaseClearsFailedReservation(t *testing.T) {
	guard := newRestartGuard(t.TempDir())
	if err := guard.Reserve(); err != nil {
		t.Fatal(err)
	}
	if err := guard.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(guard.path); !os.IsNotExist(err) {
		t.Fatalf("cooldown marker still exists: %v", err)
	}
	if err := guard.Reserve(); err != nil {
		t.Fatalf("Reserve() after release = %v", err)
	}
}
