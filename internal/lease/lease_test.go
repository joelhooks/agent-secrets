package lease

import (
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		lease    *types.Lease
		expected bool
	}{
		{
			name: "not expired",
			lease: &types.Lease{
				ID:        "lease-1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			lease: &types.Lease{
				ID:        "lease-2",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "just expired",
			lease: &types.Lease{
				ID:        "lease-3",
				ExpiresAt: time.Now().Add(-1 * time.Millisecond),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsExpired(tt.lease)
			if got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		name     string
		lease    *types.Lease
		expected bool
	}{
		{
			name:     "nil lease",
			lease:    nil,
			expected: false,
		},
		{
			name: "valid lease",
			lease: &types.Lease{
				ID:        "lease-1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Revoked:   false,
			},
			expected: true,
		},
		{
			name: "revoked lease",
			lease: &types.Lease{
				ID:        "lease-2",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Revoked:   true,
			},
			expected: false,
		},
		{
			name: "expired lease",
			lease: &types.Lease{
				ID:        "lease-3",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				Revoked:   false,
			},
			expected: false,
		},
		{
			name: "expired and revoked",
			lease: &types.Lease{
				ID:        "lease-4",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				Revoked:   true,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValid(tt.lease)
			if got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTimeRemaining(t *testing.T) {
	tests := []struct {
		name     string
		lease    *types.Lease
		wantZero bool
	}{
		{
			name:     "nil lease",
			lease:    nil,
			wantZero: true,
		},
		{
			name: "revoked lease",
			lease: &types.Lease{
				ID:        "lease-1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Revoked:   true,
			},
			wantZero: true,
		},
		{
			name: "expired lease",
			lease: &types.Lease{
				ID:        "lease-2",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				Revoked:   false,
			},
			wantZero: true,
		},
		{
			name: "valid lease",
			lease: &types.Lease{
				ID:        "lease-3",
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Revoked:   false,
			},
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remaining := TimeRemaining(tt.lease)
			if tt.wantZero && remaining != 0 {
				t.Errorf("TimeRemaining() = %v, want 0", remaining)
			}
			if !tt.wantZero && remaining <= 0 {
				t.Errorf("TimeRemaining() = %v, want > 0", remaining)
			}
		})
	}
}
