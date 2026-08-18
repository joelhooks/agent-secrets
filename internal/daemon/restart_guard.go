package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const restartCooldown = 30 * time.Second

type restartMarker struct {
	RequestedAt time.Time `json:"requested_at"`
}

type restartGuard struct {
	mu      sync.Mutex
	path    string
	pending bool
	now     func() time.Time
}

func newRestartGuard(directory string) *restartGuard {
	return &restartGuard{
		path: filepath.Join(directory, "restart-cooldown.json"),
		now:  time.Now,
	}
}

func (g *restartGuard) Reserve() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.pending {
		return fmt.Errorf("daemon restart is already pending")
	}
	if marker, err := g.readMarker(); err == nil {
		if elapsed := g.now().Sub(marker.RequestedAt); elapsed >= 0 && elapsed < restartCooldown {
			return fmt.Errorf("daemon restart is cooling down; retry after %s", restartCooldown-elapsed)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to read restart cooldown: %w", err)
	}

	marker := restartMarker{RequestedAt: g.now().UTC()}
	if err := g.writeMarker(marker); err != nil {
		return fmt.Errorf("failed to persist restart cooldown: %w", err)
	}
	g.pending = true
	return nil
}

func (g *restartGuard) Release() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending = false
	if err := os.Remove(g.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to clear restart cooldown: %w", err)
	}
	return nil
}

func (g *restartGuard) readMarker() (*restartMarker, error) {
	data, err := os.ReadFile(g.path)
	if err != nil {
		return nil, err
	}
	var marker restartMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return nil, err
	}
	return &marker, nil
}

func (g *restartGuard) writeMarker(marker restartMarker) error {
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(g.path), ".restart-cooldown-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, g.path)
}
