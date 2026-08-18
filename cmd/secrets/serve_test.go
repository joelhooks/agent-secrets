package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServeConfigHonorsConfigFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.json")
	if err := os.WriteFile(path, []byte(`{"socket_path":"/tmp/service-account.sock","socket_mode":"0660","socket_group":"joelclaw-secrets"}`), 0600); err != nil {
		t.Fatal(err)
	}

	previous := configPath
	configPath = path
	defer func() { configPath = previous }()

	cfg, err := loadServeConfig()
	if err != nil {
		t.Fatalf("loadServeConfig() error = %v", err)
	}
	if cfg.SocketPath != "/tmp/service-account.sock" {
		t.Fatalf("SocketPath = %q", cfg.SocketPath)
	}
	if cfg.SocketMode != "0660" || cfg.SocketGroup != "joelclaw-secrets" {
		t.Fatalf("socket ownership = %s/%s", cfg.SocketMode, cfg.SocketGroup)
	}
}
