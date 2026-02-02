package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the secrets daemon",
	Long: `Start the agent-secrets daemon in the foreground. The daemon listens on a Unix socket
and handles all secret operations (leases, revocations, etc.).

Use --background to run as a background process.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		background, _ := cmd.Flags().GetBool("background")

		// Load config
		cfg := config.DefaultConfig()

		// Create and start daemon
		d, err := daemon.NewDaemonWithOptions(cfg, skipPermissionCheck)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to create daemon: %w", err)))
			return err
		}

		if err := d.Start(); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to start daemon: %w", err)))
			return err
		}

		if background {
			// For background mode, we'd fork - but for now just print and exit
			// leaving the daemon running (user should use systemd or similar)
			output.Print(output.Success(
				"Daemon started",
				map[string]interface{}{
					"socket": cfg.SocketPath,
					"pid":    os.Getpid(),
				},
			))
			return nil
		}

		output.Print(output.Success(
			"Daemon running",
			map[string]interface{}{
				"socket": cfg.SocketPath,
				"pid":    os.Getpid(),
			},
		))

		// Wait for interrupt signal
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		fmt.Println("\nShutting down...")
		if err := d.Stop(); err != nil {
			output.Print(output.Error(fmt.Errorf("shutdown error: %w", err)))
			return err
		}

		output.Print(output.Success("Daemon stopped", nil))
		return nil
	},
}

func init() {
	serveCmd.Flags().Bool("background", false, "Run daemon in background")
	rootCmd.AddCommand(serveCmd)
}
