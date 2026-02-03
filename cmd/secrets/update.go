package main

import (
	"fmt"
	"os"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/update"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update to the latest version",
	Long:  `Check for and install the latest version of agent-secrets from GitHub releases.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		currentVersion := update.GetVersion()

		// Check for update first
		updateInfo, err := update.CheckForUpdate(currentVersion)
		if err != nil {
			resp := output.Error(err)
			output.Print(resp)
			return err
		}

		if !updateInfo.Available {
			resp := output.Success(
				fmt.Sprintf("Already at latest version %s", currentVersion),
				update.VersionInfo(),
			)
			output.Print(resp)
			return nil
		}

		// Check if daemon is running before update
		var daemonPID int
		var daemonWasRunning bool
		statusResp, err := rpcCall(socketPath, daemon.MethodStatus, nil)
		if err == nil && statusResp.Result != nil {
			// Daemon is running, get PID
			if result, ok := statusResp.Result.(map[string]interface{}); ok {
				if pid, ok := result["pid"].(float64); ok {
					daemonPID = int(pid)
					daemonWasRunning = true
				}
			}
		}

		// Stop daemon before update if it's running
		if daemonWasRunning && daemonPID > 0 {
			fmt.Printf("Stopping daemon (PID %d) for update...\n", daemonPID)
			if proc, err := os.FindProcess(daemonPID); err == nil {
				_ = proc.Signal(os.Interrupt)
			}
		}

		// Perform update
		if err := update.DoUpdate(currentVersion); err != nil {
			resp := output.Error(
				err,
				output.Action{
					Name:        "manual_update",
					Description: "Download manually from GitHub releases",
					Command:     "open https://github.com/joelhooks/agent-secrets/releases",
				},
			)
			output.Print(resp)
			return err
		}

		// Restart daemon if it was running
		var restartMsg string
		if daemonWasRunning {
			// Get the path to the newly installed binary
			execPath, err := os.Executable()
			if err != nil {
				execPath = "secrets" // fallback
			}

			// Start daemon in background (platform-specific)
			daemonCmd, err := startDaemonDetached(execPath)
			if err != nil {
				restartMsg = fmt.Sprintf(" (daemon restart failed: %v)", err)
			} else {
				restartMsg = fmt.Sprintf(" (daemon restarted, PID %d)", daemonCmd.Process.Pid)
			}
		}

		resp := output.Success(
			fmt.Sprintf("Updated from %s to %s%s", currentVersion, updateInfo.LatestVersion, restartMsg),
			map[string]interface{}{
				"old_version":      currentVersion,
				"new_version":      updateInfo.LatestVersion,
				"daemon_restarted": daemonWasRunning,
			},
			output.Action{
				Name:        "verify",
				Description: "Verify the new version",
				Command:     "secrets version",
			},
		)
		output.Print(resp)

		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display the current version, commit, and build information for agent-secrets.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		currentVersion := update.GetVersion()
		versionInfo := update.VersionInfo()

		// Check for updates in background
		updateInfo, _ := update.CheckForUpdate(currentVersion)

		resp := output.Success("Version information", versionInfo)
		if updateInfo != nil && updateInfo.Available {
			resp.Update = updateInfo
			resp.Actions = append(resp.Actions, output.ActionUpdate())
		}

		output.Print(resp)
		return nil
	},
}
