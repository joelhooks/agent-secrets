package main

import (
	"fmt"

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

		resp := output.Success(
			fmt.Sprintf("Updated from %s to %s", currentVersion, updateInfo.LatestVersion),
			map[string]interface{}{
				"old_version": currentVersion,
				"new_version": updateInfo.LatestVersion,
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
