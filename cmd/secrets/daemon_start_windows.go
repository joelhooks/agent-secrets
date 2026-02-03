//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// startDaemonDetached starts the daemon process detached from the parent
func startDaemonDetached(execPath string) (*exec.Cmd, error) {
	cmd := exec.Command(execPath, "serve")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	// On Windows, CREATE_NEW_PROCESS_GROUP detaches from parent
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	err := cmd.Start()
	return cmd, err
}
