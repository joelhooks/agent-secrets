//go:build unix

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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	err := cmd.Start()
	return cmd, err
}
