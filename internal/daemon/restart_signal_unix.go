//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// signalRestartProcess asks the current process to terminate so a supervisor
// (launchd, systemd, Task Scheduler, ...) can start its replacement.
//
// On Unix this sends SIGTERM, which the serve command handles gracefully:
// the daemon flushes leases and writes a daemon_stop audit entry before
// exiting.
func signalRestartProcess() error {
	return syscall.Kill(os.Getpid(), syscall.SIGTERM)
}
