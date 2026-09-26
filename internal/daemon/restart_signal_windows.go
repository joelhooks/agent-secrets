//go:build windows

package daemon

import "os"

// signalRestartProcess terminates the current process so a supervisor can
// start its replacement.
//
// Windows does not deliver POSIX signals, so the graceful SIGTERM path used on
// Unix is unavailable here; the process is terminated and the supervisor starts
// a fresh daemon, which is what the restart RPC response already promises
// ("the supervisor will start a fresh daemon").
func signalRestartProcess() error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return p.Kill()
}
