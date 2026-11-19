//go:build !windows

package store

// permissionModeIsMeaningful reports whether the permission bits returned by
// os.Stat are meaningful on this platform.
//
// On Unix they are, so key files are validated as usual.
func permissionModeIsMeaningful() bool {
	return true
}
