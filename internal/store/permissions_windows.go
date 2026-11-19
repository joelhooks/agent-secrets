//go:build windows

package store

// permissionModeIsMeaningful reports whether the permission bits returned by
// os.Stat are meaningful on this platform.
//
// On Windows they are not: os.Stat().Mode().Perm() reports 0666 regardless of
// the file's actual ACL, so validating them rejected every store and made the
// daemon treat each restart as a first run.
func permissionModeIsMeaningful() bool {
	return false
}
