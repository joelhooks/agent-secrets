package project

import (
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "darwin" {
		_ = os.Setenv("TMPDIR", "/private/tmp")
	}
	os.Exit(m.Run())
}
