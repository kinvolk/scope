package kernel

import (
	"syscall"

	"github.com/weaveworks/scope/common/marshal"
)

// Uname is swappable for mocking in tests.
var Uname = syscall.Uname

// GetReleaseAndVersion returns the kernel release and version as reported by uname.
var GetReleaseAndVersion = func() (string, string, error) {
	var utsname syscall.Utsname
	if err := Uname(&utsname); err != nil {
		return "unknown", "unknown", err
	}
	release := marshal.FromUtsname(utsname.Release)
	version := marshal.FromUtsname(utsname.Version)
	return release, version, nil
}
