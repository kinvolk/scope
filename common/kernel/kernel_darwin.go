package kernel

import (
	"bytes"
	"os/exec"
)

// GetReleaseAndVersion returns the kernel release and version as reported by uname.
var GetReleaseAndVersion = func() (string, string, error) {
	release, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return "unknown", "unknown", err
	}
	release = bytes.Trim(release, " \n")
	version, err := exec.Command("uname", "-v").CombinedOutput()
	if err != nil {
		return string(release), "unknown", err
	}
	version = bytes.Trim(version, " \n")
	return string(release), string(version), nil
}
