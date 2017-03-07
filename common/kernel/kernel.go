package kernel

import "fmt"

// GetReleaseNumbers returns the kernel release numbers: major, minor and patch number
func GetReleaseNumbers() (major, minor, patch int, err error) {
	release, _, err := GetReleaseAndVersion()
	if err != nil {
		return 0, 0, 0, err
	}
	if n, err := fmt.Sscanf(release, "%d.%d.%d", &major, &minor, &patch); err != nil || n != 3 {
		return 0, 0, 0, fmt.Errorf("Malformed version: %s", release)
	}
	return
}
