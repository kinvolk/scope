package kernel_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/weaveworks/scope/common/kernel"
)

func TestGetKernelVersion(t *testing.T) {
	release, version, err := kernel.GetReleaseAndVersion()
	if err != nil {
		t.Fatal(err)
	}
	have := fmt.Sprintf("%s %s", release, version)
	if strings.Contains(have, "unknown") {
		t.Fatal(have)
	}
	t.Log(have)
}
