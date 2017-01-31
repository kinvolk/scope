package endpoint

import (
	"github.com/weaveworks/scope/probe/endpoint/procspy"
	"github.com/weaveworks/scope/probe/process"
	"testing"
)

const bufferSize = 1024 * 1024

var (
	processFlowWalkAndProcWalk                 = process.NewCachingWalker(process.NewWalker("/proc"))
	scannerFlowWalkAndProcWalk                 = procspy.NewSyncConnectionScanner(processFlowWalkAndProcWalk)
	flowWlakAndProcWalkConnectionTrackerConfig = connectionTrackerConfig{
		HostID:       "mock;<host>",
		HostName:     "mock",
		SpyProcs:     false,
		UseConntrack: true,
		WalkProc:     true,
		UseEbpfConn:  false,
		ProcRoot:     "/proc",
		BufferSize:   bufferSize,
		Scanner:      scannerFlowWalkAndProcWalk,
		DNSSnooper:   nil,
	}

	onlyEbpfConnectionTrackerConfig = connectionTrackerConfig{
		HostID:       "mock;<host>",
		HostName:     "mock",
		SpyProcs:     false,
		UseConntrack: false,
		WalkProc:     false,
		UseEbpfConn:  true,
		ProcRoot:     "/proc",
		BufferSize:   bufferSize,
		Scanner:      nil,
		DNSSnooper:   nil,
	}
)

func TestNewConnectionTrackerNoEbpf(t *testing.T) {
	tracker := newConnectionTracker(flowWlakAndProcWalkConnectionTrackerConfig)
	defer tracker.Stop()

	if tracker.flowWalker == nil || flowWlakAndProcWalkConnectionTrackerConfig.Scanner == nil {
		t.Error("flowWalker and procWalk were not enabled")
		if tracker.flowWalker == nil {
			t.Error("flowWalker failed")
		}
		if flowWlakAndProcWalkConnectionTrackerConfig.Scanner == nil {
			t.Error("procWalker failed")
		}
	}
	if tracker.ebpfTracker != nil {
		t.Error("ebpfTracker should not be enabled")
	}
}

func TestNewConnectionTrackerEbpf(t *testing.T) {
	// TODO: load ebpf
	//tracker = newConnectionTracker(onlyEbpfConnectionTrackerConfig)
	//defer tracker.Stop()

	//if tracker.flowWalker != nil {
	//	t.Error("flowWalker should not be enabled")
	//}
	//if onlyEbpfConnectionTrackerConfig.Scanner != nil {
	//	t.Error("procWalk should not be enabled")
	//}
	//if tracker.ebpfTracker != nil {
	//	t.Error("ebpfTracker was not be enabled")
	//}
}

//func TestReportConnectionsNoEbpf(t *testing.T) {
//	tracker := newConnectionTracker(flowWlakAndProcWalkConnectionTrackerConfig)
//	defer tracker.Stop()
//
//	if tracker.flowWalker == nil || flowWlakAndProcWalkConnectionTrackerConfig.Scanner == nil {
//		// ERROR
//	}
//}
//
//func TestReportConnectionsEbpf(t *testing.T) {
//	tracker := newConnectionTracker(onlyEbpfConnectionTrackerConfig)
//	defer tracker.Stop()
//
//	if tracker.flowWalker == nil || onlyEbpfConnectionTrackerConfig.Scanner == nil {
//		// ERROR
//	}
//}

func TestAddConnection (t *testing.T) {

}

func TestPerformEbpf (t *testing.T) {

}

