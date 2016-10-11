package endpoint

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
)

// TCPV4TracerLocation is the location of the Python script
// that delivers the eBPF messages coming from the kernel.
var TCPV4TracerLocation = "/home/weave/tcpv4tracer.py"

// A ebpfConnection represents a network connection
type ebpfConnection struct {
	tuple            fourTuple
	networkNamespace string
	incoming         bool
	pid              int
}

type eventTracker interface {
	handleFlow(eventType string, tuple fourTuple, pid int, networkNamespace string)
	hasDied() bool
	run()
	walkFlows(f func(ebpfConnection))
	initialize()
	isInitialized() bool
}

// nilTracker is a tracker that does nothing, and it implements the eventTracker interface.
// It is returned when the ebpfEnabled flag is false.
type nilTracker struct{}

func (n nilTracker) handleFlow(_ string, _ fourTuple, _ int, _ string) {}
func (n nilTracker) hasDied() bool                                     { return true }
func (n nilTracker) run()                                              {}
func (n nilTracker) walkFlows(f func(ebpfConnection))                  {}
func (n nilTracker) initialize()                                       {}
func (n nilTracker) isInitialized() bool                               { return false }

// EbpfTracker contains the list of eBPF events, and the eBPF script's command
type EbpfTracker struct {
	sync.Mutex
	cmd *exec.Cmd

	initialized bool
	dead        bool

	activeFlows   map[string]ebpfConnection
	bufferedFlows []ebpfConnection
}

func newEbpfTracker(ebpfEnabled bool) eventTracker {
	if !ebpfEnabled {
		return &nilTracker{}
	}
	cmd := exec.Command(TCPV4TracerLocation)
	env := os.Environ()
	cmd.Env = append(env, "PYTHONUNBUFFERED=1")

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("EbpfTracker error: %v", err)
		return nil
	}
	go logPipe("EbpfTracker stderr:", stderr)

	tracker := &EbpfTracker{
		cmd:         cmd,
		activeFlows: map[string]ebpfConnection{},
	}
	go tracker.run()
	return tracker
}

func (t *EbpfTracker) handleFlow(eventType string, tuple fourTuple, pid int, networkNamespace string) {
	t.Lock()
	defer t.Unlock()

	switch eventType {
	case "connect":
		log.Infof("EbpfTracker: connect: %s pid=%v", tuple, pid)
		conn := ebpfConnection{
			incoming:         false,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.activeFlows[tuple.String()] = conn
	case "accept":
		log.Infof("EbpfTracker: accept: %s pid=%v", tuple, pid)
		conn := ebpfConnection{
			incoming:         true,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.activeFlows[tuple.String()] = conn
	case "close":
		log.Infof("EbpfTracker: close: %s pid=%v", tuple, pid)
		if deadConn, ok := t.activeFlows[tuple.String()]; ok {
			delete(t.activeFlows, tuple.String())
			t.bufferedFlows = append(t.bufferedFlows, deadConn)
		} else {
			log.Errorf("EbpfTracker error: unmatched close event")
		}
	}

}

func (t *EbpfTracker) run() {
	stdout, err := t.cmd.StdoutPipe()
	if err != nil {
		log.Errorf("EbpfTracker error: %v", err)
		return
	}

	if err := t.cmd.Start(); err != nil {
		log.Errorf("EbpfTracker error: %v", err)
		return
	}

	defer func() {
		if err := t.cmd.Wait(); err != nil {
			log.Errorf("EbpfTracker error: %v", err)
		}

		t.Lock()
		t.dead = true
		t.Unlock()
	}()

	reader := bufio.NewReader(stdout)
	// skip fist line
	if _, err := reader.ReadString('\n'); err != nil {
		log.Errorf("EbpfTracker error: %v", err)
		return
	}

	defer log.Infof("EbpfTracker exiting")

	scn := bufio.NewScanner(reader)
	for scn.Scan() {
		txt := scn.Text()
		line := strings.Fields(txt)

		if len(line) != 7 {
			log.Errorf("error parsing line %q", txt)
			continue
		}

		eventType := line[0]

		pid, err := strconv.Atoi(line[1])
		if err != nil {
			log.Errorf("error parsing pid %q: %v", line[1], err)
			continue
		}

		sourceAddr := net.ParseIP(line[2])
		if sourceAddr == nil {
			log.Errorf("error parsing sourceAddr %q: %v", line[2], err)
			continue
		}

		destAddr := net.ParseIP(line[3])
		if destAddr == nil {
			log.Errorf("error parsing destAddr %q: %v", line[3], err)
			continue
		}

		sPort, err := strconv.ParseUint(line[4], 10, 16)
		if err != nil {
			log.Errorf("error parsing sourcePort %q: %v", line[4], err)
			continue
		}
		sourcePort := uint16(sPort)

		dPort, err := strconv.ParseUint(line[5], 10, 16)
		if err != nil {
			log.Errorf("error parsing destPort %q: %v", line[5], err)
			continue
		}
		destPort := uint16(dPort)

		networkNamespace := line[6]

		tuple := fourTuple{sourceAddr.String(), destAddr.String(), sourcePort, destPort}

		t.handleFlow(eventType, tuple, pid, networkNamespace)
	}
}

// walkFlows calls f with all active flows and flows that have come and gone
// since the last call to walkFlows
func (t *EbpfTracker) walkFlows(f func(ebpfConnection)) {
	t.Lock()
	defer t.Unlock()

	log.Infof("EbpfTracker: WalkConnections activeFlows: %d bufferedFlows: %d", len(t.activeFlows), len(t.bufferedFlows))

	for _, flow := range t.activeFlows {
		f(flow)
	}
	for _, flow := range t.bufferedFlows {
		f(flow)
	}
	t.bufferedFlows = t.bufferedFlows[:0]
}

func (t *EbpfTracker) hasDied() bool {
	t.Lock()
	defer t.Unlock()

	return t.dead
}

func (t *EbpfTracker) initialize() {
	t.initialized = true
}

func (t *EbpfTracker) isInitialized() bool {
	return t.initialized
}
