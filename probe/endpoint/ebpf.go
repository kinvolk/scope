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

// A ebpfConnection represents a network connection
type ebpfConnection struct {
	tuple            fourTuple
	networkNamespace string
	outgoing         bool
	pid              int
}

// EbpfTracker contains the list of eBPF events, and the eBPF script's command
type EbpfTracker struct {
	sync.Mutex
	cmd *exec.Cmd

	initialized bool
	dead        bool

	activeFlows   map[string]ebpfConnection
	bufferedFlows []ebpfConnection
}

// NewEbpfTracker creates a new EbpfTracker
func NewEbpfTracker(bccProgramPath string) *EbpfTracker {
	cmd := exec.Command(bccProgramPath)
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
			outgoing:         true,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.activeFlows[tuple.String()] = conn
	case "accept":
		log.Infof("EbpfTracker: accept: %s pid=%v", tuple, pid)
		conn := ebpfConnection{
			outgoing:         true,
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
