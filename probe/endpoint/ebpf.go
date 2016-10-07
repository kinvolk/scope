package endpoint

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
)

type event int

const (
	// Connect is a TCP CONNECT event
	Connect event = iota
	// Accept is a TCP ACCEPT event
	Accept
	// Close is a TCP CLOSE event
	Close
)

// A ebpfConnection represents a network connection
type ebpfConnection struct {
	tuple    fourTuple
	outgoing bool
	pid      int
}

// EbpfTracker contains the list of eBPF events, and the eBPF script's command
type EbpfTracker struct {
	Cmd *exec.Cmd

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
		log.Errorf("bcc error: %v", err)
		return nil
	}
	go logPipe("bcc stderr:", stderr)

	tracker := &EbpfTracker{
		Cmd: cmd,
	}
	go tracker.run()
	return tracker
}

func (t *EbpfTracker) run() {
	stdout, err := t.Cmd.StdoutPipe()
	if err != nil {
		log.Errorf("conntrack error: %v", err)
		return
	}

	if err := t.Cmd.Start(); err != nil {
		log.Errorf("bcc error: %v", err)
		return
	}

	defer func() {
		if err := t.Cmd.Wait(); err != nil {
			log.Errorf("bcc error: %v", err)
		}
	}()

	reader := bufio.NewReader(stdout)
	// skip fist line
	if _, err := reader.ReadString('\n'); err != nil {
		log.Errorf("bcc error: %v", err)
		return
	}

	defer log.Infof("bcc exiting")

	scn := bufio.NewScanner(reader)
	for scn.Scan() {
		txt := scn.Text()
		line := strings.Fields(txt)

		eventStr := line[0]

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

		tuple := fourTuple{sourceAddr.String(), destAddr.String(), sourcePort, destPort}

		switch eventStr {
		case "connect":
			conn := ebpfConnection{
				outgoing: true,
				tuple:    tuple,
				pid:      pid,
			}
			t.activeFlows[tuple.String()] = conn
		case "accept":
			conn := ebpfConnection{
				outgoing: true,
				tuple:    tuple,
				pid:      pid,
			}
			t.activeFlows[tuple.String()] = conn
		case "close":
			if deadConn, ok := t.activeFlows[tuple.String()]; ok {
				delete(t.activeFlows, tuple.String())
				t.bufferedFlows = append(t.bufferedFlows, deadConn)
			}
		}

	}
}

// WalkConnections - walk through the connectionEvents
func (t EbpfTracker) WalkConnections(f func(ebpfConnection)) {
	for _, flow := range t.activeFlows {
		f(flow)
	}
	for _, flow := range t.bufferedFlows {
		f(flow)
	}
	t.bufferedFlows = t.bufferedFlows[:0]
}
