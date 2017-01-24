package endpoint

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"sync"

	log "github.com/Sirupsen/logrus"
	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/kinvolk/tcptracer-bpf/pkg/byteorder"
	"github.com/kinvolk/tcptracer-bpf/pkg/event"
	"github.com/kinvolk/tcptracer-bpf/pkg/tracer"
)

// An ebpfConnection represents a TCP connection
type ebpfConnection struct {
	tuple            fourTuple
	networkNamespace string
	incoming         bool
	pid              int
}

type eventTracker interface {
	handleConnection(ev event.EventType, tuple fourTuple, pid int, networkNamespace string)
	hasDied() bool
	run()
	walkConnections(f func(ebpfConnection))
	initialize()
	isInitialized() bool
	stop()
}

var ebpfTracker *EbpfTracker

// nilTracker is a tracker that does nothing, and it implements the eventTracker interface.
// It is returned when the useEbpfConn flag is false.
type nilTracker struct{}

func (n nilTracker) handleConnection(_ event.EventType, _ fourTuple, _ int, _ string) {}
func (n nilTracker) hasDied() bool                                                    { return true }
func (n nilTracker) run()                                                             {}
func (n nilTracker) walkConnections(f func(ebpfConnection))                           {}
func (n nilTracker) initialize()                                                      {}
func (n nilTracker) isInitialized() bool                                              { return false }
func (n nilTracker) stop()                                                            {}

// EbpfTracker contains the sets of open and closed TCP connections.
// Closed connections are kept in the `closedConnections` slice for one iteration of `walkConnections`.
type EbpfTracker struct {
	sync.Mutex
	reader      *bpflib.Module
	initialized bool
	dead        bool

	openConnections   map[string]ebpfConnection
	closedConnections []ebpfConnection
}

func newEbpfTracker(useEbpfConn bool) eventTracker {
	if !useEbpfConn {
		return &nilTracker{}
	}

	bpfObjectFile, err := findBpfObjectFile()
	if err != nil {
		log.Errorf("Cannot find BPF object file: %v", err)
		return &nilTracker{}
	}

	bpfPerfEvent := bpflib.NewModule(bpfObjectFile)
	if bpfPerfEvent == nil {
		return &nilTracker{}
	}
	if err := bpfPerfEvent.Load(); err != nil {
		log.Errorf("Error loading BPF program: %v", err)
		return &nilTracker{}
	}

	if err := bpfPerfEvent.EnableKprobes(); err != nil {
		log.Errorf("Error enabling kprobes: %v", err)
		return &nilTracker{}
	}

	tracker := &EbpfTracker{
		openConnections: map[string]ebpfConnection{},
		reader:          bpfPerfEvent,
	}
	tracker.run()

	ebpfTracker = tracker
	return tracker
}

func (t *EbpfTracker) handleConnection(ev event.EventType, tuple fourTuple, pid int, networkNamespace string) {
	t.Lock()
	defer t.Unlock()
	log.Debugf("handleConnection(%v, [%v:%v --> %v:%v], pid=%v, netNS=%v)",
		ev, tuple.fromAddr, tuple.fromPort, tuple.toAddr, tuple.toPort, pid, networkNamespace)

	switch ev {
	case event.EventConnect:
		conn := ebpfConnection{
			incoming:         false,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.openConnections[tuple.String()] = conn
	case event.EventAccept:
		conn := ebpfConnection{
			incoming:         true,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.openConnections[tuple.String()] = conn
	case event.EventClose:
		if deadConn, ok := t.openConnections[tuple.String()]; ok {
			delete(t.openConnections, tuple.String())
			t.closedConnections = append(t.closedConnections, deadConn)
		} else {
			log.Errorf("EbpfTracker error: unmatched close event: %s pid=%d netns=%s", tuple.String(), pid, networkNamespace)
		}
	}
}

func tcpEventCallback(ev event.Tcp) {
	var active bool
	typ := event.EventType(ev.Type)
	pid := ev.Pid & 0xffffffff

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	byteorder.Host.PutUint32(saddrbuf, uint32(ev.SAddr))
	byteorder.Host.PutUint32(daddrbuf, uint32(ev.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := ev.SPort
	dport := ev.DPort

	if typ == event.EventClose {
		active = true
	} else {
		active = false
	}
	tuple := fourTuple{sIP.String(), dIP.String(), uint16(sport), uint16(dport), active}

	log.Debugf("tcpEventCallback(%v, [%v:%v --> %v:%v], pid=%v, netNS=%v, cpu=%v, ts=%v)",
		typ.String(), tuple.fromAddr, tuple.fromPort, tuple.toAddr, tuple.toPort, pid, ev.NetNS, ev.CPU, ev.Timestamp)
	ebpfTracker.handleConnection(typ, tuple, int(pid), strconv.FormatUint(uint64(ev.NetNS), 10))
}

// walkConnections calls f with all open connections and connections that have come and gone
// since the last call to walkConnections
func (t *EbpfTracker) walkConnections(f func(ebpfConnection)) {
	t.Lock()
	defer t.Unlock()

	for _, connection := range t.openConnections {
		f(connection)
	}
	for _, connection := range t.closedConnections {
		f(connection)
	}
	t.closedConnections = t.closedConnections[:0]
}

func (t *EbpfTracker) run() {
	channel := make(chan []byte)

	go func() {
		var ev event.Tcp
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), byteorder.Host, &ev)
			if err != nil {
				log.Errorf("Failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCallback(ev)
		}
	}()

	perfMap, err := tracer.InitializeIPv4(t.reader, channel)
	if err != nil {
		log.Errorf("%v\n", err)
		return
	}

	perfMap.SetTimestampFunc(func(data *[]byte) (ts uint64) {
		_ = binary.Read(bytes.NewBuffer(*data), byteorder.Host, &ts)
		return
	})

	perfMap.PollStart()
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

func (t *EbpfTracker) stop() {
	// TODO: stop the go routine in run()
}
