package endpoint

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	bpflib "github.com/kinvolk/gobpf-elf-loader/bpf"
)

import "C"

var byteOrder binary.ByteOrder

type EventType uint32

const (
	_ EventType = iota
	EventConnect
	EventAccept
	EventClose
)

func (e EventType) String() string {
	switch e {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	case EventClose:
		return "close"
	default:
		return "unknown"
	}
}

type tcpEvent struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu   uint64
	Type  uint32
	Pid   uint32
	Comm  [16]byte
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	NetNS uint32
}

// An ebpfConnection represents a TCP connection
type ebpfConnection struct {
	tuple            fourTuple
	networkNamespace string
	incoming         bool
	pid              int
}

type eventTracker interface {
	handleConnection(eventType string, tuple fourTuple, pid int, networkNamespace string)
	hasDied() bool
	run()
	walkConnections(f func(ebpfConnection))
	initialize()
	isInitialized() bool
}

var ebpfTracker *EbpfTracker

// nilTracker is a tracker that does nothing, and it implements the eventTracker interface.
// It is returned when the useEbpfConn flag is false.
type nilTracker struct{}

func (n nilTracker) handleConnection(_ string, _ fourTuple, _ int, _ string) {}
func (n nilTracker) hasDied() bool                                           { return true }
func (n nilTracker) run()                                                    {}
func (n nilTracker) walkConnections(f func(ebpfConnection))                  {}
func (n nilTracker) initialize()                                             {}
func (n nilTracker) isInitialized() bool                                     { return false }

// EbpfTracker contains the sets of open and closed TCP connections.
// Closed connections are kept in the `closedConnections` slice for one iteration of `walkConnections`.
type EbpfTracker struct {
	sync.Mutex
	reader      *bpflib.BPFKProbePerf
	initialized bool
	dead        bool

	openConnections   map[string]ebpfConnection
	closedConnections []ebpfConnection
}

func newEbpfTracker(useEbpfConn bool) eventTracker {
	log.Infof("newEbpfTracker")
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	if !useEbpfConn {
		log.Infof("useEbpfConn is false")
		return &nilTracker{}
	}

	bpfPerfEvent := bpflib.NewBpfPerfEvent("/var/run/scope/ebpf/ebpf.o")
	err := bpfPerfEvent.Load()
	if err != nil {
		log.Errorf("newEbpfTracker: load err=%v", err)
		return &nilTracker{}
	}

	tracker := &EbpfTracker{
		openConnections: map[string]ebpfConnection{},
		reader:          bpfPerfEvent,
	}
	go tracker.run()

	ebpfTracker = tracker
	return tracker
}

func (t *EbpfTracker) handleConnection(eventType string, tuple fourTuple, pid int, networkNamespace string) {
	t.Lock()
	defer t.Unlock()

	switch eventType {
	case "connect":
		conn := ebpfConnection{
			incoming:         false,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.openConnections[tuple.String()] = conn
	case "accept":
		conn := ebpfConnection{
			incoming:         true,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.openConnections[tuple.String()] = conn
	case "close":
		if deadConn, ok := t.openConnections[tuple.String()]; ok {
			delete(t.openConnections, tuple.String())
			t.closedConnections = append(t.closedConnections, deadConn)
		} else {
			log.Errorf("EbpfTracker error: unmatched close event: %s pid=%d netns=%s", tuple.String(), pid, networkNamespace)
		}
	}
}

func tcpEventCallback(event tcpEvent) {
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(event.SAddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(event.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := event.SPort
	dport := event.DPort

	tuple := fourTuple{sIP.String(), dIP.String(), uint16(sport), uint16(dport)}

	log.Infof("handleConnection(%s, [%s:%d --> %s:%d], pid=%d, netNS=%d, cpu=%d, ts=%d)",
		typ.String(), tuple.fromAddr, tuple.fromPort, tuple.toAddr, tuple.toPort, pid, event.NetNS, event.Cpu, event.Timestamp)
	ebpfTracker.handleConnection(typ.String(), tuple, int(pid), string(event.NetNS))
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
	log.Infof("EbpfTracker.run()")
	channel := make(chan []byte)

	go func() {
		var event tcpEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), byteOrder, &event)
			if err != nil {
				log.Errorf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCallback(event)
		}
	}()

	log.Infof("EbpfTracker: t.reader.PollStart('tcp_event_v4'")
	t.reader.PollStart("tcp_event_v4", channel)
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
	t.reader.PollStop("tcp_event_v4")
}
