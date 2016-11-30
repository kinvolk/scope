package endpoint

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	bpflib "github.com/kinvolk/go-ebpf-kprobe-example/bpf"
)

/*
#cgo CFLAGS: -Wall -Wno-unused-variable
#cgo LDFLAGS: -lelf

#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <errno.h>
#include <linux/bpf.h>

#define TASK_COMM_LEN 16

struct tcp_event_t {
	char ev_type[12];
	__u32 pid;
	char comm[TASK_COMM_LEN];
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 netns;
};
*/
import "C"

var byteOrder binary.ByteOrder

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
	//readers     []*C.struct_perf_reader
	reader      *bpflib.BpfPerfEvent
	initialized bool
	dead        bool

	openConnections   map[string]ebpfConnection
	closedConnections []ebpfConnection
}

func newEbpfTracker(useEbpfConn bool) eventTracker {
	if !useEbpfConn {
		return &nilTracker{}
	}

	b, err := bpflib.NewBpfPerfEvent("/var/run/scope/ebpf/trace_output_kern.o")
	if err != nil {
		return &nilTracker{}
	}

	tracker := &EbpfTracker{
		openConnections: map[string]ebpfConnection{},
		reader:         b,
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

func handleConnection(eventType string, tuple fourTuple, pid int, networkNamespace string) {
	ebpfTracker.handleConnection(eventType, tuple, pid, networkNamespace)
}

func tcpEventCallback(tcpEvent *C.struct_tcp_event_t) {
	typ := C.GoString(&tcpEvent.ev_type[0])
	pid := tcpEvent.pid & 0xffffffff

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(tcpEvent.saddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(tcpEvent.daddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := tcpEvent.sport
	dport := tcpEvent.dport
	netns := tcpEvent.netns

	tuple := fourTuple{sIP.String(), dIP.String(), uint16(sport), uint16(dport)}
	handleConnection(typ, tuple, int(pid), strconv.Itoa(int(netns)))
}

//export tcpEventCb
func tcpEventCb(data []byte) {
	// See src/cc/perf_reader.c:parse_sw()
	// struct {
	//     uint32_t size;
	//     char data[0];
	// };

	tcpEvent := (*C.struct_tcp_event_t)(unsafe.Pointer(&data[0]))
	tcpEventCallback(tcpEvent)
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
	t.reader.Poll(tcpEventCb)
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
