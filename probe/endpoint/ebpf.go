package endpoint

import (
	"errors"
	"strconv"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/kinvolk/tcptracer-bpf/pkg/tracer"
	"github.com/weaveworks/scope/probe/endpoint/procspy"
)

const bpfObjectPath = "/usr/libexec/scope/ebpf/tcptracer-ebpf.o"

// An ebpfConnection represents a TCP connection
type ebpfConnection struct {
	tuple            fourTuple
	networkNamespace string
	incoming         bool
	pid              int
}

type eventTracker interface {
	handleConnection(ev tracer.EventType, tuple fourTuple, pid int, networkNamespace string)
	walkConnections(f func(ebpfConnection))
	feedInitialConnections(ci procspy.ConnIter, seenTuples map[string]fourTuple, hostNodeID string)
	feedInitialConnectionsEmpty()
	isFed() bool
	stop()
}

var ebpfTracker *EbpfTracker

// EbpfTracker contains the sets of open and closed TCP connections.
// Closed connections are kept in the `closedConnections` slice for one iteration of `walkConnections`.
type EbpfTracker struct {
	sync.Mutex
	tracer *tracer.Tracer
	fed    bool
	dead   bool

	openConnections   map[string]ebpfConnection
	closedConnections []ebpfConnection
}

func newEbpfTracker(useEbpfConn bool) (eventTracker, error) {
	if !useEbpfConn {
		return nil, errors.New("ebpf tracker not enabled")
	}

	t, err := tracer.NewTracerFromFile(bpfObjectPath, tcpEventCbV4, tcpEventCbV6)
	if err != nil {
		log.Errorf("Cannot find BPF object file: %v", err)
		return nil, err
	}

	tracker := &EbpfTracker{
		openConnections: map[string]ebpfConnection{},
		tracer:          t,
	}

	ebpfTracker = tracker
	return tracker, nil
}

var lastTimestampV4 uint64

func tcpEventCbV4(e tracer.TcpV4) {
	if lastTimestampV4 > e.Timestamp {
		log.Errorf("ERROR: late event!\n")
	}

	lastTimestampV4 = e.Timestamp

	var active bool
	if e.Type == tracer.EventClose {
		active = true
	} else {
		active = false
	}
	tuple := fourTuple{e.SAddr.String(), e.DAddr.String(), e.SPort, e.DPort, active}
	ebpfTracker.handleConnection(e.Type, tuple, int(e.Pid), strconv.Itoa(int(e.NetNS)))
}

func tcpEventCbV6(e tracer.TcpV6) {
	// TODO: IPv6 not supported in Scope
}

func (t *EbpfTracker) handleConnection(ev tracer.EventType, tuple fourTuple, pid int, networkNamespace string) {
	t.Lock()
	defer t.Unlock()
	log.Debugf("handleConnection(%v, [%v:%v --> %v:%v], pid=%v, netNS=%v)",
		ev, tuple.fromAddr, tuple.fromPort, tuple.toAddr, tuple.toPort, pid, networkNamespace)

	switch ev {
	case tracer.EventConnect:
		conn := ebpfConnection{
			incoming:         false,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.openConnections[tuple.String()] = conn
	case tracer.EventAccept:
		conn := ebpfConnection{
			incoming:         true,
			tuple:            tuple,
			pid:              pid,
			networkNamespace: networkNamespace,
		}
		t.openConnections[tuple.String()] = conn
	case tracer.EventClose:
		if deadConn, ok := t.openConnections[tuple.String()]; ok {
			delete(t.openConnections, tuple.String())
			t.closedConnections = append(t.closedConnections, deadConn)
		} else {
			log.Errorf("EbpfTracker error: unmatched close event: %s pid=%d netns=%s", tuple.String(), pid, networkNamespace)
		}
	}
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

func (t *EbpfTracker) feedInitialConnections(conns procspy.ConnIter, seenTuples map[string]fourTuple, hostNodeID string) {
	for conn := conns.Next(); conn != nil; conn = conns.Next() {
		var (
			namespaceID string
			tuple       = fourTuple{
				conn.LocalAddress.String(),
				conn.RemoteAddress.String(),
				conn.LocalPort,
				conn.RemotePort,
				true,
			}
		)

		if conn.Proc.NetNamespaceID > 0 {
			namespaceID = strconv.FormatUint(conn.Proc.NetNamespaceID, 10)
		}

		// We can use a port-heuristic to guess the direction.
		// We assume that tuple.fromPort < tuple.toPort is a connect event (outgoing)
		canonical, ok := seenTuples[tuple.key()]
		if (ok && canonical != tuple) || (!ok && tuple.fromPort < tuple.toPort) {
			t.handleConnection(tracer.EventConnect, tuple, int(conn.Proc.PID), namespaceID)
		} else {
			t.handleConnection(tracer.EventAccept, tuple, int(conn.Proc.PID), namespaceID)
		}
	}
	t.fed = true
}

func (t *EbpfTracker) feedInitialConnectionsEmpty() {
	t.fed = true
}

func (t *EbpfTracker) isFed() bool {
	return t.fed
}

func (t *EbpfTracker) stop() {
	// TODO: stop the go routine in run()
}
