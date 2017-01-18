package endpoint

import (
	"net"
	"reflect"
	"strconv"
	"testing"

	"github.com/kinvolk/tcptracer-bpf/pkg/byteorder"
	"github.com/kinvolk/tcptracer-bpf/pkg/event"
)

var (
	ServerPid  uint32 = 42
	ClientPid  uint32 = 43
	ServerIP          = net.ParseIP("127.0.0.1")
	ClientIP          = net.ParseIP("127.0.0.2")
	ServerInt  uint32 = 16777343 // uint32 of 127.0.0.1
	ClientInt  uint32 = 33554559 // uint32 of 127.0.0.2
	ServerPort uint16 = 12345
	ClientPort uint16 = 6789
	NetNS      uint32 = 123456789

	IPv4ConnectEvent = event.Tcp{
		CPU:   0,
		Type:  event.EventConnect,
		Pid:   ClientPid,
		Comm:  [16]byte{},
		SAddr: ClientInt,
		DAddr: ServerInt,
		SPort: ClientPort,
		DPort: ServerPort,
		NetNS: NetNS,
	}

	IPv4ConnectEbpfConnection = ebpfConnection{
		tuple: fourTuple{
			fromAddr: ClientIP.String(),
			toAddr:   ServerIP.String(),
			fromPort: ClientPort,
			toPort:   ServerPort,
		},
		networkNamespace: strconv.Itoa(int(NetNS)),
		incoming:         false,
		pid:              int(ClientPid),
	}

	IPv4ConnectCloseEvent = event.Tcp{
		CPU:   0,
		Type:  event.EventClose,
		Pid:   ClientPid,
		Comm:  [16]byte{},
		SAddr: ClientInt,
		DAddr: ServerInt,
		SPort: ClientPort,
		DPort: ServerPort,
		NetNS: NetNS,
	}

	IPv4AcceptEvent = event.Tcp{
		CPU:   0,
		Type:  event.EventAccept,
		Pid:   ServerPid,
		Comm:  [16]byte{},
		SAddr: ServerInt,
		DAddr: ClientInt,
		SPort: ServerPort,
		DPort: ClientPort,
		NetNS: NetNS,
	}

	IPv4AcceptEbpfConnection = ebpfConnection{
		tuple: fourTuple{
			fromAddr: ServerIP.String(),
			toAddr:   ClientIP.String(),
			fromPort: ServerPort,
			toPort:   ClientPort,
		},
		networkNamespace: strconv.Itoa(int(NetNS)),
		incoming:         true,
		pid:              int(ServerPid),
	}

	IPv4AcceptCloseEvent = event.Tcp{
		CPU:   0,
		Type:  event.EventClose,
		Pid:   ClientPid,
		Comm:  [16]byte{},
		SAddr: ServerInt,
		DAddr: ClientInt,
		SPort: ServerPort,
		DPort: ClientPort,
		NetNS: NetNS,
	}
)

func convertEvent(event event.Tcp) (typ event.EventType, pid uint32, tuple fourTuple) {
	var alive bool
	typ = event.Type

	pid = event.Pid & 0xffffffff
	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	byteorder.Host.PutUint32(saddrbuf, uint32(event.SAddr))
	byteorder.Host.PutUint32(daddrbuf, uint32(event.DAddr))
	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := event.SPort
	dport := event.DPort

	if typ.String() == "close" || typ.String() == "unknown" {
		alive = true
	} else {
		alive = false
	}
	tuple = fourTuple{sIP.String(), dIP.String(), uint16(sport), uint16(dport), alive}
	return
}

func TestEbpfIPv4ConnectAndCloseEvent(t *testing.T) {
	mockEbpfTracker := &EbpfTracker{
		initialized: true,
		dead:        false,

		openConnections:   map[string]ebpfConnection{},
		closedConnections: []ebpfConnection{},
	}

	typ, pid, tuple := convertEvent(IPv4ConnectEvent)
	mockEbpfTracker.handleConnection(typ, tuple, int(pid), strconv.FormatUint(uint64(IPv4ConnectEvent.NetNS), 10))
	if !reflect.DeepEqual(mockEbpfTracker.openConnections[tuple.String()], IPv4ConnectEbpfConnection) {
		t.Errorf("Connection mismatch connect event\nTarget connection:%v\nParsed connection:%v",
			IPv4ConnectEbpfConnection, mockEbpfTracker.openConnections[tuple.String()])
	}

	typ, pid, tuple = convertEvent(IPv4ConnectCloseEvent)
	mockEbpfTracker.handleConnection(typ, tuple, int(pid), strconv.FormatUint(uint64(IPv4ConnectCloseEvent.NetNS), 10))

	if len(mockEbpfTracker.openConnections) != 0 {
		t.Errorf("Connection mismatch close event\nConnection to close:%v",
			mockEbpfTracker.openConnections[tuple.String()])
	}
}

func TestEbpfIPv4AcceptAndCloseEvent(t *testing.T) {
	mockEbpfTracker := &EbpfTracker{
		initialized: true,
		dead:        false,

		openConnections:   map[string]ebpfConnection{},
		closedConnections: []ebpfConnection{},
	}

	typ, pid, tuple := convertEvent(IPv4AcceptEvent)
	mockEbpfTracker.handleConnection(typ, tuple, int(pid), strconv.FormatUint(uint64(IPv4AcceptEvent.NetNS), 10))
	if !reflect.DeepEqual(mockEbpfTracker.openConnections[tuple.String()], IPv4AcceptEbpfConnection) {
		t.Errorf("Connection mismatch connect event\nTarget connection:%v\nParsed connection:%v",
			IPv4AcceptEbpfConnection, mockEbpfTracker.openConnections[tuple.String()])
	}

	typ, pid, tuple = convertEvent(IPv4AcceptCloseEvent)
	mockEbpfTracker.handleConnection(typ, tuple, int(pid), strconv.FormatUint(uint64(IPv4AcceptCloseEvent.NetNS), 10))

	if len(mockEbpfTracker.openConnections) != 0 {
		t.Errorf("Connection mismatch close event\nConnection to close:%v",
			mockEbpfTracker.openConnections)
	}

}
