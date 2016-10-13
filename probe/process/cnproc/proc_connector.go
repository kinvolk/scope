package cnproc

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"sync"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/weaveworks/scope/common/fs"
)

const (
	// <linux/connector.h>
	CN_IDX_PROC = 0x1
	CN_VAL_PROC = 0x1

	// <linux/cn_proc.h>
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE = 2

	PROC_EVENT_FORK = 0x00000001 // fork() events
	PROC_EVENT_EXEC = 0x00000002 // exec() events
	PROC_EVENT_EXIT = 0x80000000 // exit() events
)

var (
	byteOrder = binary.LittleEndian
)

// ProcConnector receives events from the proc connector and maintain the set
// of processes.
type ProcConnector struct {
	Running bool

	sockfd       int
	seq          uint32
	lock         sync.RWMutex
	activePids   map[int]Process
	bufferedPids []Process
}

// Process represents a single process. Only include the constant details here.
type Process struct {
	Pid     int
	Name    string
	Cmdline string
}

// linux/connector.h: struct cb_id
type cbId struct {
	Idx uint32
	Val uint32
}

// linux/connector.h: struct cb_msg
type cnMsg struct {
	Id    cbId
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

// linux/cn_proc.h: struct proc_event.{what,cpu,timestamp_ns}
type procEventHeader struct {
	What      uint32
	Cpu       uint32
	Timestamp uint64
}

// linux/cn_proc.h: struct proc_event.fork
type forkProcEvent struct {
	ParentPid  uint32
	ParentTgid uint32
	ChildPid   uint32
	ChildTgid  uint32
}

// linux/cn_proc.h: struct proc_event.exec
type execProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
}

// linux/cn_proc.h: struct proc_event.exit
type exitProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
	ExitCode    uint32
	ExitSignal  uint32
}

// standard netlink header + connector header
type netlinkProcMessage struct {
	Header syscall.NlMsghdr
	Data   cnMsg
}

// newProcConnector creates a new process Walker.
func NewProcConnector() (cn *ProcConnector) {
	cn = &ProcConnector{
		Running:    false,
		activePids: map[int]Process{},
	}

	var err error
	cn.sockfd, err = syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM,
		syscall.NETLINK_CONNECTOR)
	if err != nil {
		return &ProcConnector{}
	}

	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: CN_IDX_PROC,
	}

	err = syscall.Bind(cn.sockfd, addr)
	if err != nil {
		return &ProcConnector{}
	}

	err = cn.subscribe(addr)
	if err != nil {
		return &ProcConnector{}
	}

	// get the initial set of pids before receiving the updates
	dirEntries, err := fs.ReadDirNames("/proc")
	if err != nil {
		return &ProcConnector{}
	}

	for _, filename := range dirEntries {
		pid, err := strconv.Atoi(filename)
		if err != nil {
			continue
		}

		cmdline, name := GetCmdline(pid)

		cn.activePids[pid] = Process{
			Pid:     pid,
			Name:    name,
			Cmdline: cmdline,
		}
	}

	log.Infof("Proc connector successfully initialized (%d processes)", len(cn.activePids))

	go cn.receive()

	cn.Running = true

	return cn
}

func GetCmdline(pid int) (name, cmdline string) {
	name = "(unknown)"

	cmdlineBuf, err := ioutil.ReadFile(path.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err == nil {
		i := bytes.IndexByte(cmdlineBuf, '\000')
		if i == -1 {
			i = len(cmdlineBuf)
		}
		name = string(cmdlineBuf[:i])
		cmdlineBuf = bytes.Replace(cmdlineBuf, []byte{'\000'}, []byte{' '}, -1)
		cmdline = string(cmdlineBuf)
	}
	return
}

func (cn *ProcConnector) subscribe(addr *syscall.SockaddrNetlink) error {
	var op uint32
	op = PROC_CN_MCAST_LISTEN
	cn.seq++

	pr := &netlinkProcMessage{}
	plen := binary.Size(pr.Data) + binary.Size(op)
	pr.Header.Len = syscall.NLMSG_HDRLEN + uint32(plen)
	pr.Header.Type = uint16(syscall.NLMSG_DONE)
	pr.Header.Flags = 0
	pr.Header.Seq = cn.seq
	pr.Header.Pid = uint32(os.Getpid())

	pr.Data.Id.Idx = CN_IDX_PROC
	pr.Data.Id.Val = CN_VAL_PROC

	pr.Data.Len = uint16(binary.Size(op))

	buf := bytes.NewBuffer(make([]byte, 0, pr.Header.Len))
	binary.Write(buf, byteOrder, pr)
	binary.Write(buf, byteOrder, op)

	err := syscall.Sendto(cn.sockfd, buf.Bytes(), 0, addr)
	return err
}

func (cn *ProcConnector) receive() {
	buf := make([]byte, syscall.Getpagesize())

	for {
		nr, _, err := syscall.Recvfrom(cn.sockfd, buf, 0)
		if err != nil {
			log.Errorf("Proc connector failed to receive a message")
			cn.Running = false
			return
		}
		if nr < syscall.NLMSG_HDRLEN {
			continue
		}

		msgs, _ := syscall.ParseNetlinkMessage(buf[:nr])
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_DONE {
				cn.handleEvent(m.Data)
			}
		}
	}
}

func (cn *ProcConnector) handleEvent(data []byte) {
	buf := bytes.NewBuffer(data)
	msg := &cnMsg{}
	hdr := &procEventHeader{}

	binary.Read(buf, byteOrder, msg)
	binary.Read(buf, byteOrder, hdr)

	switch hdr.What {
	case PROC_EVENT_FORK:
		event := &forkProcEvent{}
		binary.Read(buf, byteOrder, event)
		pid := int(event.ChildTgid)

		cmdline, name := GetCmdline(pid)

		cn.lock.Lock()
		cn.activePids[pid] = Process{
			Pid:     pid,
			Name:    name,
			Cmdline: cmdline,
		}
		cn.lock.Unlock()

	case PROC_EVENT_EXEC:
		event := &execProcEvent{}
		binary.Read(buf, byteOrder, event)
		pid := int(event.ProcessTgid)

		cmdline, name := GetCmdline(pid)

		cn.lock.Lock()
		cn.activePids[pid] = Process{
			Pid:     pid,
			Name:    name,
			Cmdline: cmdline,
		}
		cn.lock.Unlock()

	case PROC_EVENT_EXIT:
		event := &exitProcEvent{}
		binary.Read(buf, byteOrder, event)
		pid := int(event.ProcessTgid)

		cn.lock.Lock()
		defer cn.lock.Unlock()

		if pr, ok := cn.activePids[pid]; ok {
			cn.bufferedPids = append(cn.bufferedPids, pr)
			delete(cn.activePids, pid)
		}

	}
}

func (cn *ProcConnector) Walk(f func(pid Process)) {
	cn.lock.RLock()
	defer cn.lock.RUnlock()

	for _, pid := range cn.activePids {
		f(pid)
	}
	for _, pid := range cn.bufferedPids {
		f(pid)
	}
	cn.bufferedPids = cn.bufferedPids[:0]
}
