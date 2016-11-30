package bpf

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
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
#include "libbpf.h"
#include "perf_utils.h"

#define MAX_MAPS 32
extern int map_fd[MAX_MAPS];

int load_bpf_file(char *path);

extern void eventCb();
*/
import "C"

type EventCb func([]byte)

var myEventCb EventCb

type BpfPerfEvent struct {
	pmuFDs  []C.int
	headers []*C.struct_perf_event_mmap_page

	mapFd   [32]C.int
	progFd  [32]C.int
	eventFd [32]C.int
}

func perfEventPoll(fd int) error {
	var pfd C.struct_pollfd

	pfd.fd = C.int(fd)
	pfd.events = C.POLLIN

	_, err := C.poll(&pfd, 1, 1000)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

//export eventCb
func eventCb(data unsafe.Pointer, size C.int) {
	b := C.GoBytes(data, size)

	myEventCb(b)
}

func NewBpfPerfEvent(fileName string) (*BpfPerfEvent, error) {
	bpfObjectFile := C.CString(fileName)
	defer C.free(unsafe.Pointer(bpfObjectFile))

	ret := C.load_bpf_file(bpfObjectFile)
	if ret != 0 {
		return nil, fmt.Errorf("load_bpf_file error: %v\n", syscall.Errno(ret))
		os.Exit(1)
	}

	var attr C.struct_perf_event_attr
	var cpu C.int = 0
	var pmuFDs []C.int
	var headers []*C.struct_perf_event_mmap_page

	attr.size = C.sizeof_struct_perf_event_attr
	attr.config = 10 // PERF_COUNT_SW_BPF_OUTPUT
	attr._type = C.PERF_TYPE_SOFTWARE
	attr.sample_type = C.PERF_SAMPLE_RAW

	for {
		pmuFD := C.perf_event_open(&attr, -1 /* pid */, cpu /* cpu */, -1 /* group_fd */, C.PERF_FLAG_FD_CLOEXEC)
		if pmuFD < 0 {
			break
		}

		// mmap
		pageSize := os.Getpagesize()
		mmapSize := pageSize * (C.PAGE_COUNT + 1)

		base, err := syscall.Mmap(int(pmuFD), 0, mmapSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return nil, fmt.Errorf("mmap error: %v", err)
		}

		// enable
		_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pmuFD), C.PERF_EVENT_IOC_ENABLE, 0)
		if err2 != 0 {
			log.Fatal("error enabling perf event: %v", err2)
		}

		// assign perf fd tp map
		ret := C.bpf_update_elem(C.map_fd[0], unsafe.Pointer(&cpu), unsafe.Pointer(&pmuFD), C.BPF_ANY)
		if ret != 0 {
			break
			log.Fatal("bpf_update_elem error: %d", syscall.Errno(ret))
		}

		pmuFDs = append(pmuFDs, pmuFD)
		headers = append(headers, (*C.struct_perf_event_mmap_page)(unsafe.Pointer(&base[0])))

		cpu++
		if cpu == 4 {
			break
		}
	}

	return &BpfPerfEvent{
		pmuFDs:  pmuFDs,
		headers: headers,
	}, nil
}

func (b *BpfPerfEvent) Poll(cb EventCb) {
	// TODO: do something like
	// https://github.com/iovisor/gobpf/pull/2/files#diff-51d172d4e15a1a9ddb788f8eb973a93fR70
	myEventCb = cb

	for i, _ := range b.pmuFDs {
		go func(cpu int) {
			for {
				perfEventPoll(int(b.pmuFDs[cpu]))
				C.perf_event_read(b.headers[cpu], (*[0]byte)(C.eventCb))
			}
		}(i)
	}
}
