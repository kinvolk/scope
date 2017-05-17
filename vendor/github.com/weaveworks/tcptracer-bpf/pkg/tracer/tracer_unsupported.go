// +build !linux

package tracer

import (
	"fmt"
)

type Tracer struct{}

func TracerAsset() ([]byte, error) {
	return nil, fmt.Errorf("not supported on non-Linux systems")
}

func NewTracer(tcpEventCbV4 func(TcpV4), tcpEventCbV6 func(TcpV6), lostCb func(lost uint64)) (*Tracer, error) {
	return nil, fmt.Errorf("not supported on non-Linux systems")
}
func (t *Tracer) AddFdInstallWatcher(pid uint32) (err error) {
	return fmt.Errorf("not supported on non-Linux systems")
}
func (t *Tracer) RemoveFdInstallWatcher(pid uint32) (err error) {
	return fmt.Errorf("not supported on non-Linux systems")
}

func (t *Tracer) Stop() {
}
