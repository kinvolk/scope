package controls

import (
	"sync"

	"github.com/weaveworks/scope/common/xfer"
)

// HandlerRegistry is an interface for storing control request
// handlers.
type HandlerRegistry interface {
	// Register a new control handler under a given id.
	Register(control string, f xfer.ControlHandlerFunc)
	// Rm deletes the handler for a given name.
	Rm(control string)
	// Handler gets the handler for the given id.
	Handler(control string) (xfer.ControlHandlerFunc, bool)
	// RegisterBatch adds many controls in one go
}

type realHandlerRegistry map[string]xfer.ControlHandlerFunc

// Register a new control handler under a given id.
func (r realHandlerRegistry) Register(control string, f xfer.ControlHandlerFunc) {
	r[control] = f
}

// Rm deletes the handler for a given name.
func (r realHandlerRegistry) Rm(control string) {
	delete(r, control)
}

// Handler gets the handler for the given id.
func (r realHandlerRegistry) Handler(control string) (xfer.ControlHandlerFunc, bool) {
	handler, ok := r[control]
	return handler, ok
}

var (
	mtx                          = sync.Mutex{}
	realRegistry                 = realHandlerRegistry{}
	registry     HandlerRegistry = realRegistry
)

// Lock locks the registry, so the batch insertions or removals can be
// performed.
func Lock() {
	mtx.Lock()
}

// Unlock unlocks the registry.
func Unlock() {
	mtx.Unlock()
}

// SetHandlerRegistry sets custom registry for control request
// handlers.
func SetHandlerRegistry(newRegistry HandlerRegistry) {
	mtx.Lock()
	defer mtx.Unlock()
	registry = newRegistry
}

// ResetHandlerRegistry sets registry for control request handlers to
// the original one.
func ResetHandlerRegistry() {
	mtx.Lock()
	defer mtx.Unlock()
	registry = realRegistry
}

func handler(req xfer.Request) (xfer.ControlHandlerFunc, bool) {
	mtx.Lock()
	defer mtx.Unlock()
	return registry.Handler(req.Control)
}

// HandleControlRequest performs a control request.
func HandleControlRequest(req xfer.Request) xfer.Response {
	h, ok := handler(req)
	if !ok {
		return xfer.ResponseErrorf("Control %q not recognised", req.Control)
	}

	return h(req)
}

// Register registers a new control handler under a given id.
func Register(control string, f xfer.ControlHandlerFunc) {
	Lock()
	defer Unlock()
	RegisterLocked(control, f)
}

// RegisterLocked a new control handler under a given id. This
// function should be used only after getting an exclusive access to
// Registry with Lock().
func RegisterLocked(control string, f xfer.ControlHandlerFunc) {
	registry.Register(control, f)
}

// Rm deletes the handler for a given name.
func Rm(control string) {
	Lock()
	defer Unlock()
	RmLocked(control)
}

// RmLocked deletes the handler for a given name. This function should
// be used only after getting an exclusive access to Registry with
// Lock().
func RmLocked(control string) {
	registry.Rm(control)
}
