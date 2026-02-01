package common

import (
	"fmt"
)

// MemoryAccessorCallback is a function signature for callbacks that provide memory access.
// It's called when memory outside of static buffers needs to be accessed.
// Parameters:
//
//	addr: The memory address to read from
//	traceID: The trace source ID
//	space: The memory space being accessed
//	data: Buffer to fill with memory contents
//
// Returns:
//
//	The number of bytes successfully read
type MemoryAccessorCallback func(addr uint64, traceID uint8, space MemorySpace, data []byte) int

// CallbackAccessor implements MemoryAccessor using a callback function.
// This allows dynamic memory ranges that change based on trace ID or other context.
type CallbackAccessor struct {
	startAddr uint64
	endAddr   uint64
	memSpace  MemorySpace
	callback  MemoryAccessorCallback
	context   interface{}
}

// NewCallbackAccessor creates a memory accessor backed by a callback function.
// The callback is responsible for reading memory for addresses in [startAddr, endAddr).
func NewCallbackAccessor(startAddr, endAddr uint64, callback MemoryAccessorCallback) *CallbackAccessor {
	return &CallbackAccessor{
		startAddr: startAddr,
		endAddr:   endAddr,
		memSpace:  MemSpaceANY,
		callback:  callback,
	}
}

// NewCallbackAccessorWithContext creates a memory accessor backed by a callback function
// with an additional context parameter.
func NewCallbackAccessorWithContext(startAddr, endAddr uint64, callback MemoryAccessorCallback, context interface{}) *CallbackAccessor {
	return &CallbackAccessor{
		startAddr: startAddr,
		endAddr:   endAddr,
		memSpace:  MemSpaceANY,
		callback:  callback,
		context:   context,
	}
}

// ReadMemory implements MemoryAccessor.ReadMemory.
func (ca *CallbackAccessor) ReadMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	// Check if the requested space matches this accessor's space
	if !ca.memSpace.InMemSpace(space) {
		return 0, fmt.Errorf("address 0x%X space mismatch: requested %s but accessor is %s",
			addr, space.String(), ca.memSpace.String())
	}

	// Check if address is in range
	if addr < ca.startAddr || addr >= ca.endAddr {
		return 0, fmt.Errorf("address 0x%X is outside callback range [0x%X, 0x%X)",
			addr, ca.startAddr, ca.endAddr)
	}

	// Ensure we don't read past the end of this accessor's range
	available := ca.endAddr - addr
	toRead := uint64(len(data))
	if toRead > available {
		toRead = available
	}

	if ca.callback == nil {
		return 0, fmt.Errorf("callback not set for address 0x%X", addr)
	}

	// Call the callback to get the memory
	buffer := make([]byte, toRead)
	bytesRead := ca.callback(addr, traceID, space, buffer)
	copy(data, buffer[:bytesRead])
	return bytesRead, nil
}

// ReadTargetMemory implements MemoryAccessor.ReadTargetMemory.
func (ca *CallbackAccessor) ReadTargetMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	return ca.ReadMemory(addr, traceID, space, data)
}

// MemSpace returns the memory space(s) this accessor covers.
func (ca *CallbackAccessor) MemSpace() MemorySpace {
	return ca.memSpace
}

// SetMemSpace sets the memory space(s) this accessor covers.
func (ca *CallbackAccessor) SetMemSpace(space MemorySpace) {
	ca.memSpace = space
}

// StartAddr returns the start of the range this accessor covers.
func (ca *CallbackAccessor) StartAddr() uint64 {
	return ca.startAddr
}

// EndAddr returns the end of the range this accessor covers.
func (ca *CallbackAccessor) EndAddr() uint64 {
	return ca.endAddr
}

// Context returns the context associated with this accessor.
func (ca *CallbackAccessor) Context() interface{} {
	return ca.context
}

// SetContext sets the context associated with this accessor.
func (ca *CallbackAccessor) SetContext(context interface{}) {
	ca.context = context
}
