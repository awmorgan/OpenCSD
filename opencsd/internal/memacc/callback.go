package memacc

import (
	"opencsd/internal/ocsd"
)

// CallbackAccessor represents a callback trace memory accessor.
type CallbackAccessor struct {
	BaseAccessor
	callback        ocsd.MemAccessor
	traceIDCallback ocsd.MemAccessorWithID
}

// NewCallbackAccessor creates a new callback accessor.
func NewCallbackAccessor(startAddr ocsd.VAddr, endAddr ocsd.VAddr, memSpace ocsd.MemSpaceAcc) *CallbackAccessor {
	return &CallbackAccessor{
		BaseAccessor: BaseAccessor{
			StartAddress: startAddr,
			EndAddress:   endAddr,
			AccType:      TypeCBIf,
			MemSpaceAcc:  memSpace,
		},
	}
}

// ReadBytes implements the Accessor interface.
func (c *CallbackAccessor) ReadBytes(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32 {
	if c.traceIDCallback != nil {
		return c.traceIDCallback(address, memSpace, trcID, reqBytes, buffer)
	} else if c.callback != nil {
		return c.callback(address, memSpace, reqBytes, buffer)
	}

	return 0
}

// SetCallback sets a callback function that does not take a trace ID.
func (c *CallbackAccessor) SetCallback(fn ocsd.MemAccessor) {
	c.callback = fn
	c.traceIDCallback = nil
}

// SetTraceIDCallback sets a callback function that includes trace ID.
func (c *CallbackAccessor) SetTraceIDCallback(fn ocsd.MemAccessorWithID) {
	c.traceIDCallback = fn
	c.callback = nil
}

// Configure updates accessor range and memory-space routing.
func (c *CallbackAccessor) Configure(startAddr ocsd.VAddr, endAddr ocsd.VAddr, memSpace ocsd.MemSpaceAcc) {
	c.StartAddress = startAddr
	c.EndAddress = endAddr
	c.MemSpaceAcc = memSpace
}
