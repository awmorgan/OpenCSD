package memacc

import (
	"opencsd/internal/ocsd"
)

// CallbackAccessor represents a callback trace memory accessor.
type CallbackAccessor struct {
	BaseAccessor
	callback        ocsd.FnMemAccCB
	traceIDCallback ocsd.FnMemAccIDCB
	context         any
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
		return c.traceIDCallback(c.context, address, memSpace, trcID, reqBytes, buffer)
	} else if c.callback != nil {
		return c.callback(c.context, address, memSpace, reqBytes, buffer)
	}

	return 0
}

// SetCallback sets a callback function that does not take a trace ID.
func (c *CallbackAccessor) SetCallback(fn ocsd.FnMemAccCB, ctx any) {
	c.callback = fn
	c.context = ctx
	c.traceIDCallback = nil
}

// SetTraceIDCallback sets a callback function that includes trace ID.
func (c *CallbackAccessor) SetTraceIDCallback(fn ocsd.FnMemAccIDCB, ctx any) {
	c.traceIDCallback = fn
	c.context = ctx
	c.callback = nil
}

// Configure updates accessor range and memory-space routing.
func (c *CallbackAccessor) Configure(startAddr ocsd.VAddr, endAddr ocsd.VAddr, memSpace ocsd.MemSpaceAcc) {
	c.StartAddress = startAddr
	c.EndAddress = endAddr
	c.MemSpaceAcc = memSpace
}
