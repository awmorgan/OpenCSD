package memacc

import (
	"opencsd/internal/ocsd"
)

// CallbackAccessor represents a callback trace memory accessor.
type CallbackAccessor struct {
	BaseAccessor
	CBFn   ocsd.FnMemAccCB
	CBIDFn ocsd.FnMemAccIDCB
	Ctx    any
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
func (c *CallbackAccessor) ReadBytes(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, byteBuffer []byte) uint32 {
	if !c.AddrInRange(address) || !c.InMemSpace(memSpace) {
		return 0
	}

	if c.CBIDFn != nil {
		return c.CBIDFn(c.Ctx, address, memSpace, trcID, reqBytes, byteBuffer)
	} else if c.CBFn != nil {
		return c.CBFn(c.Ctx, address, memSpace, reqBytes, byteBuffer)
	}

	return 0
}

// SetCBIfFn sets the callback function.
func (c *CallbackAccessor) SetCBIfFn(fn ocsd.FnMemAccCB, ctx any) {
	c.CBFn = fn
	c.Ctx = ctx
	c.CBIDFn = nil
}

// SetCBIDIfFn sets the callback with ID function.
func (c *CallbackAccessor) SetCBIDIfFn(fn ocsd.FnMemAccIDCB, ctx any) {
	c.CBIDFn = fn
	c.Ctx = ctx
	c.CBFn = nil
}

// InitAccessor re-initializes the accessor.
func (c *CallbackAccessor) InitAccessor(startAddr ocsd.VAddr, endAddr ocsd.VAddr, memSpace ocsd.MemSpaceAcc) {
	c.StartAddress = startAddr
	c.EndAddress = endAddr
	c.MemSpaceAcc = memSpace
}
