package memacc

import (
	"opencsd/internal/ocsd"
)

// BufferAccessor represents a memory accessor for a memory buffer.
type BufferAccessor struct {
	BaseAccessor
	Buffer []byte
}

// NewBufferAccessor creates a new buffer accessor.
func NewBufferAccessor(startAddr ocsd.VAddr, buffer []byte) *BufferAccessor {
	size := uint32(len(buffer))
	return &BufferAccessor{
		BaseAccessor: BaseAccessor{
			StartAddress: startAddr,
			EndAddress:   startAddr + ocsd.VAddr(size) - 1,
			AccType:      TypeBufPtr,
			MemSpaceAcc:  ocsd.MemSpaceAny,
		},
		Buffer: buffer,
	}
}

// ReadBytes implements the Accessor interface.
func (b *BufferAccessor) ReadBytes(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, byteBuffer []byte) uint32 {
	if !b.AddrInRange(address) || !b.InMemSpace(memSpace) {
		return 0
	}

	offset := address - b.StartAddress
	bytesToRead := b.BytesInRange(address, reqBytes)

	if bytesToRead > 0 {
		copy(byteBuffer, b.Buffer[offset:offset+ocsd.VAddr(bytesToRead)])
	}

	return bytesToRead
}

// InitAccessor re-initializes the accessor with new values.
func (b *BufferAccessor) InitAccessor(startAddr ocsd.VAddr, buffer []byte) {
	b.StartAddress = startAddr
	b.EndAddress = startAddr + ocsd.VAddr(len(buffer)) - 1
	b.Buffer = buffer
}
