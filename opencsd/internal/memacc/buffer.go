package memacc

import "opencsd/internal/ocsd"

// BufferAccessor represents a memory accessor for a memory buffer.
type BufferAccessor struct {
	BaseAccessor
	Buffer []byte
}

// NewBufferAccessor creates a new buffer accessor.
func NewBufferAccessor(startAddr ocsd.VAddr, buffer []byte) *BufferAccessor {
	b := &BufferAccessor{Buffer: buffer}
	b.BaseAccessor = newBaseAccessor(startAddr, endAddress(startAddr, len(buffer)), TypeBufPtr, ocsd.MemSpaceAny)
	return b
}

// ReadBytes implements the Accessor interface.
func (b *BufferAccessor) ReadBytes(address ocsd.VAddr, _ ocsd.MemSpaceAcc, _ uint8, reqBytes uint32, buffer []byte) uint32 {
	bytesToRead := min(b.BytesInRange(address, reqBytes), uint32(len(buffer)))
	if bytesToRead == 0 {
		return 0
	}

	offset := address - b.StartAddress
	copy(buffer, b.Buffer[offset:offset+ocsd.VAddr(bytesToRead)])
	return bytesToRead
}

// Configure updates the accessor address range and backing buffer.
func (b *BufferAccessor) Configure(startAddr ocsd.VAddr, buffer []byte) {
	b.StartAddress = startAddr
	b.EndAddress = endAddress(startAddr, len(buffer))
	b.Buffer = buffer
}

func newBaseAccessor(startAddr, endAddr ocsd.VAddr, typ Type, memSpace ocsd.MemSpaceAcc) BaseAccessor {
	return BaseAccessor{
		StartAddress: startAddr,
		EndAddress:   endAddr,
		AccType:      typ,
		MemSpaceAcc:  memSpace,
	}
}

func endAddress(startAddr ocsd.VAddr, size int) ocsd.VAddr {
	if size == 0 {
		return startAddr
	}
	return startAddr + ocsd.VAddr(size) - 1
}
