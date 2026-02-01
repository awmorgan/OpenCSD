package common

import (
	"fmt"
)

// MemoryBuffer implements MemoryAccessor for a single contiguous region of memory.
// This is typically used to hold the contents of a .bin memory snapshot file.
type MemoryBuffer struct {
	// BaseAddr is the starting address of this memory region
	BaseAddr uint64
	// Data holds the actual memory contents
	Data []byte
	// memSpace specifies which memory space(s) this buffer covers
	memSpace MemorySpace
}

// NewMemoryBuffer creates a new memory buffer for the given address range.
func NewMemoryBuffer(baseAddr uint64, data []byte) *MemoryBuffer {
	return &MemoryBuffer{
		BaseAddr: baseAddr,
		Data:     data,
		memSpace: MemSpaceANY, // Default to ANY space
	}
}

// ReadMemory implements MemoryAccessor.ReadMemory.
// Reads bytes from the memory buffer at the specified address.
func (mb *MemoryBuffer) ReadMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	// Check if the requested space matches this buffer's space
	if !mb.memSpace.InMemSpace(space) {
		return 0, fmt.Errorf("address 0x%X space mismatch: requested %s but buffer is %s",
			addr, space.String(), mb.memSpace.String())
	}

	// Check if address is before our region
	if addr < mb.BaseAddr {
		return 0, fmt.Errorf("address 0x%X is before buffer base 0x%X", addr, mb.BaseAddr)
	}

	// Calculate offset into our buffer
	offset := addr - mb.BaseAddr

	// Check if address is beyond our region
	if offset >= uint64(len(mb.Data)) {
		return 0, fmt.Errorf("address 0x%X is beyond buffer range (0x%X - 0x%X)",
			addr, mb.BaseAddr, mb.BaseAddr+uint64(len(mb.Data)))
	}

	// Calculate how many bytes we can actually read
	available := uint64(len(mb.Data)) - offset
	toRead := uint64(len(data))
	if toRead > available {
		toRead = available
	}

	// Copy the data
	copy(data, mb.Data[offset:offset+toRead])

	return int(toRead), nil
}

// ReadTargetMemory implements MemoryAccessor.ReadTargetMemory.
// This mirrors the C++ naming and delegates to ReadMemory.
func (mb *MemoryBuffer) ReadTargetMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	return mb.ReadMemory(addr, traceID, space, data)
}

// Contains checks if the given address falls within this buffer's range.
func (mb *MemoryBuffer) Contains(addr uint64) bool {
	return addr >= mb.BaseAddr && addr < mb.BaseAddr+uint64(len(mb.Data))
}

// EndAddr returns the address immediately after the last byte in this buffer.
func (mb *MemoryBuffer) EndAddr() uint64 {
	return mb.BaseAddr + uint64(len(mb.Data))
}

// MemSpace returns the memory space(s) this buffer covers.
func (mb *MemoryBuffer) MemSpace() MemorySpace {
	return mb.memSpace
}

// SetMemSpace sets the memory space(s) this buffer covers.
func (mb *MemoryBuffer) SetMemSpace(space MemorySpace) {
	mb.memSpace = space
}

// MultiRegionMemory implements MemoryAccessor for multiple non-overlapping memory regions.
// This allows modeling a full system memory map with multiple .bin files (e.g., VECTORS, RAM, ROM).
type MultiRegionMemory struct {
	Regions  []*MemoryBuffer
	memSpace MemorySpace
}

// NewMultiRegionMemory creates a memory accessor that spans multiple regions.
func NewMultiRegionMemory() *MultiRegionMemory {
	return &MultiRegionMemory{
		Regions:  make([]*MemoryBuffer, 0),
		memSpace: MemSpaceANY,
	}
}

// AddRegion adds a memory region to this multi-region accessor.
// Regions should be added in ascending address order for optimal performance.
func (mrm *MultiRegionMemory) AddRegion(region *MemoryBuffer) {
	mrm.Regions = append(mrm.Regions, region)
}

// ReadMemory implements MemoryAccessor.ReadMemory.
// Searches all regions for the requested address and reads from the matching region.
func (mrm *MultiRegionMemory) ReadMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	// Check if the requested space matches this accessor's space
	if !mrm.memSpace.InMemSpace(space) {
		return 0, fmt.Errorf("address 0x%X space mismatch: requested %s but accessor is %s",
			addr, space.String(), mrm.memSpace.String())
	}

	// Find the region containing this address
	for _, region := range mrm.Regions {
		if region.Contains(addr) {
			return region.ReadMemory(addr, traceID, space, data)
		}
	}

	return 0, fmt.Errorf("address 0x%X not found in any memory region", addr)
}

// ReadTargetMemory implements MemoryAccessor.ReadTargetMemory.
// This mirrors the C++ naming and delegates to ReadMemory.
func (mrm *MultiRegionMemory) ReadTargetMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	return mrm.ReadMemory(addr, traceID, space, data)
}

// MemSpace returns the memory space(s) this accessor covers.
func (mrm *MultiRegionMemory) MemSpace() MemorySpace {
	return mrm.memSpace
}

// SetMemSpace sets the memory space(s) this accessor covers.
func (mrm *MultiRegionMemory) SetMemSpace(space MemorySpace) {
	mrm.memSpace = space
}
