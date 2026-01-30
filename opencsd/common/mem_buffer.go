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
}

// NewMemoryBuffer creates a new memory buffer for the given address range.
func NewMemoryBuffer(baseAddr uint64, data []byte) *MemoryBuffer {
	return &MemoryBuffer{
		BaseAddr: baseAddr,
		Data:     data,
	}
}

// ReadMemory implements MemoryAccessor.ReadMemory.
// Reads bytes from the memory buffer at the specified address.
func (mb *MemoryBuffer) ReadMemory(addr uint64, data []byte) (int, error) {
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

// Contains checks if the given address falls within this buffer's range.
func (mb *MemoryBuffer) Contains(addr uint64) bool {
	return addr >= mb.BaseAddr && addr < mb.BaseAddr+uint64(len(mb.Data))
}

// EndAddr returns the address immediately after the last byte in this buffer.
func (mb *MemoryBuffer) EndAddr() uint64 {
	return mb.BaseAddr + uint64(len(mb.Data))
}

// MultiRegionMemory implements MemoryAccessor for multiple non-overlapping memory regions.
// This allows modeling a full system memory map with multiple .bin files (e.g., VECTORS, RAM, ROM).
type MultiRegionMemory struct {
	Regions []*MemoryBuffer
}

// NewMultiRegionMemory creates a memory accessor that spans multiple regions.
func NewMultiRegionMemory() *MultiRegionMemory {
	return &MultiRegionMemory{
		Regions: make([]*MemoryBuffer, 0),
	}
}

// AddRegion adds a memory region to this multi-region accessor.
// Regions should be added in ascending address order for optimal performance.
func (mrm *MultiRegionMemory) AddRegion(region *MemoryBuffer) {
	mrm.Regions = append(mrm.Regions, region)
}

// ReadMemory implements MemoryAccessor.ReadMemory.
// Searches all regions for the requested address and reads from the matching region.
func (mrm *MultiRegionMemory) ReadMemory(addr uint64, data []byte) (int, error) {
	// Find the region containing this address
	for _, region := range mrm.Regions {
		if region.Contains(addr) {
			return region.ReadMemory(addr, data)
		}
	}

	return 0, fmt.Errorf("address 0x%X not found in any memory region", addr)
}
