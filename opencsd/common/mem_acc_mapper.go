package common

import (
	"fmt"
)

// MemoryAccessorMapper manages a collection of memory accessors with
// overlap detection and memory space-aware accessor selection.
// This mirrors the C++ TrcMemAccMapGlobalSpace class.
type MemoryAccessorMapper struct {
	accessors []*AccessorEntry
}

// AccessorEntry wraps a MemoryAccessor with its address range and metadata.
type AccessorEntry struct {
	Accessor  MemoryAccessor
	StartAddr uint64
	EndAddr   uint64 // Exclusive (address one past the last valid byte)
	Space     MemorySpace
	TraceID   uint8
}

// NewMemoryAccessorMapper creates a new mapper for managing memory accessors.
func NewMemoryAccessorMapper() *MemoryAccessorMapper {
	return &MemoryAccessorMapper{
		accessors: make([]*AccessorEntry, 0),
	}
}

// AddAccessor adds a memory accessor to the map, checking for overlaps.
// Returns an error if the accessor overlaps with an existing accessor in the same memory space.
func (m *MemoryAccessorMapper) AddAccessor(accessor MemoryAccessor, startAddr, endAddr uint64, traceID uint8) error {
	if startAddr >= endAddr {
		return fmt.Errorf("invalid range: start (0x%X) >= end (0x%X)", startAddr, endAddr)
	}

	space := accessor.MemSpace()

	// Check for overlaps with existing accessors
	for _, existing := range m.accessors {
		if m.overlaps(startAddr, endAddr, existing.StartAddr, existing.EndAddr) {
			// Overlap detected - check if memory spaces also conflict
			if m.spacesConflict(space, existing.Space) {
				return fmt.Errorf("overlap detected: [0x%X-0x%X) (%s) conflicts with existing [0x%X-0x%X) (%s)",
					startAddr, endAddr, space.String(),
					existing.StartAddr, existing.EndAddr, existing.Space.String())
			}
		}
	}

	// No conflict - add the accessor
	entry := &AccessorEntry{
		Accessor:  accessor,
		StartAddr: startAddr,
		EndAddr:   endAddr,
		Space:     space,
		TraceID:   traceID,
	}
	m.accessors = append(m.accessors, entry)
	return nil
}

// RemoveAccessor removes an accessor from the map.
func (m *MemoryAccessorMapper) RemoveAccessor(accessor MemoryAccessor) error {
	for i, entry := range m.accessors {
		if entry.Accessor == accessor {
			m.accessors = append(m.accessors[:i], m.accessors[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("accessor not found")
}

// ClearAccessors removes all accessors from the map.
func (m *MemoryAccessorMapper) ClearAccessors() {
	m.accessors = make([]*AccessorEntry, 0)
}

// FindAccessor searches for an accessor that covers the given address and memory space.
// Returns the accessor and its entry, or nil if not found.
// Prioritizes exact trace ID match when available.
func (m *MemoryAccessorMapper) FindAccessor(addr uint64, space MemorySpace, traceID uint8) (MemoryAccessor, *AccessorEntry) {
	// First pass: look for exact trace ID match
	for _, entry := range m.accessors {
		if addr >= entry.StartAddr && addr < entry.EndAddr &&
			entry.Space.InMemSpace(space) &&
			entry.TraceID == traceID {
			return entry.Accessor, entry
		}
	}

	// Second pass: look for any match (trace ID 0 is often the default)
	for _, entry := range m.accessors {
		if addr >= entry.StartAddr && addr < entry.EndAddr &&
			entry.Space.InMemSpace(space) {
			return entry.Accessor, entry
		}
	}
	return nil, nil
}

// ReadMemory reads bytes from the appropriate accessor for the given address and space.
func (m *MemoryAccessorMapper) ReadMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	accessor, _ := m.FindAccessor(addr, space, traceID)
	if accessor == nil {
		return 0, fmt.Errorf("no accessor found for address 0x%X in space %s", addr, space.String())
	}
	return accessor.ReadMemory(addr, traceID, space, data)
}

// ReadTargetMemory reads bytes from the appropriate accessor for the given address and space.
func (m *MemoryAccessorMapper) ReadTargetMemory(addr uint64, traceID uint8, space MemorySpace, data []byte) (int, error) {
	accessor, _ := m.FindAccessor(addr, space, traceID)
	if accessor == nil {
		return 0, fmt.Errorf("no accessor found for address 0x%X in space %s", addr, space.String())
	}
	return accessor.ReadTargetMemory(addr, traceID, space, data)
}

// GetAccessors returns all accessor entries in the map.
func (m *MemoryAccessorMapper) GetAccessors() []*AccessorEntry {
	return m.accessors
}

// overlaps checks if two address ranges overlap.
// Range 1: [a1, b1), Range 2: [a2, b2)
func (m *MemoryAccessorMapper) overlaps(a1, b1, a2, b2 uint64) bool {
	return a1 < b2 && a2 < b1
}

// spacesConflict determines if two memory spaces conflict.
// Spaces conflict if they have overlapping bits AND at least one is specific (not a general space).
func (m *MemoryAccessorMapper) spacesConflict(space1, space2 MemorySpace) bool {
	// Spaces conflict if they overlap
	if (space1 & space2) == 0 {
		return false // No overlap
	}

	// If both are general spaces or both are the same, they conflict
	if space1 == space2 {
		return true
	}

	// Check if one space is a "general" space that subsumes the other
	// General spaces: ANY, N, S, R
	// If one accessor is ANY, allow overlap (ANY means it can be accessed from any context)
	// But if both are non-ANY and they overlap, that's a conflict

	// Special case: ANY space can coexist with anything
	if space1 == MemSpaceANY || space2 == MemSpaceANY {
		return false
	}

	// For specific spaces that overlap, it's a conflict
	// Example: EL1N and EL1N would conflict (same specific space)
	// But EL1N and EL1S would NOT conflict (different specific spaces)
	// And EL1N and N would conflict because N includes EL1N

	// If the spaces share specific bits, they conflict
	// unless one is fully contained in a "different" hierarchy
	return true
}
