// Package memacc provides memory accessor registration and lookup for target-memory reads.
//
// Trace ID behavior in this package:
//   - Accessor registration: trace ID is ignored.
//   - Accessor lookup: trace ID is ignored; selection uses address and memory space only.
//   - Cache partitioning: trace ID is part of cache keys and cache invalidation.
//   - Callback dispatch: trace ID is forwarded to Accessor.ReadBytes, so callback-based
//     accessors may use it to select source data.
package memacc

import (
	"math/bits"
	"opencsd/internal/ocsd"
)

// Mapper defines the interface for mapping and reading target memory.
type Mapper interface {
	// Read reads up to reqBytes into buffer and returns bytes read with standard Go error.
	// Accessor selection is based on address and memSpace; trcID does not influence accessor lookup.
	// trcID is still passed to the selected accessor ReadBytes implementation.
	Read(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error)

	// ReadTargetMemory reads bytes from the mapped memory accessors.
	// Accessor selection is based on address and memSpace; trcID does not influence accessor lookup.
	// trcID is still passed to the selected accessor ReadBytes implementation.
	ReadTargetMemory(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, numBytes *uint32, buffer []byte) error

	// InvalidateMemAccCache invalidates cache entries for a specific Trace ID.
	// This affects cache partitioning only; it does not add/remove/register accessors.
	InvalidateMemAccCache(trcID uint8)

	// AddAccessor adds a new memory accessor to the mapper.
	// registrationTraceID is accepted for API compatibility but ignored.
	// Overlap checks and registration are based on address range and memory space only.
	AddAccessor(accessor Accessor, registrationTraceID uint8) error

	// RemoveAccessor removes a specific accessor.
	RemoveAccessor(accessor Accessor) error

	// RemoveAllAccessors clears all accessors.
	RemoveAllAccessors()

	// EnableCaching controls memory access caching.
	EnableCaching(enable bool) error
}

// GlobalMapper implements a global registry of memory accessors.
type GlobalMapper struct {
	accessors []Accessor
	accCurr   Accessor
	cache     *Cache
	enabled   bool
}

func NewGlobalMapper() *GlobalMapper {
	return &GlobalMapper{
		cache:   NewCache(),
		enabled: true,
	}
}

func (m *GlobalMapper) EnableCaching(enable bool) error {
	m.cache.EnableCaching(enable)
	return nil
}

// SetCacheSizes updates mapper cache page sizing limits.
func (m *GlobalMapper) SetCacheSizes(pageSize uint16, numPages int, errOnLimit bool) error {
	return m.cache.SetCacheSizes(pageSize, numPages, errOnLimit)
}

// Read is an idiomatic helper over ReadTargetMemory that returns bytes read and error.
func (m *GlobalMapper) Read(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error) {
	if reqBytes > uint32(len(buffer)) {
		reqBytes = uint32(len(buffer))
	}

	bytesRead := reqBytes
	err := m.ReadTargetMemory(address, trcID, memSpace, &bytesRead, buffer)
	if err != nil {
		return 0, err
	}
	return bytesRead, nil
}

func (m *GlobalMapper) ReadTargetMemory(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, numBytes *uint32, buffer []byte) error {
	prevAcc := m.accCurr
	found := m.findAccessor(address, memSpace, trcID)
	if found && m.cache.Enabled() && prevAcc != nil && prevAcc != m.accCurr {
		m.cache.InvalidateByTraceID(trcID)
	}

	if !found {
		*numBytes = 0
		return nil // Or ocsd.ErrMemNacc? C++ returns OCSD_OK but readBytes is 0.
	}

	// Read from cache if enabled
	if m.cache.EnabledForSize(*numBytes) {
		readVal, err := m.cache.Read(m.accCurr, address, memSpace, trcID, *numBytes, buffer)
		if err == nil {
			*numBytes = readVal
			return nil
		}
		// Fallback to direct read if cache fails (though ReadBytesFromCache should have loaded it)
	}

	read := m.accCurr.ReadBytes(address, memSpace, trcID, *numBytes, buffer)
	if read > *numBytes {
		return ocsd.ErrMemAccBadLen
	}
	*numBytes = read
	return nil
}

func (m *GlobalMapper) InvalidateMemAccCache(trcID uint8) {
	if m.cache.Enabled() {
		m.cache.InvalidateByTraceID(trcID)
	}
}

func (m *GlobalMapper) AddAccessor(accessor Accessor, _ uint8) error {
	if !accessor.ValidateRange() {
		return ocsd.ErrMemAccRangeInvalid
	}

	// Check for overlaps with same or intersecting memory spaces
	for _, a := range m.accessors {
		if a.OverlapRange(accessor) && (uint32(a.MemSpace())&uint32(accessor.MemSpace()) != 0) {
			return ocsd.ErrMemAccOverlap
		}
	}

	m.accessors = append(m.accessors, accessor)
	return nil
}

func (m *GlobalMapper) RemoveAccessor(accessor Accessor) error {
	for i, a := range m.accessors {
		if a == accessor {
			copy(m.accessors[i:], m.accessors[i+1:])
			m.accessors[len(m.accessors)-1] = nil
			m.accessors = m.accessors[:len(m.accessors)-1]
			if m.accCurr == accessor {
				m.accCurr = nil
			}
			if m.cache.Enabled() {
				m.cache.InvalidateAll()
			}
			return nil
		}
	}
	return ocsd.ErrInvalidParamVal
}

func (m *GlobalMapper) RemoveAllAccessors() {
	m.accessors = nil
	m.accCurr = nil
	if m.cache.Enabled() {
		m.cache.InvalidateAll()
	}
}

func (m *GlobalMapper) findAccessor(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, _ uint8) bool {
	var bestMatch Accessor
	bestMatchLen := 33 // number of bits set in memory space (0-32)

	for _, acc := range m.accessors {
		if acc.AddrInRange(address) && acc.InMemSpace(memSpace) {
			// Prioritize more specific match (fewer bits set in accessor's memory space)
			matchLen := bits.OnesCount32(uint32(acc.MemSpace()))
			// Or even better: if exact match, always take it.
			if acc.MemSpace() == memSpace {
				m.accCurr = acc
				return true
			}
			if matchLen < bestMatchLen {
				bestMatchLen = matchLen
				bestMatch = acc
			}
		}
	}

	if bestMatch != nil {
		m.accCurr = bestMatch
		return true
	}
	return false
}
