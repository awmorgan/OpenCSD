package memacc

import (
	"math/bits"
	"opencsd/internal/ocsd"
)

// Mapper defines the interface for mapping and reading target memory.
type Mapper interface {
	// ReadTargetMemory reads bytes from the mapped memory accessors.
	ReadTargetMemory(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, numBytes *uint32, pBuffer []byte) ocsd.Err

	// InvalidateMemAccCache invalidates cache entries for a specific Trace ID.
	InvalidateMemAccCache(trcID uint8)

	// AddAccessor adds a new memory accessor to the mapper.
	AddAccessor(accessor Accessor, trcID uint8) ocsd.Err

	// RemoveAccessor removes a specific accessor.
	RemoveAccessor(accessor Accessor) ocsd.Err

	// RemoveAllAccessors clears all accessors.
	RemoveAllAccessors()

	// EnableCaching controls memory access caching.
	EnableCaching(enable bool) ocsd.Err
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

func (m *GlobalMapper) EnableCaching(enable bool) ocsd.Err {
	m.cache.EnableCaching(enable)
	return ocsd.OK
}

func (m *GlobalMapper) ReadTargetMemory(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, numBytes *uint32, pBuffer []byte) ocsd.Err {
	found := false

	// Try current accessor first
	if m.accCurr != nil && m.accCurr.AddrInRange(address) && m.accCurr.InMemSpace(memSpace) {
		found = true
	} else {
		// Optimization: if we are going to look for a better one, we should always do the prioritized search
		// even if m.accCurr matched, because a more specific one might have been added.
		// However, for performance, we usually try the current first.
		// Given the user request "prioritize specific over Any", let's ensure we always find the BEST match.
		if m.findAccessor(address, memSpace, trcID) {
			found = true
			if m.cache.Enabled() {
				m.cache.InvalidateByTraceID(trcID)
			}
		}
	}

	if !found {
		*numBytes = 0
		return ocsd.OK // Or ErrMemNacc? C++ returns OCSD_OK but readBytes is 0.
	}

	// Read from cache if enabled
	if m.cache.EnabledForSize(*numBytes) {
		readVal := *numBytes
		err := m.cache.ReadBytesFromCache(m.accCurr, address, memSpace, trcID, &readVal, pBuffer)
		if err == ocsd.OK {
			*numBytes = readVal
			return ocsd.OK
		}
		// Fallback to direct read if cache fails (though ReadBytesFromCache should have loaded it)
	}

	read := m.accCurr.ReadBytes(address, memSpace, trcID, *numBytes, pBuffer)
	if read > *numBytes {
		return ocsd.ErrMemAccBadLen
	}
	*numBytes = read
	return ocsd.OK
}

func (m *GlobalMapper) InvalidateMemAccCache(trcID uint8) {
	if m.cache.Enabled() {
		m.cache.InvalidateByTraceID(trcID)
	}
}

func (m *GlobalMapper) AddAccessor(accessor Accessor, trcID uint8) ocsd.Err {
	if !accessor.ValidateRange() {
		return ocsd.ErrMemAccRangeInvalid
	}

	// Check for overlaps with same or intersecting memory spaces
	for _, a := range m.accessors {
		if a.OverlapRange(accessor) && (uint32(a.GetMemSpace())&uint32(accessor.GetMemSpace()) != 0) {
			return ocsd.ErrMemAccOverlap
		}
	}

	m.accessors = append(m.accessors, accessor)
	return ocsd.OK
}

func (m *GlobalMapper) RemoveAccessor(accessor Accessor) ocsd.Err {
	for i, a := range m.accessors {
		if a == accessor {
			m.accessors = append(m.accessors[:i], m.accessors[i+1:]...)
			if m.accCurr == accessor {
				m.accCurr = nil
			}
			if m.cache.Enabled() {
				m.cache.InvalidateAll()
			}
			return ocsd.OK
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

func (m *GlobalMapper) findAccessor(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8) bool {
	var bestMatch Accessor
	bestMatchLen := 33 // number of bits set in memory space (0-32)

	for _, acc := range m.accessors {
		if acc.AddrInRange(address) && acc.InMemSpace(memSpace) {
			// Prioritize more specific match (fewer bits set in accessor's memory space)
			matchLen := bits.OnesCount32(uint32(acc.GetMemSpace()))
			// Or even better: if exact match, always take it.
			if acc.GetMemSpace() == memSpace {
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
