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
	"errors"
	"math/bits"
	"opencsd/internal/ocsd"
)

// Sentinel errors for memory access lookups.
var (
	// ErrNoAccessor indicates no memory accessor can service the request.
	ErrNoAccessor = errors.New("no memory accessor")

	// ErrAddressNotMapped indicates the address is not mapped in any accessor.
	ErrAddressNotMapped = errors.New("address not mapped")
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
}

func NewGlobalMapper() *GlobalMapper {
	return &GlobalMapper{cache: NewCache()}
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
	bytesRead := min(reqBytes, uint32(len(buffer)))
	if err := m.ReadTargetMemory(address, trcID, memSpace, &bytesRead, buffer); err != nil {
		return 0, err
	}
	return bytesRead, nil
}

func (m *GlobalMapper) ReadTargetMemory(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, numBytes *uint32, buffer []byte) error {
	*numBytes = min(*numBytes, uint32(len(buffer)))

	prevAcc := m.accCurr
	acc, ok := m.findAccessor(address, memSpace)
	if !ok {
		*numBytes = 0
		return ErrNoAccessor
	}

	m.accCurr = acc
	if prevAcc != nil && prevAcc != acc {
		m.invalidateCacheForTrace(trcID)
	}

	if read, ok := m.readFromCache(address, trcID, memSpace, *numBytes, buffer); ok {
		*numBytes = read
		return nil
	}

	read := acc.ReadBytes(address, memSpace, trcID, *numBytes, buffer)
	if read > *numBytes {
		return ocsd.ErrMemAccBadLen
	}
	*numBytes = read
	return nil
}

func (m *GlobalMapper) readFromCache(address ocsd.VAddr, trcID uint8, memSpace ocsd.MemSpaceAcc, numBytes uint32, buffer []byte) (uint32, bool) {
	if !m.cache.EnabledForSize(numBytes) {
		return 0, false
	}

	read, err := m.cache.Read(m.accCurr, address, memSpace, trcID, numBytes, buffer)
	return read, err == nil
}

func (m *GlobalMapper) invalidateCacheForTrace(trcID uint8) {
	if m.cache.Enabled() {
		m.cache.InvalidateByTraceID(trcID)
	}
}

func (m *GlobalMapper) InvalidateMemAccCache(trcID uint8) {
	m.invalidateCacheForTrace(trcID)
}

func (m *GlobalMapper) AddAccessor(accessor Accessor, _ uint8) error {
	if accessor == nil {
		return ocsd.ErrInvalidParamVal
	}
	if !accessor.ValidateRange() {
		return ocsd.ErrMemAccRangeInvalid
	}
	if m.overlapsExisting(accessor) {
		return ocsd.ErrMemAccOverlap
	}

	m.accessors = append(m.accessors, accessor)
	return nil
}

func (m *GlobalMapper) overlapsExisting(accessor Accessor) bool {
	for _, existing := range m.accessors {
		if accessorsOverlapInMemSpace(existing, accessor) {
			return true
		}
	}
	return false
}

func accessorsOverlapInMemSpace(a, b Accessor) bool {
	return a.OverlapRange(b) && a.MemSpace()&b.MemSpace() != 0
}

func (m *GlobalMapper) RemoveAccessor(accessor Accessor) error {
	for i, acc := range m.accessors {
		if acc == accessor {
			m.removeAccessorAt(i)
			return nil
		}
	}
	return ocsd.ErrInvalidParamVal
}

func (m *GlobalMapper) removeAccessorAt(i int) {
	removed := m.accessors[i]
	copy(m.accessors[i:], m.accessors[i+1:])
	m.accessors[len(m.accessors)-1] = nil
	m.accessors = m.accessors[:len(m.accessors)-1]

	if m.accCurr == removed {
		m.accCurr = nil
	}
	if m.cache.Enabled() {
		m.cache.InvalidateAll()
	}
}

func (m *GlobalMapper) RemoveAllAccessors() {
	clear(m.accessors)
	m.accessors = nil
	m.accCurr = nil
	if m.cache.Enabled() {
		m.cache.InvalidateAll()
	}
}

func (m *GlobalMapper) findAccessor(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc) (Accessor, bool) {
	var best Accessor
	bestScore := maxMemSpaceSpecificity + 1

	for _, acc := range m.accessors {
		if !acc.AddrInRange(address) || !acc.InMemSpace(memSpace) {
			continue
		}
		if acc.MemSpace() == memSpace {
			return acc, true
		}
		if score := memSpaceSpecificity(acc.MemSpace()); score < bestScore {
			best = acc
			bestScore = score
		}
	}
	return best, best != nil
}

const maxMemSpaceSpecificity = 32

func memSpaceSpecificity(memSpace ocsd.MemSpaceAcc) int {
	return bits.OnesCount32(uint32(memSpace))
}
