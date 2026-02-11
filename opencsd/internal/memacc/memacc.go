package memacc

import (
	"encoding/binary"
	"fmt"
)

// MemSpace represents the memory space bitmask.
type MemSpace uint32

const (
	MemSpaceEL1N MemSpace = 0x1
	MemSpaceEL2  MemSpace = 0x2
	MemSpaceEL3  MemSpace = 0x4
	MemSpaceEL1S MemSpace = 0x8
	MemSpaceEL2S MemSpace = 0x10
	MemSpaceEL1R MemSpace = 0x20
	MemSpaceEL2R MemSpace = 0x40
	MemSpaceRoot MemSpace = 0x80

	MemSpaceAny MemSpace = 0xFF
	MemSpaceN   MemSpace = MemSpaceEL1N | MemSpaceEL2 | MemSpaceEL3
	MemSpaceS   MemSpace = MemSpaceEL1S | MemSpaceEL2S | MemSpaceEL3
	MemSpaceR   MemSpace = MemSpaceEL1R | MemSpaceEL2R | MemSpaceRoot
)

func (m MemSpace) String() string {
	return fmt.Sprintf("MemSpace(0x%x)", uint32(m))
}

// Common errors
var (
	ErrMemAccOverlap = fmt.Errorf("memory accessor overlap")
)

// Accessor is the interface for memory access objects.
type Accessor interface {
	SetMemSpace(space MemSpace)
	// Getters required for Mapper overlap checks
	GetStartAddr() uint64
	GetEndAddr() uint64
	GetMemSpace() MemSpace
	// Read performs a read on the specific accessor
	Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error)
}

// BufferAccessor mimics TrcMemAccBufPtr.
// It provides access to a specific buffer in memory.
type BufferAccessor struct {
	addr      uint64
	data      []byte
	memSpace  MemSpace
	startAddr uint64
	endAddr   uint64
}

func (b *BufferAccessor) InitAccessor(addr uint64, data []byte) {
	b.addr = addr
	b.data = data
	b.startAddr = addr
	b.endAddr = addr + uint64(len(data)) - 1
}

func (b *BufferAccessor) SetMemSpace(space MemSpace) {
	b.memSpace = space
}

func (b *BufferAccessor) SetRange(start, end uint64) {
	b.startAddr = start
	b.endAddr = end
}

// Implement Accessor interface
func (b *BufferAccessor) GetStartAddr() uint64  { return b.startAddr }
func (b *BufferAccessor) GetEndAddr() uint64    { return b.endAddr }
func (b *BufferAccessor) GetMemSpace() MemSpace { return b.memSpace }

func (b *BufferAccessor) Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	if addr < b.startAddr || addr > b.endAddr {
		return nil, fmt.Errorf("address out of range")
	}

	offset := addr - b.startAddr
	// Check if read extends beyond buffer
	if offset+uint64(reqBytes) > uint64(len(b.data)) {
		return nil, fmt.Errorf("read overflow")
	}

	return b.data[offset : offset+uint64(reqBytes)], nil
}

// CallbackFn defines the signature for memory access callbacks.
type CallbackFn func(context interface{}, addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error)

// CBAccessor mimics TrcMemAccCB.
type CBAccessor struct {
	startAddr uint64
	endAddr   uint64
	memSpace  MemSpace
	cb        CallbackFn
	ctx       interface{}
}

func (c *CBAccessor) InitAccessor(addr uint64, endAddr uint64, space MemSpace) {
	c.startAddr = addr
	c.endAddr = endAddr
	c.memSpace = space
}

func (c *CBAccessor) SetCB(fn CallbackFn, ctx interface{}) {
	c.cb = fn
	c.ctx = ctx
}

func (c *CBAccessor) SetMemSpace(space MemSpace) {
	c.memSpace = space
}

// Implement Accessor interface
func (c *CBAccessor) GetStartAddr() uint64  { return c.startAddr }
func (c *CBAccessor) GetEndAddr() uint64    { return c.endAddr }
func (c *CBAccessor) GetMemSpace() MemSpace { return c.memSpace }

func (c *CBAccessor) Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	if c.cb != nil {
		return c.cb(c.ctx, addr, space, trcID, reqBytes)
	}
	return nil, fmt.Errorf("callback not set")
}

type cachePage struct {
	start    uint64
	validLen uint32
	trcID    uint8
	data     []byte
	useSeq   uint32
}

type memCache struct {
	enabled  bool
	pageSize uint32
	pages    []cachePage
	mruIdx   int
	seq      uint32
}

const (
	defaultCachePageSize = 2048
	defaultCachePages    = 16
)

func newMemCache() memCache {
	pages := make([]cachePage, defaultCachePages)
	for i := range pages {
		pages[i].data = make([]byte, defaultCachePageSize)
	}
	return memCache{
		enabled:  false,
		pageSize: defaultCachePageSize,
		pages:    pages,
		mruIdx:   0,
		seq:      1,
	}
}

func (c *memCache) enable(enable bool) {
	c.enabled = enable
	if !enable {
		c.invalidateAll()
	}
}

func (c *memCache) enabledForSize(reqBytes uint32) bool {
	return c.enabled && reqBytes <= c.pageSize
}

func (c *memCache) invalidateAll() {
	for i := range c.pages {
		c.pages[i].validLen = 0
		c.pages[i].useSeq = 0
	}
	c.mruIdx = 0
}

func (c *memCache) invalidateByTraceID(trcID uint8) {
	for i := range c.pages {
		if c.pages[i].validLen > 0 && c.pages[i].trcID == trcID {
			c.pages[i].validLen = 0
			c.pages[i].useSeq = 0
		}
	}
}

func (c *memCache) findPage(addr uint64, reqBytes uint32, trcID uint8) (int, bool) {
	end := addr + uint64(reqBytes)
	for i := range c.pages {
		p := &c.pages[i]
		if p.validLen == 0 || p.trcID != trcID {
			continue
		}
		if p.start <= addr && p.start+uint64(p.validLen) >= end {
			return i, true
		}
	}
	return -1, false
}

func (c *memCache) nextPageIndex() int {
	for i := range c.pages {
		if c.pages[i].validLen == 0 {
			return i
		}
	}
	c.mruIdx++
	if c.mruIdx >= len(c.pages) {
		c.mruIdx = 0
	}
	return c.mruIdx
}

func (c *memCache) readBytes(acc Accessor, addr uint64, memSpace MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	if !c.enabledForSize(reqBytes) {
		return acc.Read(addr, memSpace, trcID, reqBytes)
	}

	if idx, ok := c.findPage(addr, reqBytes, trcID); ok {
		p := &c.pages[idx]
		offset := addr - p.start
		p.useSeq = c.seq
		c.seq++
		return p.data[offset : offset+uint64(reqBytes)], nil
	}

	idx := c.nextPageIndex()
	data, err := acc.Read(addr, memSpace, trcID, c.pageSize)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("memory not accessible")
	}
	if len(data) > int(c.pageSize) {
		return nil, fmt.Errorf("cache read overflow")
	}

	p := &c.pages[idx]
	copy(p.data, data)
	p.start = addr
	p.validLen = uint32(len(data))
	p.trcID = trcID
	p.useSeq = c.seq
	c.seq++

	if addr+uint64(reqBytes) > p.start+uint64(p.validLen) {
		return nil, fmt.Errorf("insufficient data read")
	}
	offset := addr - p.start
	return p.data[offset : offset+uint64(reqBytes)], nil
}

// Mapper mimics TrcMemAccMapGlobalSpace.
type Mapper struct {
	accessors []Accessor
	cache     memCache
	accCurr   Accessor
}

func NewMapper() *Mapper {
	return &Mapper{
		accessors: make([]Accessor, 0),
		cache:     newMemCache(),
		accCurr:   nil,
	}
}

func (m *Mapper) AddAccessor(acc Accessor, csID uint8) error {
	newStart := acc.GetStartAddr()
	newEnd := acc.GetEndAddr()
	newSpace := acc.GetMemSpace()

	for _, existing := range m.accessors {
		exStart := existing.GetStartAddr()
		exEnd := existing.GetEndAddr()
		exSpace := existing.GetMemSpace()

		// Check for Overlap
		// 1. Check Address Range Overlap
		// Two ranges overlap if: start1 <= end2 && start2 <= end1
		rangeOverlap := (exStart <= newEnd) && (newStart <= exEnd)

		// 2. Check Memory Space Overlap
		spaceOverlap := (uint32(exSpace) & uint32(newSpace)) != 0

		if rangeOverlap && spaceOverlap {
			return ErrMemAccOverlap
		}
	}

	m.accessors = append(m.accessors, acc)
	return nil
}

func (m *Mapper) RemoveAllAccessors() {
	m.accessors = nil
	m.accCurr = nil
	m.InvalidateCache()
}

func (m *Mapper) readFromCurrent(addr uint64, space MemSpace) bool {
	if m.accCurr == nil {
		return false
	}
	if addr < m.accCurr.GetStartAddr() || addr > m.accCurr.GetEndAddr() {
		return false
	}
	return (uint32(m.accCurr.GetMemSpace()) & uint32(space)) != 0
}

func (m *Mapper) findAccessor(addr uint64, space MemSpace) bool {
	for _, acc := range m.accessors {
		if addr < acc.GetStartAddr() || addr > acc.GetEndAddr() {
			continue
		}
		if (uint32(acc.GetMemSpace()) & uint32(space)) == 0 {
			continue
		}
		m.accCurr = acc
		return true
	}
	return false
}

func (m *Mapper) ReadTargetMemory(addr uint64, trcID uint8, space MemSpace, reqBytes uint32) (uint32, error) {
	readFromCurr := m.readFromCurrent(addr, space)
	if !readFromCurr {
		if !m.findAccessor(addr, space) {
			return 0, fmt.Errorf("memory not accessible")
		}
		if m.cache.enabled {
			m.cache.invalidateByTraceID(trcID)
		}
	}

	data, err := m.cache.readBytes(m.accCurr, addr, space, trcID, reqBytes)
	if err != nil {
		return 0, err
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("insufficient data read")
	}

	return binary.LittleEndian.Uint32(data), nil
}

// EnableCaching turns caching on or off.
func (m *Mapper) EnableCaching(enable bool) {
	m.cache.enable(enable)
}

func (m *Mapper) InvalidateCache() {
	m.cache.invalidateAll()
}
