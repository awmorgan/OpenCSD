package memacc

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
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
	if m == MemSpaceS {
		return "Any S"
	}
	if m == MemSpaceN {
		return "Any NS"
	}

	var s string
	if m&MemSpaceEL1N != 0 {
		s += "EL1N,"
	}
	if m&MemSpaceEL2 != 0 {
		s += "EL2,"
	}
	if m&MemSpaceEL3 != 0 {
		s += "EL3,"
	}
	if m&MemSpaceEL1S != 0 {
		s += "EL1S,"
	}
	if m&MemSpaceEL2S != 0 {
		s += "EL2S,"
	}
	if m&MemSpaceEL1R != 0 {
		s += "EL1R,"
	}
	if m&MemSpaceEL2R != 0 {
		s += "EL2R,"
	}
	if m&MemSpaceRoot != 0 {
		s += "Root,"
	}
	if s == "" {
		return "None"
	}
	return s[:len(s)-1] // Remove trailing comma
}

// Common errors
var (
	ErrMemAccOverlap  = fmt.Errorf("memory accessor overlap")
	ErrOutOfRange     = fmt.Errorf("address out of range")
	ErrAccessInvalid  = fmt.Errorf("memory access invalid")
	ErrNotInitialized = fmt.Errorf("accessor not initialized")
	ErrFileAccess     = fmt.Errorf("file access error")
)

// Accessor is the interface for memory access objects.
type Accessor interface {
	SetMemSpace(space MemSpace)
	StartAddr() uint64
	EndAddr() uint64
	MemSpace() MemSpace
	Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error)
	String() string
}

// BaseAccessor provides common fields for accessors.
type BaseAccessor struct {
	startAddr uint64
	endAddr   uint64
	memSpace  MemSpace
}

func (b *BaseAccessor) StartAddr() uint64          { return b.startAddr }
func (b *BaseAccessor) EndAddr() uint64            { return b.endAddr }
func (b *BaseAccessor) MemSpace() MemSpace         { return b.memSpace }
func (b *BaseAccessor) SetMemSpace(space MemSpace) { b.memSpace = space }
func (b *BaseAccessor) InRange(addr uint64) bool {
	return addr >= b.startAddr && addr <= b.endAddr
}
func (b *BaseAccessor) BytesInRange(addr uint64, reqBytes uint32) uint32 {
	if !b.InRange(addr) {
		return 0
	}
	available := b.endAddr - addr + 1
	if uint64(reqBytes) > available {
		return uint32(available)
	}
	return reqBytes
}

// -----------------------------------------------------------------------------
// Buffer Accessor
// -----------------------------------------------------------------------------

type BufferAccessor struct {
	BaseAccessor
	data []byte
}

func NewBufferAccessor(addr uint64, data []byte, space MemSpace) *BufferAccessor {
	return &BufferAccessor{
		BaseAccessor: BaseAccessor{
			startAddr: addr,
			endAddr:   addr + uint64(len(data)) - 1,
			memSpace:  space,
		},
		data: data,
	}
}

func (b *BufferAccessor) Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	if !b.InRange(addr) {
		return nil, nil
	}
	count := b.BytesInRange(addr, reqBytes)
	if count == 0 {
		return nil, nil
	}
	offset := addr - b.startAddr
	return b.data[offset : offset+uint64(count)], nil
}

func (b *BufferAccessor) String() string {
	return fmt.Sprintf("BuffAcc; Range::0x%x:0x%x; Space::%s", b.startAddr, b.endAddr, b.memSpace)
}

// -----------------------------------------------------------------------------
// Callback Accessor
// -----------------------------------------------------------------------------

type CallbackFn func(context interface{}, addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error)

type CBAccessor struct {
	BaseAccessor
	cb  CallbackFn
	ctx interface{}
}

func NewCBAccessor(startAddr, endAddr uint64, space MemSpace) *CBAccessor {
	return &CBAccessor{
		BaseAccessor: BaseAccessor{
			startAddr: startAddr,
			endAddr:   endAddr,
			memSpace:  space,
		},
	}
}

func (c *CBAccessor) SetCB(fn CallbackFn, ctx interface{}) {
	c.cb = fn
	c.ctx = ctx
}

func (c *CBAccessor) Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	if c.cb != nil {
		return c.cb(c.ctx, addr, space, trcID, reqBytes)
	}
	return nil, fmt.Errorf("callback not set")
}

func (c *CBAccessor) String() string {
	return fmt.Sprintf("CBAcc; Range::0x%x:0x%x; Space::%s", c.startAddr, c.endAddr, c.memSpace)
}

// -----------------------------------------------------------------------------
// File Accessor
// -----------------------------------------------------------------------------

type FileRegion struct {
	BaseAccessor
	fileOffset int64
}

type FileAccessor struct {
	BaseAccessor
	filePath   string
	file       *os.File
	fileSize   int64
	regions    []FileRegion
	hasRegions bool
	mu         sync.Mutex
}

// NewFileAccessor creates a new file accessor with a specific memory space.
func NewFileAccessor(path string, startAddr uint64, offset int64, size int64, space MemSpace) (*FileAccessor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFileAccess, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	fileSize := info.Size()

	fa := &FileAccessor{
		filePath: path,
		file:     f,
		fileSize: fileSize,
	}
	fa.memSpace = space

	if offset == 0 && size == 0 {
		fa.AddOffsetRange(startAddr, uint64(fileSize), 0)
	} else {
		if offset+size > fileSize {
			f.Close()
			return nil, fmt.Errorf("range exceeds file size")
		}
		fa.AddOffsetRange(startAddr, uint64(size), offset)
	}

	return fa, nil
}

func (f *FileAccessor) AddOffsetRange(startAddr, size uint64, offset int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if size == 0 {
		return nil
	}

	endAddr := startAddr + size - 1

	if offset == 0 && len(f.regions) == 0 {
		f.startAddr = startAddr
		f.endAddr = endAddr
		return nil
	}

	region := FileRegion{
		BaseAccessor: BaseAccessor{
			startAddr: startAddr,
			endAddr:   endAddr,
			memSpace:  f.memSpace, // Inherit space from parent
		},
		fileOffset: offset,
	}

	f.regions = append(f.regions, region)
	f.hasRegions = true

	sort.Slice(f.regions, func(i, j int) bool {
		return f.regions[i].startAddr < f.regions[j].startAddr
	})

	// Adjust base range
	if f.startAddr == 0 && f.endAddr == 0 {
		f.startAddr = startAddr
		f.endAddr = endAddr
	} else {
		if startAddr < f.startAddr {
			f.startAddr = startAddr
		}
		if endAddr > f.endAddr {
			f.endAddr = endAddr
		}
	}

	return nil
}

func (f *FileAccessor) Read(addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var readOffset int64 = -1
	var available uint32 = 0

	if f.BaseAccessor.InRange(addr) {
		available = f.BaseAccessor.BytesInRange(addr, reqBytes)
		readOffset = int64(addr - f.startAddr)
	}

	if f.hasRegions {
		for _, reg := range f.regions {
			if reg.InRange(addr) {
				available = reg.BytesInRange(addr, reqBytes)
				readOffset = int64(addr-reg.startAddr) + reg.fileOffset
				break
			}
		}
	}

	if readOffset == -1 || available == 0 {
		return nil, nil
	}

	data := make([]byte, available)
	_, err := f.file.ReadAt(data, readOffset)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return data, nil
}

func (f *FileAccessor) Close() error {
	return f.file.Close()
}

func (f *FileAccessor) String() string {
	return fmt.Sprintf("FileAcc; Range::0x%x:%x; Mem Space::%s\nFilename=%s", f.startAddr, f.endAddr, f.memSpace, f.filePath)
}

// -----------------------------------------------------------------------------
// Cache
// -----------------------------------------------------------------------------

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
		c.pages[i].trcID = 0
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
		// Check if block is entirely within the page
		if p.start <= addr && p.start+uint64(p.validLen) >= end {
			return i, true
		}
	}
	return -1, false
}

// nextPageIndex implements the LRU-like sequence logic from C++
func (c *memCache) nextPageIndex() int {
	// First pass: look for empty page
	for i := range c.pages {
		if c.pages[i].useSeq == 0 {
			return i
		}
	}

	// Second pass: find oldest sequence
	oldestIdx := c.mruIdx
	oldestSeq := c.pages[c.mruIdx].useSeq

	// Check all pages to find minimum sequence
	for i := range c.pages {
		if c.pages[i].useSeq < oldestSeq {
			oldestSeq = c.pages[i].useSeq
			oldestIdx = i
		}
	}
	return oldestIdx
}

func (c *memCache) readBytes(acc Accessor, addr uint64, memSpace MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	if !c.enabledForSize(reqBytes) {
		return acc.Read(addr, memSpace, trcID, reqBytes)
	}

	// Check Cache Hit
	if idx, ok := c.findPage(addr, reqBytes, trcID); ok {
		p := &c.pages[idx]
		offset := addr - p.start
		p.useSeq = c.seq
		c.seq++
		return p.data[offset : offset+uint64(reqBytes)], nil
	}

	// Cache Miss - Load new page
	idx := c.nextPageIndex()

	// Read a full page from underlying accessor
	data, err := acc.Read(addr, memSpace, trcID, c.pageSize)
	// C++ handles "bad length" checks here. In Go, we trust the slice len.
	if err != nil {
		// Only fail if it's a hard error. If it's just partial data, we use what we got.
		return nil, err
	}

	bytesRead := uint32(len(data))
	if bytesRead == 0 {
		return nil, nil // No data
	}

	p := &c.pages[idx]
	// Reset page info
	p.validLen = 0

	// Copy data into cache page
	copy(p.data, data)
	p.start = addr
	p.validLen = bytesRead
	p.trcID = trcID
	p.useSeq = c.seq
	c.seq++

	// Check if we actually got enough to satisfy the specific request
	if addr+uint64(reqBytes) > p.start+uint64(p.validLen) {
		// We loaded the page, but the specific bytes requested fell off the end of what was actually returned.
		// (e.g. End of memory region). Return available, or error?
		// C++ returns what is available.
		available := p.start + uint64(p.validLen) - addr
		return p.data[0:available], nil
	}

	offset := addr - p.start
	return p.data[offset : offset+uint64(reqBytes)], nil
}

// -----------------------------------------------------------------------------
// Mapper
// -----------------------------------------------------------------------------

// Mapper mimics TrcMemAccMapper.
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
	newStart := acc.StartAddr()
	newEnd := acc.EndAddr()
	newSpace := acc.MemSpace()

	for _, existing := range m.accessors {
		exStart := existing.StartAddr()
		exEnd := existing.EndAddr()
		exSpace := existing.MemSpace()

		// Check Address Range Overlap: start1 <= end2 && start2 <= end1
		rangeOverlap := (exStart <= newEnd) && (newStart <= exEnd)

		// Check Memory Space Overlap
		spaceOverlap := (uint32(exSpace) & uint32(newSpace)) != 0

		if rangeOverlap && spaceOverlap {
			return ErrMemAccOverlap
		}
	}

	m.accessors = append(m.accessors, acc)
	return nil
}

func (m *Mapper) RemoveAllAccessors() {
	// Close file accessors if any
	for _, acc := range m.accessors {
		if fa, ok := acc.(*FileAccessor); ok {
			fa.Close()
		}
	}
	m.accessors = nil
	m.accCurr = nil
	m.InvalidateCache()
}

func (m *Mapper) findAccessor(addr uint64, space MemSpace) bool {
	// Optimization: Check current first (C++ logic)
	if m.accCurr != nil {
		if m.accCurr.StartAddr() <= addr && m.accCurr.EndAddr() >= addr {
			if (uint32(m.accCurr.MemSpace()) & uint32(space)) != 0 {
				return true
			}
		}
	}

	for _, acc := range m.accessors {
		if addr < acc.StartAddr() || addr > acc.EndAddr() {
			continue
		}
		if (uint32(acc.MemSpace()) & uint32(space)) == 0 {
			continue
		}
		m.accCurr = acc
		return true
	}
	return false
}

// ReadTargetMemory reads a 32-bit word (4 bytes) from the target memory.
// Returns a uint32 in Little Endian.
func (m *Mapper) ReadTargetMemory(addr uint64, trcID uint8, space MemSpace, reqBytes uint32) (uint32, error) {
	// Locate Accessor
	if !m.findAccessor(addr, space) {
		return 0, fmt.Errorf("%w: 0x%x (%s)", ErrAccessInvalid, addr, space)
	}

	// Invalidate cache if trace ID changed (handled in C++ by invalidating on context switch,
	// but here we just ensure consistency)
	// Note: The C++ code only invalidates if the *accessor* changes or explicitly requested.
	// We will follow the C++ readBytes logic which checks cache hits by TraceID.

	// Perform Read (via Cache)
	data, err := m.cache.readBytes(m.accCurr, addr, space, trcID, reqBytes)
	if err != nil {
		return 0, err
	}

	// Convert to uint32
	if len(data) < 4 {
		// Not enough data read (e.g. near end of memory)
		// We can return what we have padded, or error.
		// Typically instruction decode requires full words.
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

func (m *Mapper) InvalidateCacheID(trcID uint8) {
	m.cache.invalidateByTraceID(trcID)
}

func (m *Mapper) GetAccessors() []Accessor {
	return m.accessors
}
