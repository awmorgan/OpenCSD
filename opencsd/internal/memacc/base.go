package memacc

import (
	"fmt"
	"opencsd/internal/ocsd"
	"strings"
)

// Type describes the storage type of the underlying memory accessor.
type Type int

const (
	TypeUnknown Type = iota
	TypeFile         // Binary data file accessor
	TypeBufPtr       // Memory buffer accessor
	TypeCBIf         // Callback interface accessor - use for live memory access
)

func (t Type) String() string {
	switch t {
	case TypeFile:
		return "FileAcc"
	case TypeBufPtr:
		return "BuffAcc"
	case TypeCBIf:
		return "CB  Acc"
	default:
		return "UnknAcc"
	}
}

// Accessor defines the interface for a memory range access.
type Accessor interface {
	// ReadBytes reads bytes from via the accessor from the memory range.
	ReadBytes(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

	// AddrInRange tests if an address is in the inclusive range for this accessor.
	AddrInRange(address ocsd.VAddr) bool

	// AddrStartOfRange tests if an address is the start of range for this accessor.
	AddrStartOfRange(address ocsd.VAddr) bool

	// BytesInRange tests number of bytes available from the start address, up to the number of requested bytes.
	BytesInRange(address ocsd.VAddr, reqBytes uint32) uint32

	// OverlapRange tests if supplied range accessor overlaps this range.
	OverlapRange(testAcc Accessor) bool

	// ValidateRange validates the address range - ensure addresses aligned, different, st < en etc.
	ValidateRange() bool

	// Type returns the storage type of this accessor.
	Type() Type

	// SetMemSpace sets the memory space for this accessor.
	SetMemSpace(memSpace ocsd.MemSpaceAcc)

	// MemSpace returns the memory space for this accessor.
	MemSpace() ocsd.MemSpaceAcc

	// InMemSpace tests if the accessor supports the given memory space.
	InMemSpace(memSpace ocsd.MemSpaceAcc) bool

	// Range returns the start and end addresses of this accessor.
	Range() (ocsd.VAddr, ocsd.VAddr)
}

// BaseAccessor implements the common logic for memory accessors.
type BaseAccessor struct {
	StartAddress ocsd.VAddr
	EndAddress   ocsd.VAddr
	AccType      Type
	MemSpaceAcc  ocsd.MemSpaceAcc
}

func (b *BaseAccessor) AddrInRange(address ocsd.VAddr) bool {
	return address >= b.StartAddress && address <= b.EndAddress
}

func (b *BaseAccessor) AddrStartOfRange(address ocsd.VAddr) bool {
	return address == b.StartAddress
}

func (b *BaseAccessor) BytesInRange(address ocsd.VAddr, reqBytes uint32) uint32 {
	if !b.AddrInRange(address) {
		return 0
	}

	avail := uint64(b.EndAddress) - uint64(address) + 1
	if avail > uint64(reqBytes) {
		return reqBytes
	}
	return uint32(avail)
}

func (b *BaseAccessor) OverlapRange(testAcc Accessor) bool {
	st, en := testAcc.Range()
	return st <= b.EndAddress && en >= b.StartAddress
}

func (b *BaseAccessor) ValidateRange() bool {
	return b.StartAddress < b.EndAddress &&
		b.StartAddress&0x1 == 0 &&
		(b.EndAddress+1)&0x1 == 0
}

func (b *BaseAccessor) Type() Type {
	return b.AccType
}

func (b *BaseAccessor) SetMemSpace(memSpace ocsd.MemSpaceAcc) {
	b.MemSpaceAcc = memSpace
}

func (b *BaseAccessor) MemSpace() ocsd.MemSpaceAcc {
	return b.MemSpaceAcc
}

func (b *BaseAccessor) InMemSpace(memSpace ocsd.MemSpaceAcc) bool {
	return b.MemSpaceAcc&memSpace != 0
}

func (b *BaseAccessor) Range() (ocsd.VAddr, ocsd.VAddr) {
	return b.StartAddress, b.EndAddress
}

func (b *BaseAccessor) String() string {
	return fmt.Sprintf("%s; Range::0x%x:%x; Mem Space::%s", b.AccType, b.StartAddress, b.EndAddress, MemSpaceString(b.MemSpaceAcc))
}

// Memory Access Cache

const (
	DefaultPageSize = 2048
	DefaultNumPages = 16
	MaxPageSize     = 16384
	MaxPages        = 256
	MinPageSize     = 64
	MinPages        = 4
)

type CacheBlock struct {
	StartAddr   ocsd.VAddr
	ValidLen    uint32
	Data        []byte
	TrcID       uint8
	UseSequence uint32
}

type Cache struct {
	blocks   []CacheBlock
	pageSize uint16
	numPages int
	sequence uint32
	enabled  bool
	mruIdx   int
}

func NewCache() *Cache {
	return &Cache{
		pageSize: DefaultPageSize,
		numPages: DefaultNumPages,
		sequence: 1,
	}
}

func (c *Cache) EnableCaching(enable bool) {
	c.enabled = enable
	if enable && c.blocks == nil {
		c.createCaches()
	}
}

func (c *Cache) Enabled() bool {
	return c.enabled
}

func (c *Cache) EnabledForSize(reqSize uint32) bool {
	return c.enabled && reqSize <= uint32(c.pageSize)
}

func (c *Cache) SetCacheSizes(pageSize uint16, numPages int, errOnLimit bool) error {
	if cacheLimitsExceeded(pageSize, numPages) {
		if errOnLimit {
			return ocsd.ErrInvalidParamVal
		}
		pageSize = clampPageSize(pageSize)
		numPages = clampNumPages(numPages)
	}

	c.pageSize = pageSize
	c.numPages = numPages
	if c.enabled {
		c.createCaches()
	}
	return nil
}

func cacheLimitsExceeded(pageSize uint16, numPages int) bool {
	return pageSize < MinPageSize || pageSize > MaxPageSize || numPages < MinPages || numPages > MaxPages
}

func clampPageSize(pageSize uint16) uint16 {
	return min(max(pageSize, MinPageSize), MaxPageSize)
}

func clampNumPages(numPages int) int {
	return min(max(numPages, MinPages), MaxPages)
}

func (c *Cache) createCaches() {
	c.blocks = make([]CacheBlock, c.numPages)
	for i := range c.blocks {
		c.blocks[i].Data = make([]byte, c.pageSize)
		c.clearPage(&c.blocks[i])
	}
}

func (c *Cache) InvalidateAll() {
	c.invalidate(func(CacheBlock) bool { return true })
}

func (c *Cache) InvalidateByTraceID(trcID uint8) {
	c.invalidate(func(block CacheBlock) bool { return block.TrcID == trcID })
}

func (c *Cache) invalidate(match func(CacheBlock) bool) {
	for i := range c.blocks {
		if match(c.blocks[i]) {
			c.clearPage(&c.blocks[i])
		}
	}
}

func (c *Cache) clearPage(block *CacheBlock) {
	block.UseSequence = 0
	block.StartAddr = 0
	block.ValidLen = 0
	block.TrcID = ocsd.BadCSSrcID
}

func (c *Cache) incSequence() {
	c.blocks[c.mruIdx].UseSequence = c.sequence
	c.sequence++
	if c.sequence != 0 {
		return
	}

	c.sequence = 1
	for i := range c.blocks {
		if c.blocks[i].UseSequence != 0 {
			c.blocks[i].UseSequence = c.sequence
			c.sequence++
		}
	}
	c.blocks[c.mruIdx].UseSequence = c.sequence
	c.sequence++
}

// Read reads up to reqBytes into buffer from cache-backed accessor state.
func (c *Cache) Read(acc Accessor, address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) (uint32, error) {
	reqBytes = min(reqBytes, uint32(len(buffer)))
	if !c.enabled {
		return 0, ocsd.ErrFail
	}

	if c.blockInCache(address, reqBytes, trcID) {
		read := c.copyFromBlock(c.mruIdx, address, reqBytes, buffer)
		c.incSequence()
		return read, nil
	}

	newIdx := c.findNewPage()
	c.mruIdx = newIdx
	if err := c.fillPage(newIdx, acc, address, memSpace, trcID); err != nil {
		return 0, err
	}

	if !c.blockInPage(newIdx, address, reqBytes, trcID) {
		return 0, nil
	}
	return c.copyFromBlock(newIdx, address, reqBytes, buffer), nil
}

func (c *Cache) fillPage(idx int, acc Accessor, address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8) error {
	avail := acc.BytesInRange(address, uint32(c.pageSize))
	if avail == 0 {
		return nil
	}

	read := acc.ReadBytes(address, memSpace, trcID, avail, c.blocks[idx].Data)
	if read > uint32(c.pageSize) {
		c.blocks[idx].ValidLen = 0
		return ocsd.ErrMemAccBadLen
	}

	c.blocks[idx].StartAddr = address
	c.blocks[idx].ValidLen = read
	c.blocks[idx].TrcID = trcID
	c.incSequence()
	return nil
}

func (c *Cache) copyFromBlock(idx int, address ocsd.VAddr, reqBytes uint32, buffer []byte) uint32 {
	block := &c.blocks[idx]
	offset := address - block.StartAddr
	copy(buffer, block.Data[offset:offset+ocsd.VAddr(reqBytes)])
	return reqBytes
}

func (c *Cache) blockInPage(idx int, address ocsd.VAddr, reqBytes uint32, trcID uint8) bool {
	block := &c.blocks[idx]
	if block.TrcID != trcID || block.ValidLen == 0 {
		return false
	}
	return address >= block.StartAddr && (address+ocsd.VAddr(reqBytes)) <= (block.StartAddr+ocsd.VAddr(block.ValidLen))
}

func (c *Cache) blockInCache(address ocsd.VAddr, reqBytes uint32, trcID uint8) bool {
	for i := range c.blocks {
		idx := (c.mruIdx + i) % len(c.blocks)
		if c.blockInPage(idx, address, reqBytes, trcID) {
			c.mruIdx = idx
			return true
		}
	}
	return false
}

func (c *Cache) findNewPage() int {
	oldestIdx := c.mruIdx
	oldestSeq := uint32(0)

	for i := 1; i < len(c.blocks); i++ {
		idx := (c.mruIdx + i) % len(c.blocks)
		block := c.blocks[idx]
		if block.UseSequence == 0 {
			return idx
		}
		if oldestSeq == 0 || block.UseSequence < oldestSeq {
			oldestSeq = block.UseSequence
			oldestIdx = idx
		}
	}
	return oldestIdx
}

// Utils

func MemSpaceString(memSpace ocsd.MemSpaceAcc) string {
	if name, ok := namedMemSpace(memSpace); ok {
		return name
	}

	parts := make([]string, 0, len(memSpaceNames))
	msBits := uint8(memSpace)
	for _, named := range memSpaceNames {
		if msBits&uint8(named.space) != 0 {
			parts = append(parts, named.name)
		}
	}
	return strings.Join(parts, ",")
}

func namedMemSpace(memSpace ocsd.MemSpaceAcc) (string, bool) {
	switch memSpace {
	case ocsd.MemSpaceNone:
		return "None", true
	case ocsd.MemSpaceS:
		return "Any S", true
	case ocsd.MemSpaceN:
		return "Any NS", true
	case ocsd.MemSpaceR:
		return "Any R", true
	case ocsd.MemSpaceAny:
		return "Any", true
	}

	for _, named := range memSpaceNames {
		if memSpace == named.space {
			return named.name, true
		}
	}
	return "", false
}

var memSpaceNames = []struct {
	space ocsd.MemSpaceAcc
	name  string
}{
	{ocsd.MemSpaceEL1S, "EL1S"},
	{ocsd.MemSpaceEL1N, "EL1N"},
	{ocsd.MemSpaceEL2, "EL2N"},
	{ocsd.MemSpaceEL3, "EL3"},
	{ocsd.MemSpaceEL2S, "EL2S"},
	{ocsd.MemSpaceEL1R, "EL1R"},
	{ocsd.MemSpaceEL2R, "EL2R"},
	{ocsd.MemSpaceRoot, "Root"},
}
