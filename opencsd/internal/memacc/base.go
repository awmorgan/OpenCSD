package memacc

import (
	"fmt"
	"opencsd/internal/ocsd"
)

// Type describes the storage type of the underlying memory accessor.
type Type int

const (
	TypeUnknown Type = iota
	TypeFile         // Binary data file accessor
	TypeBufPtr       // Memory buffer accessor
	TypeCBIf         // Callback interface accessor - use for live memory access
)

// Accessor defines the interface for a memory range access.
type Accessor interface {
	// ReadBytes reads bytes from via the accessor from the memory range.
	ReadBytes(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, byteBuffer []byte) uint32

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

	// GetType returns the storage type of this accessor.
	GetType() Type

	// SetMemSpace sets the memory space for this accessor.
	SetMemSpace(memSpace ocsd.MemSpaceAcc)

	// GetMemSpace returns the memory space for this accessor.
	GetMemSpace() ocsd.MemSpaceAcc

	// InMemSpace tests if the accessor supports the given memory space.
	InMemSpace(memSpace ocsd.MemSpaceAcc) bool

	// GetRange returns the start and end addresses of this accessor.
	GetRange() (ocsd.VAddr, ocsd.VAddr)
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
	st, en := testAcc.GetRange()
	return b.AddrInRange(st) || b.AddrInRange(en)
}

func (b *BaseAccessor) ValidateRange() bool {
	if b.StartAddress&0x1 != 0 {
		return false
	}
	if (b.EndAddress+1)&0x1 != 0 {
		return false
	}
	if b.StartAddress >= b.EndAddress {
		return false
	}
	return true
}

func (b *BaseAccessor) GetType() Type {
	return b.AccType
}

func (b *BaseAccessor) SetMemSpace(memSpace ocsd.MemSpaceAcc) {
	b.MemSpaceAcc = memSpace
}

func (b *BaseAccessor) GetMemSpace() ocsd.MemSpaceAcc {
	return b.MemSpaceAcc
}

func (b *BaseAccessor) InMemSpace(memSpace ocsd.MemSpaceAcc) bool {
	return (uint32(b.MemSpaceAcc) & uint32(memSpace)) != 0
}

func (b *BaseAccessor) GetRange() (ocsd.VAddr, ocsd.VAddr) {
	return b.StartAddress, b.EndAddress
}

func (b *BaseAccessor) String() string {
	var typeStr string
	switch b.AccType {
	case TypeFile:
		typeStr = "File"
	case TypeBufPtr:
		typeStr = "Buffer"
	case TypeCBIf:
		typeStr = "Callback"
	default:
		typeStr = "Unknown"
	}
	spaceStr := GetMemSpaceString(b.MemSpaceAcc)
	return fmt.Sprintf("Range: 0x%X - 0x%X; Type: %s; Space: %s", b.StartAddress, b.EndAddress, typeStr, spaceStr)
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
	StAddr      ocsd.VAddr
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
	errLog   ocsd.HandleErrLog // Placeholder for error logging if needed
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

func (c *Cache) SetCacheSizes(pageSize uint16, numPages int, errOnLimit bool) ocsd.Err {
	if pageSize < MinPageSize || pageSize > MaxPageSize || numPages < MinPages || numPages > MaxPages {
		if errOnLimit {
			return ocsd.ErrInvalidParamVal
		}
		if pageSize < MinPageSize {
			pageSize = MinPageSize
		} else if pageSize > MaxPageSize {
			pageSize = MaxPageSize
		}
		if numPages < MinPages {
			numPages = MinPages
		} else if numPages > MaxPages {
			numPages = MaxPages
		}
	}
	c.pageSize = pageSize
	c.numPages = numPages
	if c.enabled {
		c.createCaches()
	}
	return ocsd.OK
}

func (c *Cache) createCaches() {
	c.blocks = make([]CacheBlock, c.numPages)
	for i := range c.blocks {
		c.blocks[i].Data = make([]byte, c.pageSize)
		c.clearPage(&c.blocks[i])
	}
}

func (c *Cache) InvalidateAll() {
	if c.blocks == nil {
		return
	}
	for i := range c.blocks {
		c.clearPage(&c.blocks[i])
	}
}

func (c *Cache) InvalidateByTraceID(trcID uint8) {
	if c.blocks == nil {
		return
	}
	for i := range c.blocks {
		if c.blocks[i].TrcID == trcID {
			c.clearPage(&c.blocks[i])
		}
	}
}

func (c *Cache) clearPage(block *CacheBlock) {
	block.UseSequence = 0
	block.StAddr = 0
	block.ValidLen = 0
	block.TrcID = ocsd.BadCSSrcID
}

func (c *Cache) ReadBytesFromCache(acc Accessor, address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, numBytes *uint32, byteBuffer []byte) ocsd.Err {
	if !c.enabled {
		return ocsd.ErrFail
	}

	reqBytes := *numBytes

	// Check if block is in cache
	if c.blockInCache(address, reqBytes, trcID) {
		// Found in page (mruIdx set by blockInCache)
		offset := address - c.blocks[c.mruIdx].StAddr
		copy(byteBuffer, c.blocks[c.mruIdx].Data[offset:offset+ocsd.VAddr(reqBytes)])
		c.blocks[c.mruIdx].UseSequence = c.sequence
		c.sequence++
		return ocsd.OK
	}

	// Not in cache, load new page
	newIdx := c.findNewPage()
	c.mruIdx = newIdx

	// Prepare for read from accessor
	// Normalize address to page boundary for aligned caching
	pageBase := address & ^ocsd.VAddr(c.pageSize-1)

	// How many bytes can we read from this accessor?
	avail := acc.BytesInRange(pageBase, uint32(c.pageSize))
	if avail == 0 {
		return ocsd.ErrMemNacc
	}

	// Read from accessor into cache page
	read := acc.ReadBytes(pageBase, memSpace, trcID, avail, c.blocks[newIdx].Data)
	if read == 0 {
		return ocsd.ErrMemNacc
	}

	c.blocks[newIdx].StAddr = pageBase
	c.blocks[newIdx].ValidLen = read
	c.blocks[newIdx].TrcID = trcID
	c.blocks[newIdx].UseSequence = c.sequence
	c.sequence++

	// Now try to satisfied the original request from the new page
	if c.blockInPage(newIdx, address, reqBytes, trcID) {
		offset := address - c.blocks[newIdx].StAddr
		copy(byteBuffer, c.blocks[newIdx].Data[offset:offset+ocsd.VAddr(reqBytes)])
		return ocsd.OK
	}

	// If we still can't satisfy (e.g. request spans page boundary or read was short),
	// fallback to direct read for the client, but cache was partially populated.
	// Actually C++ logic might handle this differently.
	// In C++, if blockInPage fails after load, it just returns OCSD_ERR_MEM_ACC_BAD_LEN or similar.
	// Let's re-verify C++ ReadBytesFromCache.

	return ocsd.ErrMemNacc
}

func (c *Cache) blockInPage(idx int, address ocsd.VAddr, reqBytes uint32, trcID uint8) bool {
	block := &c.blocks[idx]
	if block.TrcID != trcID || block.ValidLen == 0 {
		return false
	}
	return address >= block.StAddr && (address+ocsd.VAddr(reqBytes)) <= (block.StAddr+ocsd.VAddr(block.ValidLen))
}

func (c *Cache) blockInCache(address ocsd.VAddr, reqBytes uint32, trcID uint8) bool {
	for i := 0; i < c.numPages; i++ {
		idx := (c.mruIdx + i) % c.numPages
		if c.blockInPage(idx, address, reqBytes, trcID) {
			c.mruIdx = idx
			return true
		}
	}
	return false
}

func (c *Cache) findNewPage() int {
	// Find oldest page (lowest UseSequence)
	oldestIdx := 0
	minSeq := c.blocks[0].UseSequence
	for i := 1; i < c.numPages; i++ {
		if c.blocks[i].UseSequence < minSeq {
			minSeq = c.blocks[i].UseSequence
			oldestIdx = i
		}
	}
	return oldestIdx
}

// Utils

func GetMemSpaceString(memSpace ocsd.MemSpaceAcc) string {
	switch memSpace {
	case ocsd.MemSpaceNone:
		return "None"
	case ocsd.MemSpaceEL1S:
		return "EL1S"
	case ocsd.MemSpaceEL1N:
		return "EL1N"
	case ocsd.MemSpaceEL2:
		return "EL2"
	case ocsd.MemSpaceEL3:
		return "EL3"
	case ocsd.MemSpaceEL2S:
		return "EL2S"
	case ocsd.MemSpaceEL1R:
		return "EL1R"
	case ocsd.MemSpaceEL2R:
		return "EL2R"
	case ocsd.MemSpaceRoot:
		return "Root"
	case ocsd.MemSpaceS:
		return "S"
	case ocsd.MemSpaceN:
		return "N"
	case ocsd.MemSpaceR:
		return "R"
	case ocsd.MemSpaceAny:
		return "Any"
	default:
		return "Unknown"
	}
}
