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
	return (uint8(b.MemSpaceAcc) & uint8(memSpace)) != 0
}

func (b *BaseAccessor) Range() (ocsd.VAddr, ocsd.VAddr) {
	return b.StartAddress, b.EndAddress
}

func (b *BaseAccessor) String() string {
	var typeStr string
	switch b.AccType {
	case TypeFile:
		typeStr = "FileAcc"
	case TypeBufPtr:
		typeStr = "BuffAcc"
	case TypeCBIf:
		typeStr = "CB  Acc"
	default:
		typeStr = "UnknAcc"
	}
	spaceStr := MemSpaceString(b.MemSpaceAcc)
	return fmt.Sprintf("%s; Range::0x%x:%x; Mem Space::%s", typeStr, b.StartAddress, b.EndAddress, spaceStr)
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

func (c *Cache) incSequence() {
	c.blocks[c.mruIdx].UseSequence = c.sequence
	c.sequence++
	if c.sequence == 0 {
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
}

// Read reads up to reqBytes into buffer from cache-backed accessor state.
func (c *Cache) Read(acc Accessor, address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) (uint32, error) {
	if reqBytes > uint32(len(buffer)) {
		reqBytes = uint32(len(buffer))
	}

	if !c.enabled {
		return 0, ocsd.ToError(ocsd.ErrFail)
	}

	bytesRead := uint32(0)

	// Check if block is in cache
	if c.blockInCache(address, reqBytes, trcID) {
		// Found in page (mruIdx set by blockInCache)
		offset := address - c.blocks[c.mruIdx].StAddr
		copy(buffer, c.blocks[c.mruIdx].Data[offset:offset+ocsd.VAddr(reqBytes)])
		bytesRead = reqBytes
		c.incSequence()
		return bytesRead, nil
	}

	// Not in cache, load new page
	newIdx := c.findNewPage()
	c.mruIdx = newIdx

	// Prepare for read from accessor
	// Normalize address to page boundary for aligned caching
	pageBase := address & ^ocsd.VAddr(c.pageSize-1)
	accStart, _ := acc.Range()
	if pageBase < accStart {
		pageBase = accStart
	}

	// How many bytes can we read from this accessor?
	avail := acc.BytesInRange(pageBase, uint32(c.pageSize))
	if avail == 0 {
		return 0, nil
	}

	// Read from accessor into cache page
	read := acc.ReadBytes(pageBase, memSpace, trcID, avail, c.blocks[newIdx].Data)
	if read > uint32(c.pageSize) {
		c.blocks[newIdx].ValidLen = 0
		return 0, ocsd.ToError(ocsd.ErrMemAccBadLen)
	}

	c.blocks[newIdx].StAddr = pageBase
	c.blocks[newIdx].ValidLen = read
	c.blocks[newIdx].TrcID = trcID
	c.incSequence()

	// Now try to satisfied the original request from the new page
	if c.blockInPage(newIdx, address, reqBytes, trcID) {
		offset := address - c.blocks[newIdx].StAddr
		copy(buffer, c.blocks[newIdx].Data[offset:offset+ocsd.VAddr(reqBytes)])
		bytesRead = reqBytes
	}
	return bytesRead, nil
}

// ReadBytesFromCache reads bytes from cache-backed accessor state.
// Deprecated: use Read.
func (c *Cache) ReadBytesFromCache(acc Accessor, address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, numBytes *uint32, byteBuffer []byte) ocsd.Err {
	bytesRead, err := c.Read(acc, address, memSpace, trcID, *numBytes, byteBuffer)
	*numBytes = bytesRead
	return ocsd.AsErr(err)
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
	currentIdx := c.mruIdx + 1
	oldestIdx := c.mruIdx
	var oldestSeq uint32
	if currentIdx >= c.numPages {
		currentIdx = 0
	}
	for currentIdx != c.mruIdx {
		if c.blocks[currentIdx].UseSequence == 0 {
			return currentIdx
		}
		if oldestSeq == 0 || oldestSeq > c.blocks[currentIdx].UseSequence {
			oldestSeq = c.blocks[currentIdx].UseSequence
			oldestIdx = currentIdx
		}
		currentIdx++
		if currentIdx >= c.numPages {
			currentIdx = 0
		}
	}
	return oldestIdx
}

// Utils

func MemSpaceString(memSpace ocsd.MemSpaceAcc) string {
	switch memSpace {
	case ocsd.MemSpaceNone:
		return "None"
	case ocsd.MemSpaceEL1S:
		return "EL1S"
	case ocsd.MemSpaceEL1N:
		return "EL1N"
	case ocsd.MemSpaceEL2:
		return "EL2N"
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
		return "Any S"
	case ocsd.MemSpaceN:
		return "Any NS"
	case ocsd.MemSpaceR:
		return "Any R"
	case ocsd.MemSpaceAny:
		return "Any"
	default:
		parts := make([]string, 0, 8)
		msBits := uint8(memSpace)
		if msBits&uint8(ocsd.MemSpaceEL1S) != 0 {
			parts = append(parts, "EL1S")
		}
		if msBits&uint8(ocsd.MemSpaceEL1N) != 0 {
			parts = append(parts, "EL1N")
		}
		if msBits&uint8(ocsd.MemSpaceEL2) != 0 {
			parts = append(parts, "EL2N")
		}
		if msBits&uint8(ocsd.MemSpaceEL3) != 0 {
			parts = append(parts, "EL3")
		}
		if msBits&uint8(ocsd.MemSpaceEL2S) != 0 {
			parts = append(parts, "EL2S")
		}
		if msBits&uint8(ocsd.MemSpaceEL1R) != 0 {
			parts = append(parts, "EL1R")
		}
		if msBits&uint8(ocsd.MemSpaceEL2R) != 0 {
			parts = append(parts, "EL2R")
		}
		if msBits&uint8(ocsd.MemSpaceRoot) != 0 {
			parts = append(parts, "Root")
		}
		return strings.Join(parts, ",")
	}
}
