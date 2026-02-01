// Package main implements mem_acc_test - tests memory accessor interfaces and caching.
// This is a Go port of the C++ mem_acc_test.cpp utility.
package main

import (
	"fmt"
	"log"
	"os"
)

const memAccStandaloneMsg = "mem_acc_test is a standalone scaffold and not wired to the OpenCSD decoder core.\n" +
	"It validates local memory accessor behavior only.\n"

// TestStats tracks test pass/fail counts
type TestStats struct {
	passed int
	failed int
}

// MemorySpace represents different memory space types
type MemorySpace uint32

const (
	MemSpaceEL0NS MemorySpace = iota
	MemSpaceEL1NS
	MemSpaceEL2NS
	MemSpaceEL1S
	MemSpaceEL2S
	MemSpaceEL3
	MemSpaceEL1R
	MemSpaceEL2R
	MemSpaceROOT
	MemSpaceS   // All secure
	MemSpaceN   // All non-secure
	MemSpaceR   // All Realm
	MemSpaceANY // All spaces
)

func (m MemorySpace) String() string {
	switch m {
	case MemSpaceEL0NS:
		return "EL0/EL1 Non-Secure"
	case MemSpaceEL1NS:
		return "EL1 Non-Secure"
	case MemSpaceEL2NS:
		return "EL2 Non-Secure"
	case MemSpaceEL1S:
		return "EL1 Secure"
	case MemSpaceEL2S:
		return "EL2 Secure"
	case MemSpaceEL3:
		return "EL3"
	case MemSpaceEL1R:
		return "EL1 Realm"
	case MemSpaceEL2R:
		return "EL2 Realm"
	case MemSpaceROOT:
		return "Root"
	case MemSpaceS:
		return "All Secure"
	case MemSpaceN:
		return "All Non-Secure"
	case MemSpaceR:
		return "All Realm"
	case MemSpaceANY:
		return "All Spaces"
	default:
		return "Unknown"
	}
}

// MemoryAccessor provides access to memory regions
type MemoryAccessor struct {
	startAddr uint64
	size      uint64
	buffer    []byte
	memSpace  MemorySpace
}

// MemoryMap manages multiple memory accessors
type MemoryMap struct {
	accessors []*MemoryAccessor
}

// NewMemoryMap creates a new memory map
func NewMemoryMap() *MemoryMap {
	return &MemoryMap{
		accessors: make([]*MemoryAccessor, 0),
	}
}

// AddAccessor adds a new memory accessor
// Returns error if regions overlap in the same memory space
func (m *MemoryMap) AddAccessor(startAddr uint64, buffer []byte, memSpace MemorySpace) error {
	accessor := &MemoryAccessor{
		startAddr: startAddr,
		size:      uint64(len(buffer)),
		buffer:    buffer,
		memSpace:  memSpace,
	}

	// Check for overlaps with same or overlapping memory space
	for _, existing := range m.accessors {
		if m.memSpacesOverlap(memSpace, existing.memSpace) {
			if m.addressRangesOverlap(startAddr, startAddr+accessor.size-1,
				existing.startAddr, existing.startAddr+existing.size-1) {
				return fmt.Errorf("memory accessor overlap detected at 0x%x in %s",
					startAddr, memSpace.String())
			}
		}
	}

	m.accessors = append(m.accessors, accessor)
	return nil
}

// memSpacesOverlap checks if two memory spaces can overlap
func (m *MemoryMap) memSpacesOverlap(space1, space2 MemorySpace) bool {
	// General spaces overlap with specific spaces
	// For simplicity, we consider overlap if they share any execution level
	if space1 == MemSpaceANY || space2 == MemSpaceANY {
		return true
	}
	if space1 == space2 {
		return true
	}
	// Check if both are in same general category
	if (space1 == MemSpaceS || space1 == MemSpaceN || space1 == MemSpaceR) &&
		(space2 == MemSpaceS || space2 == MemSpaceN || space2 == MemSpaceR) {
		return space1 == space2
	}
	return false
}

// addressRangesOverlap checks if two address ranges overlap
func (m *MemoryMap) addressRangesOverlap(start1, end1, start2, end2 uint64) bool {
	return start1 <= end2 && start2 <= end1
}

// RemoveAllAccessors clears all accessors
func (m *MemoryMap) RemoveAllAccessors() {
	m.accessors = m.accessors[:0]
}

// ReadMemory reads bytes from the specified address and memory space
func (m *MemoryMap) ReadMemory(addr uint64, memSpace MemorySpace, size uint64) ([]byte, error) {
	for _, accessor := range m.accessors {
		if !m.memSpacesOverlap(memSpace, accessor.memSpace) {
			continue
		}
		if addr >= accessor.startAddr && addr < accessor.startAddr+accessor.size {
			// Address is in this region
			offset := addr - accessor.startAddr
			available := accessor.size - offset
			if available < size {
				size = available
			}
			return accessor.buffer[offset : offset+size], nil
		}
	}
	return nil, fmt.Errorf("address 0x%x not accessible in memory space %s", addr, memSpace.String())
}

// TestRunner runs the memory accessor tests
type TestRunner struct {
	stats TestStats
	log   *log.Logger
}

// NewTestRunner creates a new test runner
func NewTestRunner() *TestRunner {
	return &TestRunner{
		stats: TestStats{},
		log:   log.New(os.Stdout, "", log.LstdFlags),
	}
}

// LogTestStart logs the start of a test
func (t *TestRunner) LogTestStart(testName string) {
	t.log.Printf("*** Test %s starting...\n", testName)
}

// LogTestEnd logs the end of a test
func (t *TestRunner) LogTestEnd(testName string) {
	t.log.Printf("*** Test %s complete (Pass: %d; Fail: %d)\n",
		testName, t.stats.passed, t.stats.failed)
}

// Assert checks a condition and updates test stats
func (t *TestRunner) Assert(condition bool, message string) {
	if condition {
		t.stats.passed++
		t.log.Printf("  PASS: %s\n", message)
	} else {
		t.stats.failed++
		t.log.Printf("  FAIL: %s\n", message)
	}
}

// TestOverlapRegions tests adding overlapping memory regions
func (t *TestRunner) TestOverlapRegions(memMap *MemoryMap) {
	t.LogTestStart("TestOverlapRegions")
	defer t.LogTestEnd("TestOverlapRegions")

	// Create some test memory blocks
	block1 := make([]byte, 4096)
	block2 := make([]byte, 4096)
	block3 := make([]byte, 4096)

	// Add non-overlapping regions
	err := memMap.AddAccessor(0x0000, block1, MemSpaceEL1NS)
	t.Assert(err == nil, "Add first accessor at 0x0000")

	err = memMap.AddAccessor(0x2000, block2, MemSpaceEL1NS)
	t.Assert(err == nil, "Add non-overlapping accessor at 0x2000")

	// Try to add overlapping region in same memory space (should fail)
	err = memMap.AddAccessor(0x1000, block2, MemSpaceEL1NS)
	t.Assert(err != nil, "Overlapping region in same memory space rejected")

	// Add overlapping region in different memory space (should succeed)
	err = memMap.AddAccessor(0x0000, block3, MemSpaceEL1S)
	t.Assert(err == nil, "Overlapping region in different memory space accepted")

	memMap.RemoveAllAccessors()
}

// TestMemoryAccess tests reading from memory accessors
func (t *TestRunner) TestMemoryAccess(memMap *MemoryMap) {
	t.LogTestStart("TestMemoryAccess")
	defer t.LogTestEnd("TestMemoryAccess")

	// Create test data with known pattern
	testData := make([]byte, 256)
	for i := 0; i < len(testData); i++ {
		testData[i] = byte(i)
	}

	err := memMap.AddAccessor(0x1000, testData, MemSpaceEL1NS)
	t.Assert(err == nil, "Add memory accessor")

	// Test reading different addresses
	data, err := memMap.ReadMemory(0x1000, MemSpaceEL1NS, 1)
	t.Assert(err == nil && len(data) > 0 && data[0] == 0, "Read first byte")

	data, err = memMap.ReadMemory(0x1010, MemSpaceEL1NS, 1)
	t.Assert(err == nil && len(data) > 0 && data[0] == 0x10, "Read byte at offset")

	// Test reading from invalid address
	_, err = memMap.ReadMemory(0x2000, MemSpaceEL1NS, 1)
	t.Assert(err != nil, "Read from invalid address returns error")

	memMap.RemoveAllAccessors()
}

func main() {
	fmt.Fprint(os.Stderr, memAccStandaloneMsg)

	runner := NewTestRunner()
	memMap := NewMemoryMap()

	fmt.Println("Memory Accessor Test Program")
	fmt.Println("============================\n")

	runner.TestOverlapRegions(memMap)
	fmt.Println()
	runner.TestMemoryAccess(memMap)

	fmt.Printf("\n\nTest Summary: Passed: %d, Failed: %d\n", runner.stats.passed, runner.stats.failed)

	if runner.stats.failed > 0 {
		os.Exit(1)
	}
}
