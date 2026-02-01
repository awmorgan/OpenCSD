// Package main implements mem_buffer_eg - demonstrates using memory buffers with the OpenCSD decoder.
// This is a Go port of the C++ mem_buff_demo.cpp utility.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const memBufferWiringIncompleteMsg = "mem_buffer_eg is a scaffold and is not wired to real protocol decoders yet.\n" +
	"It only demonstrates placeholder parsing and memory access patterns.\n"

func failIfNotWired() {
	fmt.Fprint(os.Stderr, memBufferWiringIncompleteMsg)
	os.Exit(2)
}

// MemBufferDemo demonstrates trace decoding using memory buffers
type MemBufferDemo struct {
	traceData      []byte
	programImage   []byte
	programAddress uint64
	logger         *log.Logger
}

// TraceElement represents a decoded trace element
type TraceElement struct {
	Index    uint64
	TraceID  uint8
	Atoms    string
	Address  uint64
	Cyclecnt uint32
}

// String formats the trace element for output
func (t TraceElement) String() string {
	return fmt.Sprintf("Idx:%d; ID:0x%02x; Atoms:%s; Addr:0x%x; Cycles:%d",
		t.Index, t.TraceID, t.Atoms, t.Address, t.Cyclecnt)
}

// NewMemBufferDemo creates a new memory buffer demo
func NewMemBufferDemo() *MemBufferDemo {
	return &MemBufferDemo{
		logger: log.New(os.Stdout, "", 0),
	}
}

// LoadTraceData loads trace data from a file
func (m *MemBufferDemo) LoadTraceData(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to load trace data: %w", err)
	}
	m.traceData = data
	m.logger.Printf("Loaded %d bytes of trace data from %s\n", len(data), filename)
	return nil
}

// LoadProgramImage loads the program memory image from a file
func (m *MemBufferDemo) LoadProgramImage(filename string, baseAddr uint64) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to load program image: %w", err)
	}
	m.programImage = data
	m.programAddress = baseAddr
	m.logger.Printf("Loaded %d bytes of program image from %s at address 0x%x\n",
		len(data), filename, baseAddr)
	return nil
}

// MemoryAccessor provides access to program memory
type MemoryAccessor struct {
	image     []byte
	baseAddr  uint64
	imageSize uint64
}

// NewMemoryAccessor creates a new memory accessor
func NewMemoryAccessor(image []byte, baseAddr uint64) *MemoryAccessor {
	return &MemoryAccessor{
		image:     image,
		baseAddr:  baseAddr,
		imageSize: uint64(len(image)),
	}
}

// ReadMemory reads bytes from the memory image
func (m *MemoryAccessor) ReadMemory(addr uint64, size uint32) ([]byte, error) {
	// Check if address is within bounds
	if addr < m.baseAddr || addr >= m.baseAddr+m.imageSize {
		return nil, fmt.Errorf("address 0x%x out of range", addr)
	}

	// Calculate offset into buffer
	offset := addr - m.baseAddr
	endAddr := offset + uint64(size)

	// Clamp to available data
	if endAddr > m.imageSize {
		endAddr = m.imageSize
	}

	return m.image[offset:endAddr], nil
}

// Decoder simulates the trace decoder
type Decoder struct {
	traceData      []byte
	memoryAccessor *MemoryAccessor
	logger         *log.Logger
	elemIndex      uint64
}

// NewDecoder creates a new decoder
func NewDecoder(traceData []byte, memAcc *MemoryAccessor) *Decoder {
	return &Decoder{
		traceData:      traceData,
		memoryAccessor: memAcc,
		logger:         log.New(os.Stdout, "", 0),
		elemIndex:      0,
	}
}

// ProcessTraceData processes the trace data
// This is a simplified example - the real decoder would be more complex
func (d *Decoder) ProcessTraceData() error {
	if len(d.traceData) == 0 {
		return fmt.Errorf("no trace data to process")
	}

	d.logger.Printf("Processing %d bytes of trace data\n", len(d.traceData))

	// Example: parse trace packets (simplified)
	// The actual format depends on the ETM version and configuration
	packetCount := 0
	for i := 0; i < len(d.traceData)-1; i++ {
		// Look for frame synchronization markers
		if d.traceData[i] == 0xff && d.traceData[i+1] == 0x7f {
			packetCount++
			d.logger.Printf("Found frame sync at offset 0x%x\n", i)
		}
	}

	d.logger.Printf("Found %d frame sync markers\n", packetCount)
	return nil
}

// TraceOutput processes decoded trace elements
func (d *Decoder) ProcessTraceElement(elem TraceElement) error {
	d.logger.Printf("%s\n", elem.String())

	// Example: try to access program memory at the element address
	if elem.Address > 0 && d.memoryAccessor != nil {
		instruction, err := d.memoryAccessor.ReadMemory(elem.Address, 4)
		if err == nil {
			d.logger.Printf("  Instruction at 0x%x: %02x\n", elem.Address, instruction)
		}
	}

	return nil
}

// Run executes the memory buffer demonstration
func (m *MemBufferDemo) Run(traceFile string, imageFile string, baseAddr uint64) error {
	// Load files
	if err := m.LoadTraceData(traceFile); err != nil {
		return err
	}

	if err := m.LoadProgramImage(imageFile, baseAddr); err != nil {
		return err
	}

	// Create memory accessor
	memAcc := NewMemoryAccessor(m.programImage, m.programAddress)

	// Create decoder
	decoder := NewDecoder(m.traceData, memAcc)

	// Process trace data
	if err := decoder.ProcessTraceData(); err != nil {
		return err
	}

	// Example: process some trace elements
	m.logger.Println("\nExample decoded trace elements:")
	sampleElements := []TraceElement{
		{Index: 0, TraceID: 0x10, Atoms: "E", Address: 0xFFFFFFC000081000},
		{Index: 1, TraceID: 0x10, Atoms: "E", Address: 0xFFFFFFC000081004},
		{Index: 2, TraceID: 0x10, Atoms: "E", Address: 0xFFFFFFC000081008},
	}

	for _, elem := range sampleElements {
		decoder.ProcessTraceElement(elem)
	}

	m.logger.Println("\nMemory buffer demo complete")
	return nil
}

func main() {
	failIfNotWired()

	fmt.Println("Memory Buffer Example")
	fmt.Println("====================\n")

	demo := NewMemBufferDemo()

	// Find snapshot directory
	snapshotDirs := []string{
		"../../../decoder/tests/snapshots/juno_r1_1",
		"../../decoder/tests/snapshots/juno_r1_1",
		"./decoder/tests/snapshots/juno_r1_1",
	}

	traceFile := ""
	imageFile := ""

	for _, dir := range snapshotDirs {
		traceCandidate := filepath.Join(dir, "cstrace.bin")
		imageCandidate := filepath.Join(dir, "kernel_dump.bin")

		if _, err := os.Stat(traceCandidate); err == nil {
			if _, err := os.Stat(imageCandidate); err == nil {
				traceFile = traceCandidate
				imageFile = imageCandidate
				break
			}
		}
	}

	if traceFile == "" || imageFile == "" {
		fmt.Println("Error: Could not find snapshot files")
		fmt.Println("Expected files: cstrace.bin, kernel_dump.bin")
		fmt.Println("Tried directories:")
		for _, dir := range snapshotDirs {
			fmt.Printf("  %s\n", dir)
		}
		os.Exit(1)
	}

	// Run the demo
	baseAddr := uint64(0xFFFFFFC000081000) // Example kernel address
	if err := demo.Run(traceFile, imageFile, baseAddr); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
