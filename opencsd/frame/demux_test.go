package frame

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDemuxerBasic(t *testing.T) {
	d := NewDemuxer()

	// Create a simple frame with ID 0x13 and some data
	// ID byte format: (id << 1) | 1
	// Data byte format: (data & 0xFE) with flag bit in byte 15
	frame := make([]byte, 16)

	// Byte 0: ID = 0x13 -> (0x13 << 1) | 1 = 0x27
	frame[0] = 0x27
	// Byte 1: data = 0x08 (ISYNC header)
	frame[1] = 0x08
	// Bytes 2-13: more data
	frame[2] = 0x82 // data
	frame[3] = 0x8D
	frame[4] = 0x01
	frame[5] = 0xC0
	frame[6] = 0x61
	frame[7] = 0x00
	frame[8] = 0x00
	frame[9] = 0x00
	frame[10] = 0x00
	frame[11] = 0x00
	frame[12] = 0x00
	frame[13] = 0x00
	// Byte 14: more data
	frame[14] = 0x00
	// Byte 15: flags - all zeros means no LSB restoration needed
	frame[15] = 0x00

	result := d.Process(frame)

	if len(result) == 0 {
		t.Fatal("No data extracted")
	}

	data, ok := result[0x13]
	if !ok {
		t.Fatal("No data for ID 0x13")
	}

	t.Logf("Extracted %d bytes for ID 0x13: %v", len(data), data)

	// Should have extracted some data bytes
	if len(data) < 1 {
		t.Errorf("Expected at least 1 data byte, got %d", len(data))
	}

	// First byte should be 0x08 (ISYNC header)
	if data[0] != 0x08 {
		t.Errorf("Expected first byte 0x08, got 0x%02x", data[0])
	}
}

func TestDemuxerFSyncSkip(t *testing.T) {
	d := NewDemuxer()
	d.ResetOn4Sync = true

	// Create FSYNC frame followed by data frame
	data := make([]byte, 32)

	// First frame: all FSYNCs (0x7FFFFFFF pattern)
	for i := 0; i < 16; i += 4 {
		data[i] = 0xFF
		data[i+1] = 0xFF
		data[i+2] = 0xFF
		data[i+3] = 0x7F
	}

	// Second frame: ID 0x10 with data
	data[16] = 0x21 // ID = 0x10 -> (0x10 << 1) | 1 = 0x21
	data[17] = 0xAA // data
	for i := 18; i < 31; i++ {
		data[i] = 0x00
	}
	data[31] = 0x00 // flags

	result := d.Process(data)

	if len(result) == 0 {
		t.Fatal("No data extracted")
	}

	idData, ok := result[0x10]
	if !ok {
		t.Fatal("No data for ID 0x10")
	}

	t.Logf("Extracted %d bytes for ID 0x10", len(idData))

	if len(idData) == 0 || idData[0] != 0xAA {
		t.Errorf("Expected first byte 0xAA, got %v", idData)
	}
}

func TestDemuxerTC2(t *testing.T) {
	// Test with actual TC2 cstrace.bin
	snapshotPath := "../decoder/tests/snapshots/TC2"
	tracePath := filepath.Join(snapshotPath, "cstrace.bin")

	// Check if file exists (relative path from opencsd/frame)
	tracePath = "../../decoder/tests/snapshots/TC2/cstrace.bin"

	data, err := os.ReadFile(tracePath)
	if err != nil {
		t.Skipf("Skipping TC2 test, file not found: %v", err)
	}

	t.Logf("Loaded %d bytes of trace data", len(data))

	d := NewDemuxer()
	d.MemAligned = true
	d.ResetOn4Sync = true

	result := d.Process(data)

	t.Logf("Found data for %d trace IDs", len(result))

	for id, idData := range result {
		t.Logf("  ID 0x%02x: %d bytes", id, len(idData))
	}

	// TC2 should have PTM data on ID 0x13
	ptmData, ok := result[0x13]
	if !ok {
		t.Error("No data for PTM ID 0x13")
	} else {
		t.Logf("PTM ID 0x13: %d bytes", len(ptmData))
		if len(ptmData) > 20 {
			t.Logf("  First 20 bytes: %v", ptmData[:20])
		}
	}
}

func TestIsFSyncFrame(t *testing.T) {
	d := NewDemuxer()

	// Valid FSYNC frame
	fsync := make([]byte, 16)
	for i := 0; i < 16; i += 4 {
		fsync[i] = 0xFF
		fsync[i+1] = 0xFF
		fsync[i+2] = 0xFF
		fsync[i+3] = 0x7F
	}

	if !d.isFSyncFrame(fsync) {
		t.Error("Should recognize FSYNC frame")
	}

	// Non-FSYNC frame
	notFsync := make([]byte, 16)
	notFsync[0] = 0x27 // ID byte
	if d.isFSyncFrame(notFsync) {
		t.Error("Should not recognize as FSYNC frame")
	}
}
