// Package frame implements CoreSight trace frame demultiplexing.
// CoreSight trace data from multiple sources is multiplexed into 16-byte frames
// with embedded trace source IDs. This package extracts the data for each trace ID.
package frame

// FrameSize is the size of a CoreSight trace frame in bytes
const FrameSize = 16

// Demuxer extracts trace data for specific trace IDs from multiplexed CoreSight frames.
type Demuxer struct {
	// Configuration
	HasFSyncs    bool // Frame syncs present in data
	HasHSyncs    bool // Half-frame syncs present in data
	MemAligned   bool // Data is memory-aligned (always 16-byte frames)
	ResetOn4Sync bool // Reset decoders on 4 consecutive FSYNCs

	// State
	synced    bool   // True once synchronized to frame boundary
	currID    uint8  // Current trace source ID
	frameData []byte // Current frame being processed

	// Output buffers per trace ID (0-127)
	idData [128][]byte
}

// NewDemuxer creates a new frame demuxer with default settings.
func NewDemuxer() *Demuxer {
	return &Demuxer{
		MemAligned:   true, // Most common case
		ResetOn4Sync: true,
		currID:       0xFF, // Invalid ID
	}
}

// Reset clears demuxer state.
func (d *Demuxer) Reset() {
	d.synced = false
	d.currID = 0xFF
	d.frameData = nil
	for i := range d.idData {
		d.idData[i] = nil
	}
}

// Process processes raw trace data and extracts per-ID data.
// Returns a map of trace ID to extracted data bytes.
func (d *Demuxer) Process(data []byte) map[uint8][]byte {
	// Clear output buffers
	for i := range d.idData {
		d.idData[i] = nil
	}

	if len(data) == 0 {
		return nil
	}

	// For memory-aligned data, process 16-byte frames
	if d.MemAligned {
		d.processAligned(data)
	} else {
		d.processWithSyncs(data)
	}

	// Build result map (only IDs with data)
	result := make(map[uint8][]byte)
	for id, buf := range d.idData {
		if len(buf) > 0 {
			result[uint8(id)] = buf
		}
	}
	return result
}

// GetIDData returns extracted data for a specific trace ID.
func (d *Demuxer) GetIDData(id uint8) []byte {
	if id > 127 {
		return nil
	}
	return d.idData[id]
}

// processAligned processes memory-aligned 16-byte frames.
func (d *Demuxer) processAligned(data []byte) {
	offset := 0

	for offset+FrameSize <= len(data) {
		frame := data[offset : offset+FrameSize]

		// Check for FSYNC pattern (0x7FFFFFFF repeated)
		if d.ResetOn4Sync && d.isFSyncFrame(frame) {
			// Skip FSYNC frames, reset state
			d.currID = 0xFF
			offset += FrameSize
			continue
		}

		d.unpackFrame(frame)
		offset += FrameSize
	}
}

// processWithSyncs processes data that may contain FSYNCs/HSYNCs.
func (d *Demuxer) processWithSyncs(data []byte) {
	offset := 0

	// Find initial sync if not synced
	if !d.synced {
		syncOffset := d.findSync(data)
		if syncOffset < 0 {
			return // No sync found
		}
		offset = syncOffset
		d.synced = true
	}

	// Process frames
	for offset+FrameSize <= len(data) {
		// Skip FSYNCs
		for offset+4 <= len(data) && d.isFSync(data[offset:offset+4]) {
			offset += 4
		}

		if offset+FrameSize > len(data) {
			break
		}

		frame := data[offset : offset+FrameSize]
		d.unpackFrame(frame)
		offset += FrameSize
	}
}

// isFSyncFrame checks if a 16-byte frame is all FSYNCs.
func (d *Demuxer) isFSyncFrame(frame []byte) bool {
	if len(frame) < 16 {
		return false
	}
	// FSYNC pattern is 0x7FFFFFFF in little-endian
	for i := 0; i < 16; i += 4 {
		if frame[i] != 0xFF || frame[i+1] != 0xFF ||
			frame[i+2] != 0xFF || frame[i+3] != 0x7F {
			return false
		}
	}
	return true
}

// isFSync checks for a 4-byte FSYNC pattern.
func (d *Demuxer) isFSync(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 0xFF && data[1] == 0xFF &&
		data[2] == 0xFF && data[3] == 0x7F
}

// findSync finds the first frame sync in data.
func (d *Demuxer) findSync(data []byte) int {
	// Look for FSYNC pattern
	for i := 0; i+4 <= len(data); i++ {
		if d.isFSync(data[i : i+4]) {
			// Found FSYNC, align to frame boundary
			return i + 4
		}
	}
	return -1
}

// unpackFrame extracts data bytes from a 16-byte frame.
// Frame format:
// - Bytes 0-14: Data or ID bytes
// - Byte 15: Flag bits for bytes 0,2,4,6,8,10,12,14
//
// ID byte: LSB=1, bits[7:1] = trace ID
// Data byte: LSB=0, bits[7:1] = data (combined with flag bit)
func (d *Demuxer) unpackFrame(frame []byte) {
	if len(frame) < 16 {
		return
	}

	flags := frame[15]
	flagBit := uint8(0x01)

	// Process bytes 0-13 in pairs
	for i := 0; i < 14; i += 2 {
		b0 := frame[i]
		b1 := frame[i+1]

		prevIDChange := false

		// Check if byte 0 is an ID byte (LSB=1)
		if (b0 & 0x01) != 0 {
			newID := (b0 >> 1) & 0x7F

			if newID != d.currID {
				// ID change - check if flag bit means b1 goes to previous ID
				prevIDChange = (flags & flagBit) != 0

				if prevIDChange && d.currID != 0xFF && d.currID <= 127 {
					// b1 goes to previous ID
					d.idData[d.currID] = append(d.idData[d.currID], b1)
				}

				d.currID = newID
			}
		} else {
			// Data byte - combine with flag bit to restore LSB
			dataByte := b0
			if (flags & flagBit) != 0 {
				dataByte |= 0x01
			}
			if d.currID != 0xFF && d.currID <= 127 {
				d.idData[d.currID] = append(d.idData[d.currID], dataByte)
			}
		}

		// b1 is always data (unless already output for prev ID change)
		if !prevIDChange && d.currID != 0xFF && d.currID <= 127 {
			d.idData[d.currID] = append(d.idData[d.currID], b1)
		}

		flagBit <<= 1
	}

	// Process byte 14
	b14 := frame[14]
	if (b14 & 0x01) != 0 {
		// ID byte
		d.currID = (b14 >> 1) & 0x7F
	} else {
		// Data byte
		dataByte := b14
		if (flags & flagBit) != 0 {
			dataByte |= 0x01
		}
		if d.currID != 0xFF && d.currID <= 127 {
			d.idData[d.currID] = append(d.idData[d.currID], dataByte)
		}
	}
}
