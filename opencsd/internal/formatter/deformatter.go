package formatter

import (
	"encoding/binary"
	"opencsd/internal/common"
)

const (
	FrameSize    = 16
	fsyncPattern = uint32(0x7FFFFFFF) // Little Endian FSYNC
)

// Deformatter mimics TraceFmtDcdImpl.
type Deformatter struct {
	receivers map[uint8]common.TrcDataIn
	currID    uint8
	buffer    []byte
	synced    bool
}

func NewDeformatter() *Deformatter {
	return &Deformatter{
		receivers: make(map[uint8]common.TrcDataIn),
		currID:    0,
		buffer:    make([]byte, 0, FrameSize*2),
		synced:    true,
	}
}

func (d *Deformatter) Attach(id uint8, receiver common.TrcDataIn) {
	d.receivers[id] = receiver
}

func (d *Deformatter) TraceDataIn(op common.DataPathOp, index int64, data []byte) (common.DataPathResp, int, error) {
	if op == common.OpEOT {
		for _, r := range d.receivers {
			r.TraceDataIn(common.OpEOT, index, nil)
		}
		return common.RespCont, 0, nil
	}

	totalProcessed := 0
	d.buffer = append(d.buffer, data...)

	// 1. Synchronization Loop
	if !d.synced {
		for len(d.buffer) >= 4 {
			val := binary.LittleEndian.Uint32(d.buffer[:4])
			if val == fsyncPattern {
				d.synced = true
				d.buffer = d.buffer[4:]
				totalProcessed += 4
				break
			}
			// Skip 1 byte and retry
			d.buffer = d.buffer[1:]
			totalProcessed++
		}
	}

	if !d.synced {
		return common.RespCont, totalProcessed, nil
	}

	// 2. Frame Processing Loop
	for len(d.buffer) >= FrameSize {
		// Check for FSYNCs embedded in the stream (padding/reset)
		val := binary.LittleEndian.Uint32(d.buffer[:4])
		if val == fsyncPattern {
			d.buffer = d.buffer[4:]
			totalProcessed += 4
			continue
		}

		// Process one 16-byte frame
		frame := d.buffer[:FrameSize]
		err := d.unpackFrame(frame, index+int64(totalProcessed))
		if err != nil {
			return common.RespFatal, totalProcessed, err
		}

		d.buffer = d.buffer[FrameSize:]
		totalProcessed += FrameSize
	}

	return common.RespCont, len(data), nil
}

// unpackFrame implements TraceFmtDcdImpl::unpackFrame.
// - Iterates 0..14 in steps of 2.
// - Byte 15 contains flags for the even bytes (bit 0 for byte 0, bit 1 for byte 2, etc).
func (d *Deformatter) unpackFrame(frame []byte, index int64) error {
	flags := frame[15]
	flagBitMask := byte(1)

	// Process 7 pairs (Bytes 0-13)
	for i := 0; i < 14; i += 2 {
		// --- Even Byte (i) ---
		bEven := frame[i]
		if (bEven & 0x01) == 0x01 {
			// ID Change: New ID is in bits [7:1]
			d.currID = (bEven >> 1) & 0x7F
		} else {
			// Data: LSB is 0 in frame, restored from flag bit
			lsb := byte(0)
			if (flags & flagBitMask) != 0 {
				lsb = 1
			}
			d.outputByte(bEven|lsb, index+int64(i))
		}

		// --- Odd Byte (i+1) ---
		// Always raw data, no flag bit used
		bOdd := frame[i+1]
		d.outputByte(bOdd, index+int64(i+1))

		// Shift flag mask for the next *pair*
		flagBitMask <<= 1
	}

	// Process Byte 14 (Single byte at end)
	// It behaves like an Even byte (uses bit 7 of flags)
	bLast := frame[14]
	if (bLast & 0x01) == 0x01 {
		d.currID = (bLast >> 1) & 0x7F
	} else {
		lsb := byte(0)
		if (flags & flagBitMask) != 0 {
			lsb = 1
		}
		d.outputByte(bLast|lsb, index+14)
	}

	return nil
}

func (d *Deformatter) outputByte(b byte, index int64) {
	if receiver, ok := d.receivers[d.currID]; ok {
		receiver.TraceDataIn(common.OpData, index, []byte{b})
	}
}
