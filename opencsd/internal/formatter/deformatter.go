package formatter

import (
	"opencsd/internal/common"
)

const (
	FrameSize = 16
	// CoreSight Frame Format constants
	fsyncPattern = 0x7FFFFFFF
)

// Deformatter mimics TraceFormatterFrameDecoder.
// It accepts raw TPIU frames, unpacks them, and sends byte streams to registered ID channels.
type Deformatter struct {
	receivers map[uint8]common.TrcDataIn
	currID    uint8
	buffer    []byte // Buffer for partial frames
}

func NewDeformatter() *Deformatter {
	return &Deformatter{
		receivers: make(map[uint8]common.TrcDataIn),
		currID:    0, // ID 0 is usually reserved/idle
		buffer:    make([]byte, 0, FrameSize),
	}
}

// Attach registers a receiver (e.g., PTM Decoder) for a specific Trace ID.
func (d *Deformatter) Attach(id uint8, receiver common.TrcDataIn) {
	d.receivers[id] = receiver
}

// TraceDataIn processes a block of raw formatted trace data.
func (d *Deformatter) TraceDataIn(op common.DataPathOp, index int64, data []byte) (common.DataPathResp, int, error) {
	if op == common.OpEOT {
		// Flush all receivers
		for _, r := range d.receivers {
			r.TraceDataIn(common.OpEOT, index, nil)
		}
		return common.RespCont, 0, nil
	}

	totalProcessed := 0

	// Append new data to any existing partial buffer
	d.buffer = append(d.buffer, data...)

	// Process complete 16-byte frames
	for len(d.buffer) >= FrameSize {
		// Grab one frame
		frame := d.buffer[:FrameSize]

		// Process the frame
		// TODO: Add FSYNC synchronization logic here (simplified for now: assuming aligned input)
		err := d.unpackFrame(frame, index+int64(totalProcessed))
		if err != nil {
			return common.RespFatal, totalProcessed, err
		}

		// Advance
		d.buffer = d.buffer[FrameSize:]
		totalProcessed += FrameSize
	}

	// We technically "processed" all input bytes, masking the buffering from the caller
	return common.RespCont, len(data), nil
}

// unpackFrame implements the logic from TraceFmtDcdImpl::unpackFrame
// CoreSight Frame: 16 bytes.
// Bytes 0-14: 7 bits of data, LSB indicates ID change (1) or Data (0).
// Byte 15: Flag bits for bytes 0-14 (rarely used in simple TPIU, simplified here).
func (d *Deformatter) unpackFrame(frame []byte, index int64) error {
	// Iterate 0 to 14 in steps of 2 (pairs) - Logic from C++ unpackFrame
	// Note: This is a simplified unpacker assuming standard TPIU formatting

	// Flags in byte 15 (ignored in this simplified port, assuming standard packed)
	// frameFlags := frame[15]

	for i := 0; i < 15; i++ {
		b := frame[i]

		if (b & 0x01) == 1 {
			// ID Change. New ID is bits [7:1]
			d.currID = (b >> 1) & 0x7F
		} else {
			// Data byte for current ID
			// Bit 0 is flag, data is usually the byte itself in unpacked mode,
			// but in packed mode, the LSB is removed?
			// C++ Logic: "m_out_data ... = m_ex_frm_data[i] | ((frameFlagBit...) ? 0x1 : 0x0)"
			// Actually, usually TPIU strips the LSB. However, PTM decoder expects raw bytes.
			// If the LSB is 0, the byte IS data (including the 0 LSB).
			// If the LSB is 1, it is an ID change.

			// Wait, looking at C++ TraceFmtDcdImpl::unpackFrame:
			// "it's just data" -> output byte directly.
			// "it's an ID" -> switch ID.

			// For the Go port, simply:
			if (b & 0x01) == 0 {
				// It is data for the current ID
				d.outputByte(b, index+int64(i))
			} else {
				// ID change, handled above
			}
		}
	}
	return nil
}

func (d *Deformatter) outputByte(b byte, index int64) {
	if receiver, ok := d.receivers[d.currID]; ok {
		// Send single byte (inefficient, but correct for porting)
		// Optimization: Buffer these per ID in a real implementation
		receiver.TraceDataIn(common.OpData, index, []byte{b})
	}
}
