package demux

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"opencsd/internal/ocsd"
)

const (
	fSyncPattern uint32 = 0x7FFFFFFF
	hSyncPattern uint16 = 0x7FFF
	fSyncStart   uint16 = 0xFFFF
)

var fSyncPatternBytes = []byte{0xff, 0xff, 0xff, 0x7f}

// Sync points
func (d *FrameDeformatter) checkForSync(dataBlockSize uint32) bool {
	if d.frameSynced {
		return true
	}

	unsyncedBytes := d.unsyncedPrefixLen(dataBlockSize)
	if unsyncedBytes > 0 {
		d.outputUnsyncedBytes(unsyncedBytes)
		d.inBlockProcessed = unsyncedBytes
		d.trcCurrIdx += ocsd.TrcIndex(unsyncedBytes)
	}
	return d.frameSynced
}

func (d *FrameDeformatter) unsyncedPrefixLen(dataBlockSize uint32) uint32 {
	switch {
	case d.useForceSync:
		return d.unsyncedPrefixLenForForcedSync(dataBlockSize)
	case d.cfgFlags&ocsd.DfrmtrHasFsyncs != 0:
		return d.findfirstFSync(dataBlockSize)
	default:
		d.frameSynced = true
		return 0
	}
}

func (d *FrameDeformatter) unsyncedPrefixLenForForcedSync(dataBlockSize uint32) uint32 {
	start := d.trcCurrIdx
	end := start + ocsd.TrcIndex(dataBlockSize)
	forceSyncIdx := ocsd.TrcIndex(d.forceSyncIdx)
	if forceSyncIdx >= start && forceSyncIdx < end {
		d.frameSynced = true
		return d.forceSyncIdx - uint32(start)
	}
	return dataBlockSize
}

func (d *FrameDeformatter) findfirstFSync(dataBlockSize uint32) uint32 {
	if dataBlockSize < uint32(len(fSyncPatternBytes)) {
		return dataBlockSize
	}

	idx := bytes.Index(d.inBlockBase[:int(dataBlockSize)], fSyncPatternBytes)
	if idx >= 0 {
		d.frameSynced = true
		return uint32(idx)
	}
	return dataBlockSize - uint32(len(fSyncPatternBytes)-1)
}

func (d *FrameDeformatter) outputUnsyncedBytes(numBytes uint32) {
	// Not implemented in C++ lib
}

func (d *FrameDeformatter) checkForResetFSyncPatterns(dataBlockSize uint32) (uint32, error) {
	numFsyncs := d.countLeadingFSyncs(dataBlockSize)
	if numFsyncs == 0 {
		return 0, nil
	}

	fSyncBytes := uint32(numFsyncs * len(fSyncPatternBytes))
	if numFsyncs%4 != 0 {
		return fSyncBytes, ocsd.ErrDfrmtrBadFhsync
	}

	err := d.resetAllIDs(d.trcCurrIdx)
	d.currSrcID = ocsd.BadCSSrcID
	d.exFrmBytes = 0
	d.trcCurrIdxSof = ocsd.BadTrcIndex
	return fSyncBytes, err
}

func (d *FrameDeformatter) countLeadingFSyncs(dataBlockSize uint32) int {
	count := 0
	bytesProcessed := d.inBlockProcessed

	for bytesProcessed+uint32(len(fSyncPatternBytes)) <= dataBlockSize && binary.LittleEndian.Uint32(d.inBlockBase[bytesProcessed:]) == fSyncPattern {
		count++
		bytesProcessed += uint32(len(fSyncPatternBytes))
	}
	return count
}

func (d *FrameDeformatter) extractFrame(dataBlockSize uint32) (bool, error) {
	bufLeft := dataBlockSize - d.inBlockProcessed
	if bufLeft == 0 {
		return false, nil
	}

	var (
		totalProcessed uint32
		err            error
	)
	if d.cfgFlags&ocsd.DfrmtrFrameMemAlign != 0 {
		totalProcessed, bufLeft, err = d.extractAlignedFrame(dataBlockSize, bufLeft)
	} else {
		totalProcessed, bufLeft, err = d.extractUnalignedFrame(bufLeft)
	}
	if err != nil {
		return false, err
	}

	if (d.exFrmBytes == ocsd.DfrmtrFrameSize || bufLeft == 0) && d.outPackedRaw {
		d.outputRawMonBytes(d.trcCurrIdx, ocsd.FrmPacked, d.inBlockBase[d.inBlockProcessed:d.inBlockProcessed+totalProcessed], 0)
	}

	d.advanceInput(totalProcessed)

	// In C++ it updates stats here, omitted for this Go port since DemuxStats isn't passed around yet
	return d.exFrmBytes == ocsd.DfrmtrFrameSize, nil
}

func (d *FrameDeformatter) extractAlignedFrame(dataBlockSize, bufLeft uint32) (totalProcessed, remaining uint32, err error) {
	fSyncBytes := uint32(0)
	if d.cfgFlags&ocsd.DfrmtrResetOn4xFsync != 0 {
		fSyncBytes, err = d.consumeResetFSyncs(dataBlockSize)
		if err != nil {
			return 0, bufLeft, err
		}
		bufLeft -= fSyncBytes
	}

	if bufLeft == 0 {
		return fSyncBytes, bufLeft, nil
	}
	if bufLeft < ocsd.DfrmtrFrameSize {
		return 0, bufLeft, fmt.Errorf("%w: Insufficient bytes for aligned frame at index %d", ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx)
	}

	start := d.inBlockProcessed + fSyncBytes
	copy(d.exFrmData, d.inBlockBase[start:start+ocsd.DfrmtrFrameSize])
	d.exFrmBytes = ocsd.DfrmtrFrameSize
	d.trcCurrIdxSof = d.trcCurrIdx + ocsd.TrcIndex(fSyncBytes)
	return fSyncBytes + ocsd.DfrmtrFrameSize, bufLeft, nil
}

func (d *FrameDeformatter) consumeResetFSyncs(dataBlockSize uint32) (uint32, error) {
	fSyncBytes, err := d.checkForResetFSyncPatterns(dataBlockSize)
	if fSyncBytes > 0 && (d.outPackedRaw || d.outUnpackedRaw) {
		d.outputRawMonBytes(d.trcCurrIdx, ocsd.FrmFsync, d.inBlockBase[d.inBlockProcessed:d.inBlockProcessed+fSyncBytes], 0)
	}
	if err == nil {
		return fSyncBytes, nil
	}
	if err == ocsd.ErrDfrmtrBadFhsync {
		return fSyncBytes, fmt.Errorf("%w: Incorrect FSYNC frame reset pattern at index %d", err, d.trcCurrIdx)
	}
	return fSyncBytes, err
}

func (d *FrameDeformatter) extractUnalignedFrame(bufLeft uint32) (totalProcessed, remaining uint32, err error) {
	var fSyncBytes, hSyncBytes, exBytes uint32
	hasFSyncs := d.cfgFlags&ocsd.DfrmtrHasFsyncs != 0
	hasHSyncs := d.cfgFlags&ocsd.DfrmtrHasHsyncs != 0
	dataPtrIdx := d.inBlockProcessed

	if hasFSyncs && d.exFrmBytes == 0 {
		bufLeft, dataPtrIdx, fSyncBytes, err = d.consumeLeadingUnalignedFSyncs(bufLeft, dataPtrIdx)
		if err != nil {
			return 0, bufLeft, err
		}
	}

	for d.exFrmBytes < ocsd.DfrmtrFrameSize && bufLeft >= 2 {
		if d.exFrmBytes == 0 {
			d.trcCurrIdxSof = d.trcCurrIdx + ocsd.TrcIndex(fSyncBytes)
		}

		pair := binary.LittleEndian.Uint16(d.inBlockBase[dataPtrIdx:])
		switch pair {
		case hSyncPattern:
			if !hasHSyncs {
				return 0, bufLeft, fmt.Errorf("%w: Bad HSYNC in frame at index %d", ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx)
			}
			hSyncBytes += 2
		case fSyncStart:
			return 0, bufLeft, fmt.Errorf("%w: Bad FSYNC start in frame or invalid ID (0x7F) at index %d", ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx)
		default:
			d.copyFramePair(dataPtrIdx)
			exBytes += 2
		}

		bufLeft -= 2
		dataPtrIdx += 2
	}

	if bufLeft == 1 {
		return 0, bufLeft, fmt.Errorf("%w: Odd trailing byte in frame stream at index %d", ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx)
	}

	return exBytes + fSyncBytes + hSyncBytes, bufLeft, nil
}

func (d *FrameDeformatter) consumeLeadingUnalignedFSyncs(bufLeft, dataPtrIdx uint32) (uint32, uint32, uint32, error) {
	var fSyncBytes uint32

	if d.fsyncStartEOB {
		if bufLeft >= 2 {
			if binary.LittleEndian.Uint16(d.inBlockBase[dataPtrIdx:]) != hSyncPattern {
				return bufLeft, dataPtrIdx, fSyncBytes, fmt.Errorf("%w: Bad FSYNC pattern before frame or invalid ID.(0x7F) at index %d", ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx)
			}
			fSyncBytes += 2
			bufLeft -= 2
			dataPtrIdx += 2
		}
		d.fsyncStartEOB = false
	}

	for bufLeft >= uint32(len(fSyncPatternBytes)) && binary.LittleEndian.Uint32(d.inBlockBase[dataPtrIdx:]) == fSyncPattern {
		fSyncBytes += uint32(len(fSyncPatternBytes))
		dataPtrIdx += uint32(len(fSyncPatternBytes))
		bufLeft -= uint32(len(fSyncPatternBytes))
	}

	if bufLeft == 2 && binary.LittleEndian.Uint16(d.inBlockBase[dataPtrIdx:]) == fSyncStart {
		fSyncBytes += 2
		bufLeft -= 2
		dataPtrIdx += 2
		d.fsyncStartEOB = true
	}

	return bufLeft, dataPtrIdx, fSyncBytes, nil
}

func (d *FrameDeformatter) copyFramePair(dataPtrIdx uint32) {
	d.exFrmData[d.exFrmBytes] = d.inBlockBase[dataPtrIdx]
	d.exFrmData[d.exFrmBytes+1] = d.inBlockBase[dataPtrIdx+1]
	d.exFrmBytes += 2
}

func (d *FrameDeformatter) advanceInput(numBytes uint32) {
	d.inBlockProcessed += numBytes
	d.trcCurrIdx += ocsd.TrcIndex(numBytes)
}

func (d *FrameDeformatter) unpackFrame() bool {
	d.resetOutputForFrame()

	frameFlagBit := uint8(0x1)
	for i := 0; i < 14; i += 2 {
		prevIDandIDChange := false

		if d.exFrmData[i]&0x1 != 0 {
			prevIDandIDChange = d.handleIDByte(i, frameFlagBit)
		} else {
			d.appendOutputByte(d.dataByteWithFlag(i, frameFlagBit))
		}

		if !prevIDandIDChange {
			d.appendOutputByte(d.exFrmData[i+1])
		}
		frameFlagBit <<= 1
	}

	if d.exFrmData[14]&0x1 != 0 {
		d.currSrcID = (d.exFrmData[14] >> 1) & 0x7F
	} else {
		d.appendOutputByte(d.dataByteWithFlag(14, frameFlagBit))
	}
	d.exFrmBytes = 0
	return true
}

func (d *FrameDeformatter) resetOutputForFrame() {
	d.outData = d.outData[:1]
	d.outProcessed = 0
	d.outData[0].reset(d.currSrcID, d.trcCurrIdxSof)
}

func (d *FrameDeformatter) handleIDByte(i int, frameFlagBit uint8) bool {
	newSrcID := (d.exFrmData[i] >> 1) & 0x7F
	if newSrcID == d.currSrcID {
		return false
	}

	prevIDandIDChange := frameFlagBit&d.exFrmData[15] != 0
	if prevIDandIDChange {
		d.appendOutputByte(d.exFrmData[i+1])
	}

	d.currSrcID = newSrcID
	if d.currentOutput().valid > 0 {
		d.outData = append(d.outData, outDataEntry{})
		d.currentOutput().reset(d.currSrcID, d.trcCurrIdxSof+ocsd.TrcIndex(i))
	} else {
		d.currentOutput().id = d.currSrcID
	}
	return prevIDandIDChange
}

func (d *FrameDeformatter) dataByteWithFlag(i int, frameFlagBit uint8) byte {
	b := d.exFrmData[i]
	if frameFlagBit&d.exFrmData[15] != 0 {
		b |= 0x1
	}
	return b
}

func (d *FrameDeformatter) currentOutput() *outDataEntry {
	return &d.outData[len(d.outData)-1]
}

func (d *FrameDeformatter) appendOutputByte(b byte) {
	d.currentOutput().appendByte(b)
}

func (d *FrameDeformatter) outputFrame(outErr error) (bool, error) {
	for d.outProcessed < uint32(len(d.outData)) {
		entry := &d.outData[d.outProcessed]
		if d.shouldOutputRawEntry(entry) {
			d.outputRawEntry(entry)
		}

		stream := d.outputStream(entry.id)
		if stream == nil {
			d.outProcessed++
			continue
		}

		bytesUsed, err := d.callIDStream(stream, entry.remainingIndex(), entry.remaining())
		if err != nil && outErr == nil {
			outErr = err
		}
		if outErr != nil {
			entry.used += bytesUsed
			if entry.used == entry.valid {
				d.outProcessed++
			}
			return false, outErr
		}
		d.outProcessed++
	}
	return true, outErr
}

func (d *FrameDeformatter) shouldOutputRawEntry(entry *outDataEntry) bool {
	if !d.outUnpackedRaw {
		return false
	}
	if entry.id == ocsd.BadCSSrcID {
		return true
	}
	return d.rawChanEnabled(entry.id) && entry.used == 0
}

func (d *FrameDeformatter) outputRawEntry(entry *outDataEntry) {
	d.outputRawMonBytes(entry.index, ocsd.FrmIDData, entry.bytes(), entry.id)
}

func (d *FrameDeformatter) outputStream(id uint8) ocsd.TraceDecoder {
	if !validTraceID(id) {
		return nil
	}
	return d.idStreams[id]
}
