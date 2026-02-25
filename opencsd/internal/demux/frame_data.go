package demux

import (
	"encoding/binary"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// Sync points
func (d *FrameDeformatter) checkForSync(dataBlockSize uint32) bool {
	var unsyncedBytes uint32

	if !d.frameSynced {
		if d.useForceSync {
			if ocsd.TrcIndex(d.forceSyncIdx) >= d.trcCurrIdx && ocsd.TrcIndex(d.forceSyncIdx) < (d.trcCurrIdx+ocsd.TrcIndex(dataBlockSize)) {
				unsyncedBytes = d.forceSyncIdx - uint32(d.trcCurrIdx)
				d.frameSynced = true
			} else {
				unsyncedBytes = dataBlockSize
			}
		} else if d.cfgFlags&ocsd.DfrmtrHasFsyncs != 0 {
			unsyncedBytes = d.findfirstFSync(dataBlockSize)
		} else {
			d.frameSynced = true
		}

		if unsyncedBytes > 0 {
			d.outputUnsyncedBytes(unsyncedBytes)
			d.inBlockProcessed = unsyncedBytes
			d.trcCurrIdx += ocsd.TrcIndex(unsyncedBytes)
		}
	}
	return d.frameSynced
}

func (d *FrameDeformatter) findfirstFSync(dataBlockSize uint32) uint32 {
	var processed uint32
	const FSYNC_PATTERN uint32 = 0x7FFFFFFF

	for processed+3 < dataBlockSize {
		val := binary.LittleEndian.Uint32(d.inBlockBase[processed:])
		if val == FSYNC_PATTERN {
			d.frameSynced = true
			break
		}
		processed++
	}
	return processed
}

func (d *FrameDeformatter) outputUnsyncedBytes(numBytes uint32) {
	// Not implemented in C++ lib
}

func (d *FrameDeformatter) checkForResetFSyncPatterns(fSyncBytes *uint32, dataBlockSize uint32) ocsd.Err {
	const FSYNC_PATTERN uint32 = 0x7FFFFFFF
	checkForFsync := true
	numFsyncs := 0
	bytesProcessed := d.inBlockProcessed
	err := ocsd.OK

	for checkForFsync && (bytesProcessed < dataBlockSize) {
		if bytesProcessed+3 < dataBlockSize && binary.LittleEndian.Uint32(d.inBlockBase[bytesProcessed:]) == FSYNC_PATTERN {
			numFsyncs++
			bytesProcessed += 4
		} else {
			checkForFsync = false
		}
	}

	if numFsyncs > 0 {
		if numFsyncs%4 == 0 {
			d.executeNoneDataOpAllIDs(ocsd.OpReset, d.trcCurrIdx)
			d.currSrcID = ocsd.BadCSSrcID
			d.exFrmNBytes = 0
			d.trcCurrIdxSof = ocsd.BadTrcIndex
		} else {
			err = ocsd.ErrDfrmtrBadFhsync
		}
	}
	*fSyncBytes += uint32(numFsyncs * 4)
	return err
}

func (d *FrameDeformatter) extractFrame(dataBlockSize uint32) bool {
	const FSYNC_PATTERN uint32 = 0x7FFFFFFF
	const HSYNC_PATTERN uint16 = 0x7FFF
	const FSYNC_START uint16 = 0xFFFF

	var err ocsd.Err
	var fSyncBytes, hSyncBytes, exBytes uint32
	bufLeft := dataBlockSize - d.inBlockProcessed

	if bufLeft == 0 {
		return false
	}

	if d.cfgFlags&ocsd.DfrmtrFrameMemAlign != 0 {
		if d.cfgFlags&ocsd.DfrmtrResetOn4xFsync != 0 {
			err = d.checkForResetFSyncPatterns(&fSyncBytes, dataBlockSize)

			if fSyncBytes > 0 && (d.outPackedRaw || d.outUnpackedRaw) {
				d.outputRawMonBytes(ocsd.OpData, d.trcCurrIdx, ocsd.FrmFsync, d.inBlockBase[d.inBlockProcessed:d.inBlockProcessed+fSyncBytes], 0)
			}
			if err != ocsd.OK {
				panic(common.NewErrorWithIdxMsg(ocsd.ErrSevError, err, d.trcCurrIdx, "Incorrect FSYNC frame reset pattern"))
			}
			bufLeft -= fSyncBytes
		}

		if bufLeft > 0 {
			d.exFrmNBytes = ocsd.DfrmtrFrameSize
			copy(d.exFrmData[:], d.inBlockBase[d.inBlockProcessed+fSyncBytes:d.inBlockProcessed+fSyncBytes+ocsd.DfrmtrFrameSize])
			d.trcCurrIdxSof = d.trcCurrIdx + ocsd.TrcIndex(fSyncBytes)
			exBytes = ocsd.DfrmtrFrameSize
		}
	} else {
		hasFSyncs := (d.cfgFlags & ocsd.DfrmtrHasFsyncs) != 0
		hasHSyncs := (d.cfgFlags & ocsd.DfrmtrHasHsyncs) != 0

		dataPtrIdx := d.inBlockProcessed

		if hasFSyncs && d.exFrmNBytes == 0 {
			if d.bFsyncStartEob {
				if bufLeft >= 2 && binary.LittleEndian.Uint16(d.inBlockBase[dataPtrIdx:]) != HSYNC_PATTERN {
					panic(common.NewErrorWithIdxMsg(ocsd.ErrSevError, ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx, "Bad FSYNC pattern before frame or invalid ID.(0x7F)"))
				} else if bufLeft >= 2 {
					fSyncBytes += 2
					bufLeft -= 2
					dataPtrIdx += 2
				}
				d.bFsyncStartEob = false
			}

			for bufLeft >= 4 && binary.LittleEndian.Uint32(d.inBlockBase[dataPtrIdx:]) == FSYNC_PATTERN {
				fSyncBytes += 4
				dataPtrIdx += 4
				bufLeft -= 4
			}

			if bufLeft == 2 {
				if binary.LittleEndian.Uint16(d.inBlockBase[dataPtrIdx:]) == FSYNC_START {
					fSyncBytes += 2
					bufLeft -= 2
					dataPtrIdx += 2
					d.bFsyncStartEob = true
				}
			}
		}

		for d.exFrmNBytes < ocsd.DfrmtrFrameSize && bufLeft > 0 {
			if d.exFrmNBytes == 0 {
				d.trcCurrIdxSof = d.trcCurrIdx + ocsd.TrcIndex(fSyncBytes)
			}

			d.exFrmData[d.exFrmNBytes] = d.inBlockBase[dataPtrIdx]
			d.exFrmData[d.exFrmNBytes+1] = d.inBlockBase[dataPtrIdx+1]

			dataPairVal := binary.LittleEndian.Uint16(d.inBlockBase[dataPtrIdx:])

			if dataPairVal == HSYNC_PATTERN {
				if hasHSyncs {
					hSyncBytes += 2
				} else {
					panic(common.NewErrorWithIdxMsg(ocsd.ErrSevError, ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx, "Bad HSYNC in frame."))
				}
			} else if dataPairVal == FSYNC_START {
				panic(common.NewErrorWithIdxMsg(ocsd.ErrSevError, ocsd.ErrDfrmtrBadFhsync, d.trcCurrIdx, "Bad FSYNC start in frame or invalid ID (0x7F)."))
			} else {
				d.exFrmNBytes += 2
				exBytes += 2
			}

			bufLeft -= 2
			dataPtrIdx += 2
		}
	}

	totalProcessed := exBytes + fSyncBytes + hSyncBytes

	if (d.exFrmNBytes == ocsd.DfrmtrFrameSize || bufLeft == 0) && d.outPackedRaw {
		d.outputRawMonBytes(ocsd.OpData, d.trcCurrIdx, ocsd.FrmPacked, d.inBlockBase[d.inBlockProcessed:d.inBlockProcessed+totalProcessed], 0)
	}

	d.inBlockProcessed += totalProcessed
	d.trcCurrIdx += ocsd.TrcIndex(totalProcessed)

	// In C++ it updates stats here, omitted for this Go port since DemuxStats isn't passed around yet

	return d.exFrmNBytes == ocsd.DfrmtrFrameSize
}

func (d *FrameDeformatter) unpackFrame() bool {
	frameFlagBit := uint8(0x1)
	newSrcID := ocsd.BadCSSrcID
	prevIDandIDChange := false

	d.outDataIdx = 0
	d.outProcessed = 0

	d.outData[d.outDataIdx].id = d.currSrcID
	d.outData[d.outDataIdx].valid = 0
	d.outData[d.outDataIdx].index = d.trcCurrIdxSof
	d.outData[d.outDataIdx].used = 0

	for i := 0; i < 14; i += 2 {
		prevIDandIDChange = false

		if d.exFrmData[i]&0x1 != 0 {
			newSrcID = (d.exFrmData[i] >> 1) & 0x7F
			if newSrcID != d.currSrcID {
				prevIDandIDChange = (frameFlagBit & d.exFrmData[15]) != 0

				if prevIDandIDChange {
					d.outData[d.outDataIdx].data[d.outData[d.outDataIdx].valid] = d.exFrmData[i+1]
					d.outData[d.outDataIdx].valid++
				}

				d.currSrcID = newSrcID

				if d.outData[d.outDataIdx].valid > 0 {
					d.outDataIdx++
					d.outData[d.outDataIdx].valid = 0
					d.outData[d.outDataIdx].used = 0
					d.outData[d.outDataIdx].index = d.trcCurrIdxSof + ocsd.TrcIndex(i)
				}

				d.outData[d.outDataIdx].id = d.currSrcID
			}
		} else {
			b := d.exFrmData[i]
			if (frameFlagBit & d.exFrmData[15]) != 0 {
				b |= 0x1
			}
			d.outData[d.outDataIdx].data[d.outData[d.outDataIdx].valid] = b
			d.outData[d.outDataIdx].valid++
		}

		if !prevIDandIDChange {
			d.outData[d.outDataIdx].data[d.outData[d.outDataIdx].valid] = d.exFrmData[i+1]
			d.outData[d.outDataIdx].valid++
		}

		frameFlagBit <<= 1
	}

	if d.exFrmData[14]&0x1 != 0 {
		d.currSrcID = (d.exFrmData[14] >> 1) & 0x7F
	} else {
		b := d.exFrmData[14]
		if (frameFlagBit & d.exFrmData[15]) != 0 {
			b |= 0x1
		}
		d.outData[d.outDataIdx].data[d.outData[d.outDataIdx].valid] = b
		d.outData[d.outDataIdx].valid++
	}
	d.exFrmNBytes = 0

	return true
}

func (d *FrameDeformatter) outputFrame() bool {
	contProcessing := true

	for d.outProcessed < (d.outDataIdx+1) && contProcessing {
		id := d.outData[d.outProcessed].id
		if id != ocsd.BadCSSrcID {
			pDataIn := d.idStreams[id]
			if pDataIn != nil {
				if d.outUnpackedRaw && d.outData[d.outProcessed].used == 0 && d.rawChanEnabled(id) {
					d.outputRawMonBytes(ocsd.OpData,
						d.outData[d.outProcessed].index,
						ocsd.FrmIDData,
						d.outData[d.outProcessed].data[:d.outData[d.outProcessed].valid],
						id)
				}
				bytesUsed, resp := pDataIn.TraceDataIn(ocsd.OpData,
					d.outData[d.outProcessed].index+ocsd.TrcIndex(d.outData[d.outProcessed].used),
					d.outData[d.outProcessed].data[d.outData[d.outProcessed].used:d.outData[d.outProcessed].valid])

				d.collateDataPathResp(resp)

				if !d.dataPathCont() {
					contProcessing = false
					d.outData[d.outProcessed].used += bytesUsed
					if d.outData[d.outProcessed].used == d.outData[d.outProcessed].valid {
						d.outProcessed++
					}
				} else {
					d.outProcessed++
				}
			} else {
				if d.outUnpackedRaw && d.rawChanEnabled(id) {
					d.outputRawMonBytes(ocsd.OpData,
						d.outData[d.outProcessed].index,
						ocsd.FrmIDData,
						d.outData[d.outProcessed].data[:d.outData[d.outProcessed].valid],
						id)
				}
				d.outProcessed++
			}
		} else {
			if d.outUnpackedRaw {
				d.outputRawMonBytes(ocsd.OpData,
					d.outData[d.outProcessed].index,
					ocsd.FrmIDData,
					d.outData[d.outProcessed].data[:d.outData[d.outProcessed].valid],
					id)
			}
			d.outProcessed++
		}
	}
	return contProcessing
}
