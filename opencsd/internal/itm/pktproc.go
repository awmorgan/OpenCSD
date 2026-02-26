package itm

import (
	"fmt"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type processState int

const (
	procWaitSync processState = iota
	procHdr
	procData
	procSendPkt
)

// PktProc converts incoming byte stream into ITM packets
type PktProc struct {
	common.PktProcBase[Packet, PktType, Config]

	procState processState

	currPacket  Packet
	bStreamSync bool
	dataIn      []byte
	dataInSize  uint32
	dataInUsed  uint32
	packetIndex ocsd.TrcIndex

	headerByte        uint8
	packetData        []uint8
	sentNotSyncPacket bool
	syncStart         bool
	dumpUnsyncedBytes int

	currPktFn func()
}

// NewPktProc creates a new ITM packet processor.
func NewPktProc(instID int) *PktProc {
	p := &PktProc{}
	p.InitPktProcBase("PKTP_ITM") // name
	p.FnProcessData = p.processData
	p.FnOnEOT = p.onEOT
	p.FnOnReset = p.onReset
	p.FnOnFlush = p.onFlush
	p.FnOnProtocolConfig = p.onProtocolConfig
	p.FnIsBadPacket = p.isBadPacket

	p.SetSupportedOpModes(ocsd.OpflgPktprocCommon)
	p.initProcessorState()
	return p
}

func (p *PktProc) initProcessorState() {
	p.setProcUnsynced()
	p.initNextPacket()
	p.sentNotSyncPacket = false
	p.syncStart = false
	p.dumpUnsyncedBytes = 0
}

func (p *PktProc) initNextPacket() {
	p.packetData = p.packetData[:0] // clear
	p.currPacket.InitPacket()
}

func (p *PktProc) setProcUnsynced() {
	p.procState = procWaitSync
	p.bStreamSync = false
}

func (p *PktProc) dataToProcess() bool {
	return (p.dataInUsed < p.dataInSize) || (p.procState == procSendPkt)
}

func (p *PktProc) processData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
	resp := ocsd.RespCont
	p.dataIn = dataBlock
	p.dataInSize = uint32(len(dataBlock))
	p.dataInUsed = 0

	for p.dataToProcess() && ocsd.DataRespIsCont(resp) {
		errResp, handled := p.processStateLoop(index)
		if handled {
			resp = errResp
			if ocsd.DataRespIsFatal(resp) {
				break
			}
		}
	}
	return p.dataInUsed, resp
}

func (p *PktProc) processStateLoop(index ocsd.TrcIndex) (resp ocsd.DatapathResp, handled bool) {
	resp = ocsd.RespCont
	handled = false

	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(*common.Error); ok {
				p.LogError(e)
				if (e.Code == ocsd.ErrBadPacketSeq || e.Code == ocsd.ErrInvalidPcktHdr) &&
					(p.ComponentOpMode()&ocsd.OpflgPktprocErrBadPkts) == 0 {
					resp = p.outputPacket()
					if (p.ComponentOpMode() & ocsd.OpflgPktprocUnsyncOnBadPkts) != 0 {
						p.procState = procWaitSync
					}
				} else {
					resp = ocsd.RespFatalInvalidData
				}
			} else {
				resp = ocsd.RespFatalSysErr
				fatal := common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrFail, p.packetIndex, p.traceID(), fmt.Sprintf("Unknown System Error decoding trace: %v", r))
				p.LogError(fatal)
			}
			handled = true
		}
	}()

	switch p.procState {
	case procWaitSync:
		resp = p.waitForSync(index)
		handled = true
	case procHdr:
		p.packetIndex = index + ocsd.TrcIndex(p.dataInUsed)
		p.itmProcessHdr() // will set to PROC_DATA or SEND_PKT on valid header.
		if p.procState != procData {
			break
		}
		fallthrough
	case procData:
		if p.currPktFn != nil {
			p.currPktFn()
		}
		if p.procState != procSendPkt {
			break
		}
		fallthrough
	case procSendPkt:
		resp = p.outputPacket()
		handled = true
	}
	return resp, handled
}

func (p *PktProc) traceID() uint8 {
	if p.Config != nil {
		return p.Config.TraceID()
	}
	return 0
}

func (p *PktProc) onEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if p.procState == procData {
		p.currPacket.UpdateErrType(PktIncompleteEOT)
		resp = p.outputPacket()
	}
	return resp
}

func (p *PktProc) onReset() ocsd.DatapathResp {
	p.initProcessorState()
	return ocsd.RespCont
}

func (p *PktProc) onFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (p *PktProc) onProtocolConfig() ocsd.Err {
	return ocsd.OK
}

func (p *PktProc) isBadPacket() bool {
	return p.currPacket.IsBadPacket()
}

func (p *PktProc) outputPacket() ocsd.DatapathResp {
	resp := p.OutputOnAllInterfaces(p.packetIndex, &p.currPacket, p.currPacket.Type, p.packetData)
	p.packetData = p.packetData[:0]
	p.initNextPacket()
	if p.bStreamSync {
		p.procState = procHdr
	} else {
		p.procState = procWaitSync
	}
	return resp
}

func (p *PktProc) throwBadSequenceError(msg string) {
	p.currPacket.UpdateErrType(PktBadSequence)
	err := common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, p.packetIndex, p.traceID(), msg)
	panic(err)
}

func (p *PktProc) throwReservedHdrError(msg string) {
	p.currPacket.SetPacketType(PktReserved)
	err := common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrInvalidPcktHdr, p.packetIndex, p.traceID(), msg)
	panic(err)
}

func (p *PktProc) savePacketByte(val byte) {
	p.packetData = append(p.packetData, val)
}

func (p *PktProc) readByte() (byte, bool) {
	if p.dataInUsed < p.dataInSize {
		b := p.dataIn[p.dataInUsed]
		p.dataInUsed++
		p.savePacketByte(b)
		return b, true
	}
	return 0, false
}

func (p *PktProc) itmProcessHdr() {
	b, ok := p.readByte()
	if !ok {
		return
	}
	p.headerByte = b

	if (b & 0x03) != 0x00 { // Stimulus packets
		if (b & 0x4) != 0 {
			p.currPacket.SetPacketType(PktDWT)
		} else {
			p.currPacket.SetPacketType(PktSWIT)
		}
		p.currPktFn = p.itmPktData
		p.procState = procData
	} else if (b & 0x0F) == 0x00 {
		if (b & 0xF0) == 0x00 {
			p.currPacket.SetPacketType(PktAsync)
			p.currPktFn = p.itmPktAsync
			p.procState = procData
		} else if (b & 0xF0) == 0x70 {
			p.currPacket.SetPacketType(PktOverflow)
			p.procState = procSendPkt
		} else {
			p.currPacket.SetPacketType(PktTSLocal)
			p.currPktFn = p.itmPktLocalTS
			p.procState = procData
		}
	} else if (b & 0x0B) == 0x08 {
		p.currPacket.SetPacketType(PktExtension)
		p.currPktFn = p.itmPktExtension
		p.procState = procData
	} else if (b & 0xDF) == 0x94 {
		if (b & 0x20) == 0x00 {
			p.currPacket.SetPacketType(PktTSGlobal1)
			p.currPktFn = p.itmPktGlobalTS1
		} else {
			p.currPacket.SetPacketType(PktTSGlobal2)
			p.currPktFn = p.itmPktGlobalTS2
		}
		p.procState = procData
	} else {
		p.throwReservedHdrError("")
	}
}

func (p *PktProc) itmPktData() {
	payloadBytesReq := int(p.headerByte & 0x3)
	payloadBytesGot := len(p.packetData) - 1

	if payloadBytesReq == 3 {
		payloadBytesReq = 4
	}

	if len(p.packetData) == 1 {
		p.currPacket.SetSrcID((p.headerByte >> 3) & 0x1F)
	}

	for payloadBytesGot < payloadBytesReq {
		if _, ok := p.readByte(); !ok {
			break
		}
		payloadBytesGot++
	}

	if payloadBytesGot == payloadBytesReq {
		var value uint32 = uint32(p.packetData[1])
		if payloadBytesReq >= 2 {
			value |= (uint32(p.packetData[2]) << 8)
		}
		if payloadBytesReq == 4 {
			value |= (uint32(p.packetData[3]) << 16)
			value |= (uint32(p.packetData[4]) << 24)
		}
		p.currPacket.SetValue(value, uint8(payloadBytesReq))
		p.procState = procSendPkt
	}
}

func (p *PktProc) readContBytes(limit int) bool {
	bDone := false
	for !bDone && len(p.packetData) < limit {
		b, ok := p.readByte()
		if !ok {
			break
		}
		bDone = ((b & 0x80) == 0x00)
	}
	return bDone
}

func (p *PktProc) extractContVal32() uint32 {
	var value uint32 = 0
	shift := 0
	idxMax := len(p.packetData) - 1

	for idx := 1; idx <= idxMax; idx++ {
		value |= (uint32(p.packetData[idx]&0x7F) << shift)
		shift += 7
	}
	return value
}

func (p *PktProc) extractContVal64() uint64 {
	var value uint64 = 0
	shift := 0
	idxMax := len(p.packetData) - 1

	for idx := 1; idx <= idxMax; idx++ {
		value |= (uint64(p.packetData[idx]&0x7F) << shift)
		shift += 7
	}
	return value
}

func (p *PktProc) itmPktLocalTS() {
	const pktSizeLimit = 5
	bGotContVal := false

	if len(p.packetData) == 1 {
		if (p.headerByte & 0x80) != 0 {
			p.currPacket.SetSrcID((p.headerByte >> 4) & 0x3)
		} else {
			p.currPacket.SetSrcID(0)
			p.currPacket.SetValue(uint32((p.headerByte>>4)&0x7), 1)
			p.procState = procSendPkt
			return
		}
	}

	bGotContVal = p.readContBytes(pktSizeLimit)

	if bGotContVal {
		p.currPacket.SetValue(p.extractContVal32(), uint8(len(p.packetData)-1))
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		p.throwBadSequenceError("Local TS packet: Payload continuation value too long")
	}
}

func (p *PktProc) itmPktGlobalTS1() {
	const pktSizeLimit = 5
	bGotContVal := p.readContBytes(pktSizeLimit)

	if bGotContVal {
		if len(p.packetData) == 5 {
			b := p.packetData[4]
			p.currPacket.SetSrcID((b >> 5) & 0x3)
			p.packetData[4] = b & 0x1F
		}
		p.currPacket.SetValue(p.extractContVal32(), uint8(len(p.packetData)-1))
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		p.throwBadSequenceError("GTS1 packet: Payload continuation value too long")
	}
}

func (p *PktProc) itmPktGlobalTS2() {
	const pktSizeLimit = 7
	bGotContVal := p.readContBytes(pktSizeLimit)

	if bGotContVal {
		if len(p.packetData) <= 5 {
			p.currPacket.SetValue(p.extractContVal32(), uint8(len(p.packetData)-1))
		} else {
			p.currPacket.SetExtValue(p.extractContVal64())
		}
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		p.throwBadSequenceError("GTS2 packet: Payload continuation value too long")
	}
}

func (p *PktProc) itmPktExtension() {
	const pktSizeLimit = 5
	nBitLength := []uint8{2, 9, 16, 23, 31}
	bGotContVal := false

	if (p.headerByte & 0x80) == 0 {
		bGotContVal = true
	} else {
		bGotContVal = p.readContBytes(pktSizeLimit)
	}

	if bGotContVal {
		srcIdVal := nBitLength[len(p.packetData)-1]
		if (p.headerByte & 0x4) != 0 {
			srcIdVal |= 0x80
		}
		p.currPacket.SetSrcID(srcIdVal)

		value := uint32(0)
		if len(p.packetData) > 1 {
			value = p.extractContVal32()
			value <<= 3
		}
		value |= uint32((p.headerByte >> 4) & 0x7)
		p.currPacket.SetValue(value, 4)
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		p.throwBadSequenceError("Extension packet: Payload continuation value too long")
	}
}

func (p *PktProc) readAsyncSeq() (bFoundAsync bool, bError bool) {
	bError = false
	bFoundAsync = false

	for len(p.packetData) < 5 && !bError {
		b, ok := p.readByte()
		if !ok {
			break
		}
		if b != 0x00 {
			bError = true
		}
	}

	for !bFoundAsync && !bError {
		b, ok := p.readByte()
		if !ok {
			break
		}
		if b == 0x80 {
			bFoundAsync = true
		} else if b != 0x00 {
			bError = true
		}
	}
	return bFoundAsync, bError
}

func (p *PktProc) itmPktAsync() {
	bFoundAsync, bError := p.readAsyncSeq()
	if bFoundAsync {
		p.procState = procSendPkt
	} else if bError {
		p.throwBadSequenceError("Async Packet: unexpected none zero value")
	}
}

func (p *PktProc) flushUnsyncedBytes() ocsd.DatapathResp {
	resp := ocsd.RespCont

	p.OutputRawPacketToMonitor(p.packetIndex, &p.currPacket, p.packetData[:p.dumpUnsyncedBytes])

	if !p.sentNotSyncPacket {
		resp = p.OutputDecodedPacket(p.packetIndex, &p.currPacket)
		p.sentNotSyncPacket = true
	}

	if len(p.packetData) <= p.dumpUnsyncedBytes {
		p.packetData = p.packetData[:0]
	} else {
		// remove dumped bytes
		p.packetData = p.packetData[p.dumpUnsyncedBytes:]
	}
	p.dumpUnsyncedBytes = 0

	return resp
}

func (p *PktProc) waitForSync(blkStIndex ocsd.TrcIndex) ocsd.DatapathResp {
	resp := ocsd.RespCont
	p.currPacket.SetPacketType(PktNotSync)
	p.dumpUnsyncedBytes = 0

	if !p.syncStart {
		p.packetIndex = blkStIndex + ocsd.TrcIndex(p.dataInUsed)
	}

	for !p.bStreamSync && p.dataToProcess() && ocsd.DataRespIsCont(resp) {
		if p.syncStart {
			bFoundAsync, bAsyncErr := p.readAsyncSeq()
			p.bStreamSync = bFoundAsync
			if p.bStreamSync {
				p.currPacket.SetPacketType(PktAsync)
				p.procState = procSendPkt
			} else if bAsyncErr {
				p.dumpUnsyncedBytes = len(p.packetData)
				p.syncStart = false
			}
		}

		if !p.syncStart {
			b, ok := p.readByte()
			if !ok {
				break
			}

			if b == 0x00 {
				p.syncStart = true
				resp = p.flushUnsyncedBytes()
				p.packetIndex = blkStIndex + ocsd.TrcIndex(p.dataInUsed) - 1
			} else {
				p.dumpUnsyncedBytes++
				if p.dumpUnsyncedBytes >= 8 {
					resp = p.flushUnsyncedBytes()
				}
			}
		}
	}

	if !p.bStreamSync && !p.syncStart && p.dumpUnsyncedBytes > 0 {
		resp = p.flushUnsyncedBytes()
	}

	return resp
}
