package stm

import (
	"fmt"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type processState int

const (
	procWaitSync processState = iota
	procHdrState
	procDataState
	procSendPkt
)

// PktProc converts the byte stream into basic STM trace packets.
type PktProc struct {
	common.PktProcBase[Packet, PktType, Config]

	procState processState

	op1N [0x10]func()
	op2N [0x10]func()
	op3N [0x10]func()

	currPktFn func()

	currPacket  Packet
	bNeedsTS    bool
	bIsMarker   bool
	bStreamSync bool

	numNibbles     uint8
	nibble         uint8
	nibble2nd      uint8
	nibble2ndValid bool
	numDataNibbles uint8

	dataIn      []byte
	dataInSize  uint32
	dataInUsed  uint32
	packetIndex ocsd.TrcIndex

	packetData              []byte
	bWaitSyncSaveSuppressed bool

	val8  uint8
	val16 uint16
	val32 uint32
	val64 uint64

	reqTSNibbles  uint8
	currTSNibbles uint8
	tsUpdateValue uint64
	tsReqSet      bool

	numFNibbles uint8
	syncStart   bool
	isSync      bool
	syncIndex   ocsd.TrcIndex
}

// NewPktProc creates a new STM packet processor.
func NewPktProc(instIDNum int) *PktProc {
	p := &PktProc{}
	p.InitPktProcBase(fmt.Sprintf("%s_%d", "PKTP_STM", instIDNum))

	p.FnProcessData = p.processData
	p.FnOnEOT = p.onEOT
	p.FnOnReset = p.onReset
	p.FnOnFlush = p.onFlush
	p.FnOnProtocolConfig = p.onProtocolConfig
	p.FnIsBadPacket = p.isBadPacket

	p.SetSupportedOpModes(ocsd.OpflgPktprocCommon)
	p.initProcessorState()
	p.buildOpTables()
	return p
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
				warn := common.NewErrorMsg(ocsd.ErrSevWarn, ocsd.ErrFail, fmt.Sprintf("Recovered decode panic, forcing resync: %v", r))
				warn.Idx = p.packetIndex
				if p.Config != nil {
					warn.ChanID = p.Config.TraceID()
				}
				p.LogError(warn)
				p.currPacket.SetPacketType(PktNotSync, false)
				p.procState = procWaitSync
				resp = ocsd.RespErrCont
			}
			handled = true
		}
	}()

	switch p.procState {
	case procWaitSync:
		p.waitForSync(index)
	case procHdrState:
		p.packetIndex = index + ocsd.TrcIndex(p.dataInUsed)
		if p.readNibble() {
			p.procState = procDataState
			p.currPktFn = p.op1N[p.nibble]
		} else {
			break
		}
		fallthrough
	case procDataState:
		p.currPktFn()
		if p.procState != procSendPkt {
			break
		}
		fallthrough
	case procSendPkt:
		resp = p.outputPacket()
	}

	return resp, false
}

func (p *PktProc) onEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if p.numNibbles > 0 {
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
	if p.nibble2ndValid {
		p.savePacketByte(p.nibble2nd << 4)
	}
	if p.bStreamSync {
		p.procState = procHdrState
	} else {
		p.procState = procWaitSync
	}
	return resp
}

func (p *PktProc) throwBadSequenceError(msg string) {
	p.currPacket.UpdateErrType(PktBadSequence)
	trcID := uint8(0)
	if p.Config != nil {
		trcID = p.Config.TraceID()
	}
	err := common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, p.packetIndex, trcID, msg)
	panic(err)
}

func (p *PktProc) throwReservedHdrError(msg string) {
	p.currPacket.SetPacketType(PktReserved, false)
	trcID := uint8(0)
	if p.Config != nil {
		trcID = p.Config.TraceID()
	}
	err := common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrInvalidPcktHdr, p.packetIndex, trcID, msg)
	panic(err)
}

func (p *PktProc) initProcessorState() {
	p.setProcUnsynced()
	p.clearSyncCount()
	p.currPacket.InitStartState()
	p.nibble2ndValid = false
	p.initNextPacket()
	p.bWaitSyncSaveSuppressed = false
	p.packetData = nil
}

func (p *PktProc) initNextPacket() {
	p.bNeedsTS = false
	p.bIsMarker = false
	p.numNibbles = 0
	p.numDataNibbles = 0
	p.currPacket.InitNextPacket()
}

func (p *PktProc) waitForSync(blkStIndex ocsd.TrcIndex) {
	bGotData := true
	startOffset := p.dataInUsed

	p.packetIndex = blkStIndex + ocsd.TrcIndex(p.dataInUsed)
	p.numNibbles = p.numFNibbles
	if p.isSync {
		p.numNibbles++
	}

	p.bWaitSyncSaveSuppressed = true
	for bGotData && !p.isSync {
		bGotData = p.readNibble()
	}
	p.bWaitSyncSaveSuppressed = false

	if p.numNibbles == 0 {
		return
	}

	if !bGotData || p.numNibbles > 22 {
		p.currPacket.SetPacketType(PktNotSync, false)
		if p.PktRawMonI.HasAttachedAndEnabled() {
			nibblesToSend := p.numNibbles - p.numFNibbles
			if p.isSync {
				nibblesToSend = p.numNibbles - 22
			}
			bytesToSend := (nibblesToSend / 2) + (nibblesToSend % 2)
			for i := range bytesToSend {
				p.savePacketByte(p.dataIn[startOffset+uint32(i)])
			}
		}
	} else {
		p.currPacket.SetPacketType(PktAsync, false)
		p.bStreamSync = true
		p.clearSyncCount()
		p.packetIndex = p.syncIndex
		if p.PktRawMonI.HasAttachedAndEnabled() {
			for range 10 {
				p.savePacketByte(0xFF)
			}
			p.savePacketByte(0x0F)
		}
	}
	p.sendPacket()
}

func (p *PktProc) stmPktReserved() {
	badOpcode := uint16(p.nibble)
	p.currPacket.SetD16Payload(badOpcode)
	p.throwReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) stmPktNull() {
	p.currPacket.SetPacketType(PktNull, false)
	if p.bNeedsTS {
		p.currPktFn = p.stmExtractTS
		p.currPktFn()
	} else {
		p.sendPacket()
	}
}

func (p *PktProc) stmPktNullTS() {
	p.pktNeedsTS()
	p.currPktFn = p.stmPktNull
	p.currPktFn()
}

func (p *PktProc) stmPktM8() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktM8, false)
	}
	p.stmExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetMaster(p.val8)
		p.sendPacket()
	}
}

func (p *PktProc) stmPktMERR() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktMErr, false)
	}
	p.stmExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetChannel(0, false)
		p.currPacket.SetD8Payload(p.val8)
		p.sendPacket()
	}
}

func (p *PktProc) stmPktC8() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktC8, false)
	}
	p.stmExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetChannel(uint16(p.val8), true)
		p.sendPacket()
	}
}

func (p *PktProc) stmPktD4() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD4, p.bIsMarker)
		p.numDataNibbles = 2
	}
	if p.numNibbles != p.numDataNibbles {
		if p.readNibble() {
			p.currPacket.SetD4Payload(p.nibble)
			if p.bNeedsTS {
				p.currPktFn = p.stmExtractTS
				p.currPktFn()
			} else {
				p.sendPacket()
			}
		}
	}
}

func (p *PktProc) stmPktD8() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD8, p.bIsMarker)
		p.numDataNibbles = 3
	}
	p.stmExtractVal8(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD8Payload(p.val8)
		if p.bNeedsTS {
			p.currPktFn = p.stmExtractTS
			p.currPktFn()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) stmPktD16() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD16, p.bIsMarker)
		p.numDataNibbles = 5
	}
	p.stmExtractVal16(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD16Payload(p.val16)
		if p.bNeedsTS {
			p.currPktFn = p.stmExtractTS
			p.currPktFn()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) stmPktD32() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD32, p.bIsMarker)
		p.numDataNibbles = 9
	}
	p.stmExtractVal32(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD32Payload(p.val32)
		if p.bNeedsTS {
			p.currPktFn = p.stmExtractTS
			p.currPktFn()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) stmPktD64() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD64, p.bIsMarker)
		p.numDataNibbles = 17
	}
	p.stmExtractVal64(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD64Payload(p.val64)
		if p.bNeedsTS {
			p.currPktFn = p.stmExtractTS
			p.currPktFn()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) stmPktD4MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currPktFn = p.stmPktD4
	p.currPktFn()
}

func (p *PktProc) stmPktD8MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currPktFn = p.stmPktD8
	p.currPktFn()
}

func (p *PktProc) stmPktD16MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currPktFn = p.stmPktD16
	p.currPktFn()
}

func (p *PktProc) stmPktD32MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currPktFn = p.stmPktD32
	p.currPktFn()
}

func (p *PktProc) stmPktD64MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currPktFn = p.stmPktD64
	p.currPktFn()
}

func (p *PktProc) stmPktFlagTS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktFlag, false)
	p.currPktFn = p.stmExtractTS
	p.currPktFn()
}

func (p *PktProc) stmPktFExt() {
	if p.readNibble() {
		p.currPktFn = p.op2N[p.nibble]
		p.currPktFn()
	}
}

func (p *PktProc) stmPktReservedFn() {
	badOpcode := uint16(0x00F) | (uint16(p.nibble) << 4)
	p.currPacket.SetD16Payload(badOpcode)
	p.throwReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) stmPktF0Ext() {
	if p.readNibble() {
		p.currPktFn = p.op3N[p.nibble]
		p.currPktFn()
	}
}

func (p *PktProc) stmPktGERR() {
	if p.numNibbles == 2 {
		p.currPacket.SetPacketType(PktGErr, false)
	}
	p.stmExtractVal8(4)
	if p.numNibbles == 4 {
		p.currPacket.SetD8Payload(p.val8)
		p.currPacket.SetMaster(0)
		p.sendPacket()
	}
}

func (p *PktProc) stmPktC16() {
	if p.numNibbles == 2 {
		p.currPacket.SetPacketType(PktC16, false)
	}
	p.stmExtractVal16(6)
	if p.numNibbles == 6 {
		p.currPacket.SetChannel(p.val16, false)
		p.sendPacket()
	}
}

func (p *PktProc) stmPktD4TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD4, false)
	p.numDataNibbles = 3
	p.currPktFn = p.stmPktD4
	p.currPktFn()
}

func (p *PktProc) stmPktD8TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD8, false)
	p.numDataNibbles = 4
	p.currPktFn = p.stmPktD8
	p.currPktFn()
}

func (p *PktProc) stmPktD16TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD16, false)
	p.numDataNibbles = 6
	p.currPktFn = p.stmPktD16
	p.currPktFn()
}

func (p *PktProc) stmPktD32TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD32, false)
	p.numDataNibbles = 10
	p.currPktFn = p.stmPktD32
	p.currPktFn()
}

func (p *PktProc) stmPktD64TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD64, false)
	p.numDataNibbles = 18
	p.currPktFn = p.stmPktD64
	p.currPktFn()
}

func (p *PktProc) stmPktD4M() {
	p.currPacket.SetPacketType(PktD4, true)
	p.numDataNibbles = 3
	p.currPktFn = p.stmPktD4
	p.currPktFn()
}

func (p *PktProc) stmPktD8M() {
	p.currPacket.SetPacketType(PktD8, true)
	p.numDataNibbles = 4
	p.currPktFn = p.stmPktD8
	p.currPktFn()
}

func (p *PktProc) stmPktD16M() {
	p.currPacket.SetPacketType(PktD16, true)
	p.numDataNibbles = 6
	p.currPktFn = p.stmPktD16
	p.currPktFn()
}

func (p *PktProc) stmPktD32M() {
	p.currPacket.SetPacketType(PktD32, true)
	p.numDataNibbles = 10
	p.currPktFn = p.stmPktD32
	p.currPktFn()
}

func (p *PktProc) stmPktD64M() {
	p.currPacket.SetPacketType(PktD64, true)
	p.numDataNibbles = 18
	p.currPktFn = p.stmPktD64
	p.currPktFn()
}

func (p *PktProc) stmPktFlag() {
	p.currPacket.SetPacketType(PktFlag, false)
	p.sendPacket()
}

func (p *PktProc) stmPktReservedF0n() {
	badOpcode := uint16(0x00F) | (uint16(p.nibble) << 8)
	p.currPacket.SetD16Payload(badOpcode)
	p.throwReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) stmPktVersion() {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktVersion, false)
	}
	if p.readNibble() {
		p.currPacket.SetD8Payload(p.nibble)
		switch p.nibble {
		case 3:
			p.currPacket.OnVersionPkt(TSNatBinary)
		case 4:
			p.currPacket.OnVersionPkt(TSGrey)
		default:
			p.throwBadSequenceError("STM VERSION packet : unrecognised version number.")
		}
		p.sendPacket()
	}
}

func (p *PktProc) stmPktTrigger() {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktTrig, false)
	}
	p.stmExtractVal8(5)
	if p.numNibbles == 5 {
		p.currPacket.SetD8Payload(p.val8)
		if p.bNeedsTS {
			p.currPktFn = p.stmExtractTS
			p.currPktFn()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) stmPktTriggerTS() {
	p.pktNeedsTS()
	p.currPktFn = p.stmPktTrigger
	p.currPktFn()
}

func (p *PktProc) stmPktFreq() {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktFreq, false)
		p.val32 = 0
	}
	p.stmExtractVal32(11)
	if p.numNibbles == 11 {
		p.currPacket.SetD32Payload(p.val32)
		p.sendPacket()
	}
}

func (p *PktProc) stmPktASync() {
	bCont := true
	for bCont {
		bCont = p.readNibble()
		if bCont {
			if p.isSync {
				bCont = false
				p.bStreamSync = true
				p.currPacket.SetPacketType(PktAsync, false)
				p.clearSyncCount()
				p.sendPacket()
			} else if !p.syncStart {
				p.throwBadSequenceError("STM: Invalid ASYNC sequence")
			}
		}
	}
}

func (p *PktProc) readNibble() bool {
	dataFound := true
	if p.nibble2ndValid {
		p.nibble = p.nibble2nd
		p.nibble2ndValid = false
		p.numNibbles++
		p.checkSyncNibble()
	} else if p.dataInUsed < p.dataInSize {
		p.nibble = p.dataIn[p.dataInUsed]
		p.dataInUsed++
		p.savePacketByte(p.nibble)
		p.nibble2nd = (p.nibble >> 4) & 0xF
		p.nibble2ndValid = true
		p.nibble &= 0xF
		p.numNibbles++
		p.checkSyncNibble()
	} else {
		dataFound = false
	}
	return dataFound
}

func (p *PktProc) pktNeedsTS() {
	p.bNeedsTS = true
	p.reqTSNibbles = 0
	p.currTSNibbles = 0
	p.tsUpdateValue = 0
	p.tsReqSet = false
}

func (p *PktProc) stmExtractTS() {
	if !p.tsReqSet {
		if p.readNibble() {
			p.reqTSNibbles = p.nibble
			if p.nibble == 0xD {
				p.reqTSNibbles = 14
			} else if p.nibble == 0xE {
				p.reqTSNibbles = 16
			}
			if p.nibble == 0xF {
				p.throwBadSequenceError("STM: Invalid timestamp size 0xF")
			}
			p.tsReqSet = true
		}
	}

	if p.tsReqSet {
		if p.reqTSNibbles != p.currTSNibbles {
			bCont := true
			for bCont && (p.currTSNibbles < p.reqTSNibbles) {
				bCont = p.readNibble()
				if bCont {
					p.tsUpdateValue <<= 4
					p.tsUpdateValue |= uint64(p.nibble)
					p.currTSNibbles++
				}
			}
		}

		if p.reqTSNibbles == p.currTSNibbles {
			newBits := p.reqTSNibbles * 4
			switch p.currPacket.TSType {
			case TSGrey:
				grayVal := p.binToGray(p.currPacket.Timestamp)
				if newBits == 64 {
					grayVal = p.tsUpdateValue
				} else {
					mask := (uint64(1) << newBits) - 1
					grayVal &^= mask
					grayVal |= p.tsUpdateValue & mask
				}
				p.currPacket.SetTS(p.grayToBin(grayVal), newBits)
			case TSNatBinary:
				p.currPacket.SetTS(p.tsUpdateValue, newBits)
			default:
				p.throwBadSequenceError("STM: unknown timestamp encoding")
			}
			p.sendPacket()
		}
	}
}

func (p *PktProc) stmExtractVal8(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val8 <<= 4
			p.val8 |= p.nibble
		}
	}
}

func (p *PktProc) stmExtractVal16(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val16 <<= 4
			p.val16 |= uint16(p.nibble)
		}
	}
}

func (p *PktProc) stmExtractVal32(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val32 <<= 4
			p.val32 |= uint32(p.nibble)
		}
	}
}

func (p *PktProc) stmExtractVal64(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val64 <<= 4
			p.val64 |= uint64(p.nibble)
		}
	}
}

func (p *PktProc) binToGray(binValue uint64) uint64 {
	grayValue := (1 << 63) & binValue
	for i := 62; i >= 0; i-- {
		grayArg1 := ((1 << (i + 1)) & binValue) >> (i + 1)
		grayArg2 := ((1 << i) & binValue) >> i
		grayValue |= ((grayArg1 ^ grayArg2) << i)
	}
	return grayValue
}

func (p *PktProc) grayToBin(grayValue uint64) uint64 {
	var binValue uint64
	for binBit := range uint64(64) {
		bitTmp := ((1 << binBit) & grayValue) >> binBit
		for grayBit := binBit + 1; grayBit < 64; grayBit++ {
			bitTmp ^= (((1 << grayBit) & grayValue) >> grayBit)
		}
		binValue |= (bitTmp << binBit)
	}
	return binValue
}

func (p *PktProc) buildOpTables() {
	for i := range 0x10 {
		p.op1N[i] = p.stmPktReserved
		p.op2N[i] = p.stmPktReservedFn
		p.op3N[i] = p.stmPktReservedF0n
	}

	p.op1N[0x0] = p.stmPktNull
	p.op1N[0x1] = p.stmPktM8
	p.op1N[0x2] = p.stmPktMERR
	p.op1N[0x3] = p.stmPktC8
	p.op1N[0x4] = p.stmPktD8
	p.op1N[0x5] = p.stmPktD16
	p.op1N[0x6] = p.stmPktD32
	p.op1N[0x7] = p.stmPktD64
	p.op1N[0x8] = p.stmPktD8MTS
	p.op1N[0x9] = p.stmPktD16MTS
	p.op1N[0xA] = p.stmPktD32MTS
	p.op1N[0xB] = p.stmPktD64MTS
	p.op1N[0xC] = p.stmPktD4
	p.op1N[0xD] = p.stmPktD4MTS
	p.op1N[0xE] = p.stmPktFlagTS
	p.op1N[0xF] = p.stmPktFExt

	p.op2N[0x0] = p.stmPktF0Ext
	p.op2N[0x2] = p.stmPktGERR
	p.op2N[0x3] = p.stmPktC16
	p.op2N[0x4] = p.stmPktD8TS
	p.op2N[0x5] = p.stmPktD16TS
	p.op2N[0x6] = p.stmPktD32TS
	p.op2N[0x7] = p.stmPktD64TS
	p.op2N[0x8] = p.stmPktD8M
	p.op2N[0x9] = p.stmPktD16M
	p.op2N[0xA] = p.stmPktD32M
	p.op2N[0xB] = p.stmPktD64M
	p.op2N[0xC] = p.stmPktD4TS
	p.op2N[0xD] = p.stmPktD4M
	p.op2N[0xE] = p.stmPktFlag
	p.op2N[0xF] = p.stmPktASync

	p.op3N[0x0] = p.stmPktVersion
	p.op3N[0x1] = p.stmPktNullTS
	p.op3N[0x6] = p.stmPktTrigger
	p.op3N[0x7] = p.stmPktTriggerTS
	p.op3N[0x8] = p.stmPktFreq
}

func (p *PktProc) checkSyncNibble() {
	if p.nibble != 0xF {
		if !p.syncStart {
			return
		}
		if p.nibble == 0 && p.numFNibbles >= 21 {
			p.isSync = true
			p.numFNibbles = 21
		} else {
			p.clearSyncCount()
		}
		return
	}

	p.numFNibbles++
	if !p.syncStart {
		p.syncStart = true
		p.syncIndex = p.packetIndex + ocsd.TrcIndex((p.numNibbles-1)/2)
	}
}

func (p *PktProc) clearSyncCount() {
	p.numFNibbles = 0
	p.syncStart = false
	p.isSync = false
}

func (p *PktProc) sendPacket() {
	p.procState = procSendPkt
}

func (p *PktProc) setProcUnsynced() {
	p.procState = procWaitSync
	p.bStreamSync = false
}

func (p *PktProc) savePacketByte(val uint8) {
	if p.PktRawMonI.HasAttachedAndEnabled() && !p.bWaitSyncSaveSuppressed {
		p.packetData = append(p.packetData, val)
	}
}

func (p *PktProc) dataToProcess() bool {
	return (p.dataInUsed < p.dataInSize) || p.nibble2ndValid || (p.procState == procSendPkt)
}
