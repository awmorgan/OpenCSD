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

type decodeAction int

const (
	decodeNone decodeAction = iota
	decodePktReserved
	decodePktNull
	decodePktNullTS
	decodePktM8
	decodePktMERR
	decodePktC8
	decodePktD4
	decodePktD8
	decodePktD16
	decodePktD32
	decodePktD64
	decodePktD4MTS
	decodePktD8MTS
	decodePktD16MTS
	decodePktD32MTS
	decodePktD64MTS
	decodePktFlagTS
	decodePktFExt
	decodePktReservedFn
	decodePktF0Ext
	decodePktGERR
	decodePktC16
	decodePktD4TS
	decodePktD8TS
	decodePktD16TS
	decodePktD32TS
	decodePktD64TS
	decodePktD4M
	decodePktD8M
	decodePktD16M
	decodePktD32M
	decodePktD64M
	decodePktFlag
	decodePktReservedF0n
	decodePktVersion
	decodePktTrigger
	decodePktTriggerTS
	decodePktFreq
	decodePktASync
	decodeExtractTS
)

// PktProc converts the byte stream into basic STM trace packets.
type PktProc struct {
	common.PktProcBase[Packet, PktType, Config]

	procState processState

	op1N [0x10]decodeAction
	op2N [0x10]decodeAction
	op3N [0x10]decodeAction

	currDecode decodeAction

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

	// pktErr is set by setBadSequenceError / setReservedHdrError and is checked
	// in processStateLoop after each packet function.
	pktErr *common.Error
}

// NewPktProc creates a new STM packet processor.
func NewPktProc(instIDNum int) *PktProc {
	p := &PktProc{}
	p.InitPktProcBase(fmt.Sprintf("PKTP_STM_%d", instIDNum))
	p.SetStrategy(p)

	p.SetSupportedOpModes(ocsd.OpflgPktprocCommon)
	p.initProcessorState()
	p.buildOpTables()
	return p
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	var err error
	p.dataIn = dataBlock
	p.dataInSize = uint32(len(dataBlock))
	p.dataInUsed = 0

	for p.dataToProcess() && ocsd.DataRespIsCont(resp) {
		errResp, loopErr, handled := p.processStateLoop(index)
		if handled {
			resp = errResp
			err = loopErr
			if ocsd.DataRespIsFatal(resp) {
				break
			}
			if err != nil {
				break
			}
		}
	}

	return p.dataInUsed, resp, err
}

func (p *PktProc) processStateLoop(index ocsd.TrcIndex) (resp ocsd.DatapathResp, err error, handled bool) {
	resp = ocsd.RespCont

	switch p.procState {
	case procWaitSync:
		p.waitForSync(index)
	case procHdrState:
		p.packetIndex = index + ocsd.TrcIndex(p.dataInUsed)
		if p.readNibble() {
			p.procState = procDataState
			p.currDecode = p.op1N[p.nibble]
		} else {
			break
		}
		fallthrough
	case procDataState:
		p.runDecodeAction()
		if e := p.pktErr; e != nil {
			p.pktErr = nil
			p.LogError(e)
			err = e
			if (e.Code == ocsd.ErrBadPacketSeq || e.Code == ocsd.ErrInvalidPcktHdr) &&
				(p.ComponentOpMode()&ocsd.OpflgPktprocErrBadPkts) == 0 {
				resp = p.outputPacket()
				if (p.ComponentOpMode() & ocsd.OpflgPktprocUnsyncOnBadPkts) != 0 {
					p.procState = procWaitSync
				}
			} else {
				resp = ocsd.RespFatalInvalidData
			}
			return resp, err, true
		}
		if p.procState != procSendPkt {
			break
		}
		fallthrough
	case procSendPkt:
		resp = p.outputPacket()
	}

	return resp, nil, false
}

func (p *PktProc) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if p.numNibbles > 0 {
		p.currPacket.UpdateErrType(PktIncompleteEOT)
		resp = p.outputPacket()
	}
	return resp
}

func (p *PktProc) OnReset() ocsd.DatapathResp {
	p.initProcessorState()
	return ocsd.RespCont
}

func (p *PktProc) OnFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (p *PktProc) OnProtocolConfig() ocsd.Err {
	return ocsd.OK
}

func (p *PktProc) IsBadPacket() bool {
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

// setBadSequenceError records a bad-sequence error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setBadSequenceError(msg string) {
	p.currPacket.UpdateErrType(PktBadSequence)
	trcID := uint8(0)
	if p.Config != nil {
		trcID = p.Config.TraceID()
	}
	p.pktErr = common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, p.packetIndex, trcID, msg)
}

// setReservedHdrError records a reserved-header error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setReservedHdrError(msg string) {
	p.currPacket.SetPacketType(PktReserved, false)
	trcID := uint8(0)
	if p.Config != nil {
		trcID = p.Config.TraceID()
	}
	p.pktErr = common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrInvalidPcktHdr, p.packetIndex, trcID, msg)
}

func (p *PktProc) initProcessorState() {
	p.setProcUnsynced()
	p.clearSyncCount()
	p.currPacket.InitStartState()
	p.nibble2ndValid = false
	p.initNextPacket()
	p.bWaitSyncSaveSuppressed = false
	p.packetData = nil
	p.pktErr = nil
}

func (p *PktProc) initNextPacket() {
	p.bNeedsTS = false
	p.bIsMarker = false
	p.numNibbles = 0
	p.numDataNibbles = 0
	p.currDecode = decodeNone
	p.currPacket.InitNextPacket()
}

func (p *PktProc) runDecodeAction() {
	switch p.currDecode {
	case decodePktReserved:
		p.PktReserved()
	case decodePktNull:
		p.PktNull()
	case decodePktNullTS:
		p.PktNullTS()
	case decodePktM8:
		p.PktM8()
	case decodePktMERR:
		p.PktMERR()
	case decodePktC8:
		p.PktC8()
	case decodePktD4:
		p.PktD4()
	case decodePktD8:
		p.PktD8()
	case decodePktD16:
		p.PktD16()
	case decodePktD32:
		p.PktD32()
	case decodePktD64:
		p.PktD64()
	case decodePktD4MTS:
		p.PktD4MTS()
	case decodePktD8MTS:
		p.PktD8MTS()
	case decodePktD16MTS:
		p.PktD16MTS()
	case decodePktD32MTS:
		p.PktD32MTS()
	case decodePktD64MTS:
		p.PktD64MTS()
	case decodePktFlagTS:
		p.PktFlagTS()
	case decodePktFExt:
		p.PktFExt()
	case decodePktReservedFn:
		p.PktReservedFn()
	case decodePktF0Ext:
		p.PktF0Ext()
	case decodePktGERR:
		p.PktGERR()
	case decodePktC16:
		p.PktC16()
	case decodePktD4TS:
		p.PktD4TS()
	case decodePktD8TS:
		p.PktD8TS()
	case decodePktD16TS:
		p.PktD16TS()
	case decodePktD32TS:
		p.PktD32TS()
	case decodePktD64TS:
		p.PktD64TS()
	case decodePktD4M:
		p.PktD4M()
	case decodePktD8M:
		p.PktD8M()
	case decodePktD16M:
		p.PktD16M()
	case decodePktD32M:
		p.PktD32M()
	case decodePktD64M:
		p.PktD64M()
	case decodePktFlag:
		p.PktFlag()
	case decodePktReservedF0n:
		p.PktReservedF0n()
	case decodePktVersion:
		p.PktVersion()
	case decodePktTrigger:
		p.PktTrigger()
	case decodePktTriggerTS:
		p.PktTriggerTS()
	case decodePktFreq:
		p.PktFreq()
	case decodePktASync:
		p.PktASync()
	case decodeExtractTS:
		p.ExtractTS()
	default:
		p.setBadSequenceError("STM decode action not set")
	}
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
			nibblesToSend := uint32(p.numNibbles - p.numFNibbles)
			if p.isSync {
				nibblesToSend = uint32(p.numNibbles - 22)
			}
			bytesToSend := (nibblesToSend / 2) + (nibblesToSend % 2)
			// Clamp to the bytes actually available in the current dataIn window.
			// If clearSyncCount() reset numFNibbles to 0 mid-loop, nibblesToSend
			// would overcount and cause an out-of-bounds access.
			if available := p.dataInSize - startOffset; bytesToSend > available {
				bytesToSend = available
			}
			for i := range bytesToSend {
				p.savePacketByte(p.dataIn[startOffset+i])
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

func (p *PktProc) PktReserved() {
	badOpcode := uint16(p.nibble)
	p.currPacket.SetD16Payload(badOpcode)
	p.setReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) PktNull() {
	p.currPacket.SetPacketType(PktNull, false)
	if p.bNeedsTS {
		p.currDecode = decodeExtractTS
		p.runDecodeAction()
	} else {
		p.sendPacket()
	}
}

func (p *PktProc) PktNullTS() {
	p.pktNeedsTS()
	p.currDecode = decodePktNull
	p.runDecodeAction()
}

func (p *PktProc) PktM8() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktM8, false)
	}
	p.ExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetMaster(p.val8)
		p.sendPacket()
	}
}

func (p *PktProc) PktMERR() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktMErr, false)
	}
	p.ExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetChannel(0, false)
		p.currPacket.SetD8Payload(p.val8)
		p.sendPacket()
	}
}

func (p *PktProc) PktC8() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktC8, false)
	}
	p.ExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetChannel(uint16(p.val8), true)
		p.sendPacket()
	}
}

func (p *PktProc) PktD4() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD4, p.bIsMarker)
		p.numDataNibbles = 2
	}
	if p.numNibbles != p.numDataNibbles {
		if p.readNibble() {
			p.currPacket.SetD4Payload(p.nibble)
			if p.bNeedsTS {
				p.currDecode = decodeExtractTS
				p.runDecodeAction()
			} else {
				p.sendPacket()
			}
		}
	}
}

func (p *PktProc) PktD8() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD8, p.bIsMarker)
		p.numDataNibbles = 3
	}
	p.ExtractVal8(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD8Payload(p.val8)
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) PktD16() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD16, p.bIsMarker)
		p.numDataNibbles = 5
	}
	p.ExtractVal16(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD16Payload(p.val16)
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) PktD32() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD32, p.bIsMarker)
		p.numDataNibbles = 9
	}
	p.ExtractVal32(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD32Payload(p.val32)
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) PktD64() {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD64, p.bIsMarker)
		p.numDataNibbles = 17
	}
	p.ExtractVal64(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.SetD64Payload(p.val64)
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) PktD4MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD4
	p.runDecodeAction()
}

func (p *PktProc) PktD8MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD8
	p.runDecodeAction()
}

func (p *PktProc) PktD16MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD16
	p.runDecodeAction()
}

func (p *PktProc) PktD32MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD32
	p.runDecodeAction()
}

func (p *PktProc) PktD64MTS() {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD64
	p.runDecodeAction()
}

func (p *PktProc) PktFlagTS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktFlag, false)
	p.currDecode = decodeExtractTS
	p.runDecodeAction()
}

func (p *PktProc) PktFExt() {
	if p.readNibble() {
		p.currDecode = p.op2N[p.nibble]
		p.runDecodeAction()
	}
}

func (p *PktProc) PktReservedFn() {
	badOpcode := uint16(0x00F) | (uint16(p.nibble) << 4)
	p.currPacket.SetD16Payload(badOpcode)
	p.setReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) PktF0Ext() {
	if p.readNibble() {
		p.currDecode = p.op3N[p.nibble]
		p.runDecodeAction()
	}
}

func (p *PktProc) PktGERR() {
	if p.numNibbles == 2 {
		p.currPacket.SetPacketType(PktGErr, false)
	}
	p.ExtractVal8(4)
	if p.numNibbles == 4 {
		p.currPacket.SetD8Payload(p.val8)
		p.currPacket.SetMaster(0)
		p.sendPacket()
	}
}

func (p *PktProc) PktC16() {
	if p.numNibbles == 2 {
		p.currPacket.SetPacketType(PktC16, false)
	}
	p.ExtractVal16(6)
	if p.numNibbles == 6 {
		p.currPacket.SetChannel(p.val16, false)
		p.sendPacket()
	}
}

func (p *PktProc) PktD4TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD4, false)
	p.numDataNibbles = 3
	p.currDecode = decodePktD4
	p.runDecodeAction()
}

func (p *PktProc) PktD8TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD8, false)
	p.numDataNibbles = 4
	p.currDecode = decodePktD8
	p.runDecodeAction()
}

func (p *PktProc) PktD16TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD16, false)
	p.numDataNibbles = 6
	p.currDecode = decodePktD16
	p.runDecodeAction()
}

func (p *PktProc) PktD32TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD32, false)
	p.numDataNibbles = 10
	p.currDecode = decodePktD32
	p.runDecodeAction()
}

func (p *PktProc) PktD64TS() {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD64, false)
	p.numDataNibbles = 18
	p.currDecode = decodePktD64
	p.runDecodeAction()
}

func (p *PktProc) PktD4M() {
	p.currPacket.SetPacketType(PktD4, true)
	p.numDataNibbles = 3
	p.currDecode = decodePktD4
	p.runDecodeAction()
}

func (p *PktProc) PktD8M() {
	p.currPacket.SetPacketType(PktD8, true)
	p.numDataNibbles = 4
	p.currDecode = decodePktD8
	p.runDecodeAction()
}

func (p *PktProc) PktD16M() {
	p.currPacket.SetPacketType(PktD16, true)
	p.numDataNibbles = 6
	p.currDecode = decodePktD16
	p.runDecodeAction()
}

func (p *PktProc) PktD32M() {
	p.currPacket.SetPacketType(PktD32, true)
	p.numDataNibbles = 10
	p.currDecode = decodePktD32
	p.runDecodeAction()
}

func (p *PktProc) PktD64M() {
	p.currPacket.SetPacketType(PktD64, true)
	p.numDataNibbles = 18
	p.currDecode = decodePktD64
	p.runDecodeAction()
}

func (p *PktProc) PktFlag() {
	p.currPacket.SetPacketType(PktFlag, false)
	p.sendPacket()
}

func (p *PktProc) PktReservedF0n() {
	badOpcode := uint16(0x00F) | (uint16(p.nibble) << 8)
	p.currPacket.SetD16Payload(badOpcode)
	p.setReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) PktVersion() {
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
			p.setBadSequenceError("STM VERSION packet : unrecognised version number.")
			return
		}
		p.sendPacket()
	}
}

func (p *PktProc) PktTrigger() {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktTrig, false)
	}
	p.ExtractVal8(5)
	if p.numNibbles == 5 {
		p.currPacket.SetD8Payload(p.val8)
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
}

func (p *PktProc) PktTriggerTS() {
	p.pktNeedsTS()
	p.currDecode = decodePktTrigger
	p.runDecodeAction()
}

func (p *PktProc) PktFreq() {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktFreq, false)
		p.val32 = 0
	}
	p.ExtractVal32(11)
	if p.numNibbles == 11 {
		p.currPacket.SetD32Payload(p.val32)
		p.sendPacket()
	}
}

func (p *PktProc) PktASync() {
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
				p.setBadSequenceError("STM: Invalid ASYNC sequence")
				return
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

func (p *PktProc) ExtractTS() {
	if !p.tsReqSet {
		if p.readNibble() {
			p.reqTSNibbles = p.nibble
			switch p.nibble {
			case 0xD:
				p.reqTSNibbles = 14
			case 0xE:
				p.reqTSNibbles = 16
			}
			if p.nibble == 0xF {
				p.setBadSequenceError("STM: Invalid timestamp size 0xF")
				return
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
				p.setBadSequenceError("STM: unknown timestamp encoding")
				return
			}
			p.sendPacket()
		}
	}
}

func (p *PktProc) ExtractVal8(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val8 <<= 4
			p.val8 |= p.nibble
		}
	}
}

func (p *PktProc) ExtractVal16(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val16 <<= 4
			p.val16 |= uint16(p.nibble)
		}
	}
}

func (p *PktProc) ExtractVal32(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val32 <<= 4
			p.val32 |= uint32(p.nibble)
		}
	}
}

func (p *PktProc) ExtractVal64(nibblesToVal uint8) {
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
	return binValue ^ (binValue >> 1)
}

func (p *PktProc) grayToBin(grayValue uint64) uint64 {
	binValue := grayValue
	for shift := uint(1); shift < 64; shift <<= 1 {
		binValue ^= binValue >> shift
	}
	return binValue
}

func (p *PktProc) buildOpTables() {
	for i := range 0x10 {
		p.op1N[i] = decodePktReserved
		p.op2N[i] = decodePktReservedFn
		p.op3N[i] = decodePktReservedF0n
	}

	p.op1N[0x0] = decodePktNull
	p.op1N[0x1] = decodePktM8
	p.op1N[0x2] = decodePktMERR
	p.op1N[0x3] = decodePktC8
	p.op1N[0x4] = decodePktD8
	p.op1N[0x5] = decodePktD16
	p.op1N[0x6] = decodePktD32
	p.op1N[0x7] = decodePktD64
	p.op1N[0x8] = decodePktD8MTS
	p.op1N[0x9] = decodePktD16MTS
	p.op1N[0xA] = decodePktD32MTS
	p.op1N[0xB] = decodePktD64MTS
	p.op1N[0xC] = decodePktD4
	p.op1N[0xD] = decodePktD4MTS
	p.op1N[0xE] = decodePktFlagTS
	p.op1N[0xF] = decodePktFExt

	p.op2N[0x0] = decodePktF0Ext
	p.op2N[0x2] = decodePktGERR
	p.op2N[0x3] = decodePktC16
	p.op2N[0x4] = decodePktD8TS
	p.op2N[0x5] = decodePktD16TS
	p.op2N[0x6] = decodePktD32TS
	p.op2N[0x7] = decodePktD64TS
	p.op2N[0x8] = decodePktD8M
	p.op2N[0x9] = decodePktD16M
	p.op2N[0xA] = decodePktD32M
	p.op2N[0xB] = decodePktD64M
	p.op2N[0xC] = decodePktD4TS
	p.op2N[0xD] = decodePktD4M
	p.op2N[0xE] = decodePktFlag
	p.op2N[0xF] = decodePktASync

	p.op3N[0x0] = decodePktVersion
	p.op3N[0x1] = decodePktNullTS
	p.op3N[0x6] = decodePktTrigger
	p.op3N[0x7] = decodePktTriggerTS
	p.op3N[0x8] = decodePktFreq
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
