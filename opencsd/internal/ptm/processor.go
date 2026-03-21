package ptm

import (
	"fmt"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type processState int

const (
	stateWaitSync processState = iota
	stateProcHdr
	stateProcData
	stateSendPkt
)

type asyncResult int

const (
	asyncResultAsync           asyncResult = iota // pattern confirmed async 0x00 x 5, 0x80
	asyncResultNotAsync                           // pattern confirmed not async
	asyncResultAsyncExtra0                        // pattern confirmed 0x00 x N + ASYNC
	asyncResultThrow0                             // long pattern of 0x00 - throw some away.
	asyncResultAsyncIncomplete                    // not enough input data.
)

const (
	asyncPad0Limit = 11
	asyncReq0      = 5
)

type decodeAction int

const (
	decodeReserved decodeAction = iota
	decodeBranchAddr
	decodeAtom
	decodeASync
	decodeISync
	decodeWPointUpdate
	decodeTrigger
	decodeCtxtID
	decodeVMID
	decodeTimeStamp
	decodeExceptionRet
	decodeIgnore
)

type PktProc struct {
	common.PktProcBase[Packet, PktType, Config]

	processState processState

	currPacketData []uint8
	currPktIdx     uint32
	currPacket     Packet
	currPktIndex   ocsd.TrcIndex

	chanIDCopy uint8

	pDataIn         []uint8
	dataInLen       uint32
	dataInProcessed uint32
	blockIdx        ocsd.TrcIndex

	waitASyncSOPkt bool
	bAsyncRawOp    bool
	bOPNotSyncPkt  bool
	async0         int
	partAsync      bool

	numPktBytesReq int
	needCycleCount bool
	gotCycleCount  bool
	gotCCBytes     int
	numCtxtIDBytes int
	gotCtxtIDBytes int
	gotTSBytes     bool
	tsByteMax      int

	gotAddrBytes  bool
	numAddrBytes  int
	gotExcepBytes bool
	numExcepBytes int
	addrPktIsa    ocsd.ISA
	excepAltISA   int

	iTable [256]struct {
		pktType PktType
		action  decodeAction
	}
	currDecode decodeAction
}

func NewPktProc(instIDNum int) *PktProc {
	p := &PktProc{}
	p.InitPktProcBase(fmt.Sprintf("%s_%d", "PKTP_PTM", instIDNum))

	p.initProcessorState()
	p.buildIPacketTable()
	return p
}

func (p *PktProc) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	var processed uint32 = 0
	var err error

	switch op {
	case ocsd.OpData:
		if len(dataBlock) == 0 {
			p.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "Packet Processor: Zero length data block error"))
			resp = ocsd.RespFatalInvalidParam
		} else {
			processed, resp, err = p.ProcessData(index, dataBlock)
		}
	case ocsd.OpEOT:
		resp = p.OnEOT()
		if p.PktOutI.HasAttachedAndEnabled() && !ocsd.DataRespIsFatal(resp) {
			resp = p.PktOutI.First().PacketDataIn(ocsd.OpEOT, 0, nil)
		}
		if p.PktRawMonI.HasAttachedAndEnabled() {
			p.PktRawMonI.First().RawPacketDataMon(ocsd.OpEOT, 0, nil, nil)
		}
	case ocsd.OpFlush:
		resp = p.OnFlush()
		if ocsd.DataRespIsCont(resp) && p.PktOutI.HasAttachedAndEnabled() {
			resp = p.PktOutI.First().PacketDataIn(ocsd.OpFlush, 0, nil)
		}
	case ocsd.OpReset:
		if p.PktOutI.HasAttachedAndEnabled() {
			resp = p.PktOutI.First().PacketDataIn(ocsd.OpReset, index, nil)
		}
		if !ocsd.DataRespIsFatal(resp) {
			resp = p.OnReset()
		}
		if p.PktRawMonI.HasAttachedAndEnabled() {
			p.PktRawMonI.First().RawPacketDataMon(ocsd.OpReset, index, nil, nil)
		}
	default:
		p.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "Packet Processor : Unknown Datapath operation"))
		resp = ocsd.RespFatalInvalidOp
	}
	return processed, resp, err
}

func (p *PktProc) SetProtocolConfig(config *Config) ocsd.Err {
	p.Config = config
	if p.Config != nil {
		p.chanIDCopy = p.Config.TraceID()
		return ocsd.OK
	}
	return ocsd.ErrNotInit
}

func (p *PktProc) IsBadPacket() bool {
	return p.currPacket.IsBadPacket()
}

func (p *PktProc) initPacketState() {
	p.currPacket.Clear()
}

func (p *PktProc) initProcessorState() {
	p.currPacket.Type = PktNotSync
	p.currDecode = decodeReserved
	p.processState = stateWaitSync
	p.async0 = 0
	p.waitASyncSOPkt = false
	p.bAsyncRawOp = false
	p.bOPNotSyncPkt = false
	p.excepAltISA = 0

	p.currPacket.ResetState()
	p.initPacketState()
}

func (p *PktProc) readByteVal() (uint8, bool) {
	if p.dataInProcessed < p.dataInLen {
		currByte := p.pDataIn[p.dataInProcessed]
		p.dataInProcessed++
		p.currPacketData = append(p.currPacketData, currByte)
		return currByte, true
	}
	return 0, false
}

func (p *PktProc) readByte() bool {
	_, ok := p.readByteVal()
	return ok
}

func (p *PktProc) unReadByte() {
	p.dataInProcessed--
	p.currPacketData = p.currPacketData[:len(p.currPacketData)-1]
}

func (p *PktProc) isSync() bool {
	return p.currPacket.Type == PktNotSync
}

func (p *PktProc) malformedPacketErr(msg string) error {
	p.currPacket.ErrType = PktBadSequence
	return common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, p.currPktIndex, p.chanIDCopy, msg)
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []uint8) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	var err error
	var currByte uint8
	var ok bool

	p.dataInProcessed = 0
	if p.Config == nil {
		return 0, ocsd.RespFatalNotInit, nil
	}

	p.pDataIn = dataBlock
	p.dataInLen = uint32(len(dataBlock))
	p.blockIdx = index

	for ((p.dataInProcessed < p.dataInLen) || (p.dataInProcessed == p.dataInLen && p.processState == stateSendPkt)) && ocsd.DataRespIsCont(resp) {
		resp, err = p.doProcessLoop(&currByte, &ok)
		if ocsd.DataRespIsFatal(resp) {
			break
		}
		if err != nil {
			break
		}
	}

	return p.dataInProcessed, resp, err
}

func (p *PktProc) doProcessLoop(currByte *uint8, ok *bool) (ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	handleErr := func(err error) (ocsd.DatapathResp, error) {
		if err == nil {
			return ocsd.RespCont, nil
		}
		ce, ok := err.(*common.Error)
		if !ok {
			return ocsd.RespFatalInvalidData, err
		}
		p.LogError(ce)
		if ce.Code == ocsd.ErrBadPacketSeq || ce.Code == ocsd.ErrInvalidPcktHdr {
			p.processState = stateSendPkt
			return ocsd.RespCont, err
		}
		return ocsd.RespFatalInvalidData, err
	}

	switch p.processState {
	case stateWaitSync:
		if !p.waitASyncSOPkt {
			p.currPktIndex = p.blockIdx + ocsd.TrcIndex(p.dataInProcessed)
			p.currPacket.Type = PktNotSync
			p.bAsyncRawOp = p.PktRawMonI.HasAttachedAndEnabled()
		}
		resp = p.waitASync()

	case stateProcHdr:
		p.currPktIndex = p.blockIdx + ocsd.TrcIndex(p.dataInProcessed)
		if *currByte, *ok = p.readByteVal(); *ok {
			p.currDecode = p.iTable[*currByte].action
			p.currPacket.Type = p.iTable[*currByte].pktType
		} else {
			return handleErr(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrPktInterpFail, p.currPktIndex, p.chanIDCopy, "Data Buffer Overrun"))
		}
		p.processState = stateProcData
		fallthrough

	case stateProcData:
		if err := p.runDecodeAction(); err != nil {
			return handleErr(err)
		}

	case stateSendPkt:
		resp = p.outputPacket()
		p.initPacketState()
		p.processState = stateProcHdr
	}

	return resp, nil
}

func (p *PktProc) runDecodeAction() error {
	switch p.currDecode {
	case decodeBranchAddr:
		return p.pktBranchAddr()
	case decodeAtom:
		return p.pktAtom()
	case decodeASync:
		return p.pktASync()
	case decodeISync:
		return p.pktISync()
	case decodeWPointUpdate:
		return p.pktWPointUpdate()
	case decodeTrigger:
		return p.pktTrigger()
	case decodeCtxtID:
		return p.pktCtxtID()
	case decodeVMID:
		return p.pktVMID()
	case decodeTimeStamp:
		return p.pktTimeStamp()
	case decodeExceptionRet:
		return p.pktExceptionRet()
	case decodeIgnore:
		return p.pktIgnore()
	default:
		return p.pktReserved()
	}
}

func (p *PktProc) outputPacket() ocsd.DatapathResp {
	resp := p.OutputOnAllInterfaces(p.currPktIndex, &p.currPacket, p.currPacket.Type, p.currPacketData)
	p.currPacketData = p.currPacketData[:0]
	return resp
}

func (p *PktProc) OnEOT() ocsd.DatapathResp {
	if p.Config == nil {
		return ocsd.RespFatalNotInit
	}
	resp := ocsd.RespCont
	if len(p.currPacketData) > 0 {
		p.currPacket.ErrType = p.currPacket.Type
		p.currPacket.Type = PktIncompleteEOT
		resp = p.outputPacket()
	}
	return resp
}

func (p *PktProc) OnReset() ocsd.DatapathResp {
	if p.Config == nil {
		return ocsd.RespFatalNotInit
	}
	p.initProcessorState()
	return ocsd.RespCont
}

func (p *PktProc) OnFlush() ocsd.DatapathResp {
	if p.Config == nil {
		return ocsd.RespFatalNotInit
	}
	return ocsd.RespCont
}

func (p *PktProc) waitASync() ocsd.DatapathResp {
	resp := ocsd.RespCont
	doScan := true
	bSendUnsyncedData := false
	bHaveASync := false
	unsyncedBytes := 0
	unsyncScanBlockStart := 0
	pktBytesOnEntry := len(p.currPacketData)
	spareZeros := make([]uint8, 16)

	const unsyncPktMax = 16

	for doScan && ocsd.DataRespIsCont(resp) {
		if p.waitASyncSOPkt {
			switch p.findAsync() {
			case asyncResultAsync, asyncResultAsyncExtra0:
				p.processState = stateSendPkt
				p.waitASyncSOPkt = false
				bSendUnsyncedData = true
				bHaveASync = true
				doScan = false
			case asyncResultThrow0:
				unsyncedBytes += asyncPad0Limit
				p.waitASyncSOPkt = false
				p.currPacketData = append([]uint8(nil), p.currPacketData[asyncPad0Limit:]...)
			case asyncResultNotAsync:
				unsyncedBytes += len(p.currPacketData)
				p.waitASyncSOPkt = false
				p.currPacketData = p.currPacketData[:0]
			case asyncResultAsyncIncomplete:
				bSendUnsyncedData = true
				doScan = false
			}
		} else {
			if p.pDataIn[p.dataInProcessed] == 0x00 {
				p.dataInProcessed++
				p.waitASyncSOPkt = true
				p.currPacketData = append(p.currPacketData, 0)
				p.async0 = 1
			} else {
				p.dataInProcessed++
				unsyncedBytes++
			}
		}

		if unsyncedBytes >= unsyncPktMax {
			bSendUnsyncedData = true
		}

		if p.dataInProcessed == p.dataInLen {
			bSendUnsyncedData = true
			doScan = false
		}

		if bSendUnsyncedData && unsyncedBytes > 0 {
			if p.bAsyncRawOp {
				if pktBytesOnEntry > 0 {
					p.OutputRawPacketToMonitor(p.currPktIndex, &p.currPacket, spareZeros[:pktBytesOnEntry])
					p.currPktIndex += ocsd.TrcIndex(pktBytesOnEntry)
				}
				rawData := p.pDataIn
				rawEnd := unsyncScanBlockStart + unsyncedBytes
				if rawEnd <= len(rawData) {
					p.OutputRawPacketToMonitor(p.currPktIndex, &p.currPacket, rawData[unsyncScanBlockStart:rawEnd])
				} else if unsyncScanBlockStart < len(rawData) {
					// Keep bug-for-bug raw packet monitor output compatible with OpenCSD C++ in
					// the carry-over NOT_ASYNC path: one synthetic tail byte may be emitted when
					// unsynced accounting includes a previous SOP-candidate byte.
					base := rawData[unsyncScanBlockStart:len(rawData)]
					missing := rawEnd - len(rawData)
					if missing > 0 {
						fill := byte(len(p.pDataIn))
						tmp := make([]byte, len(base)+missing)
						copy(tmp, base)
						for i := len(base); i < len(tmp); i++ {
							tmp[i] = fill
						}
						p.OutputRawPacketToMonitor(p.currPktIndex, &p.currPacket, tmp)
					} else {
						p.OutputRawPacketToMonitor(p.currPktIndex, &p.currPacket, base)
					}
				}
			}
			if !p.bOPNotSyncPkt {
				resp = p.OutputDecodedPacket(p.currPktIndex, &p.currPacket)
				p.bOPNotSyncPkt = true
			}
			unsyncScanBlockStart += unsyncedBytes
			p.currPktIndex += ocsd.TrcIndex(unsyncedBytes)
			unsyncedBytes = 0
			bSendUnsyncedData = false
		}

		if bHaveASync {
			p.currPacket.Type = PktASync
		}
	}
	return resp
}

func (p *PktProc) findAsync() asyncResult {
	asyncRes := asyncResultNotAsync
	bFound := false
	bByteAvail := true
	var currByte uint8

	for !bFound && bByteAvail {
		if currByte, bByteAvail = p.readByteVal(); bByteAvail {
			if currByte == 0x00 {
				p.async0++
				if p.async0 >= (asyncPad0Limit + asyncReq0) {
					bFound = true
					asyncRes = asyncResultThrow0
				}
			} else {
				if currByte == 0x80 {
					if p.async0 == 5 {
						asyncRes = asyncResultAsync
					} else if p.async0 > 5 {
						asyncRes = asyncResultAsyncExtra0
					}
				}
				bFound = true
			}
		} else {
			bByteAvail = false
			asyncRes = asyncResultAsyncIncomplete
		}
	}
	return asyncRes
}

func (p *PktProc) pktASync() error {
	if len(p.currPacketData) == 1 {
		p.async0 = 1
	}
	switch p.findAsync() {
	case asyncResultAsync, asyncResultAsyncExtra0:
		p.processState = stateSendPkt
	case asyncResultThrow0, asyncResultNotAsync:
		return p.malformedPacketErr("Bad Async packet")
	case asyncResultAsyncIncomplete:
	}
	return nil
}

func (p *PktProc) extractCycleCount(offset int) (uint32, error) {
	bCont := true
	cycleCount := uint32(0)
	byIdx := 0
	shift := 4

	for bCont {
		if offset+byIdx >= len(p.currPacketData) {
			return 0, p.malformedPacketErr("Insufficient packet bytes for Cycle Count value.")
		}
		currByte := p.currPacketData[offset+byIdx]
		if byIdx == 0 {
			bCont = (currByte & 0x40) != 0
			cycleCount = uint32((currByte >> 2) & 0xF)
		} else {
			bCont = (currByte & 0x80) != 0
			if byIdx == 4 {
				bCont = false
			}
			cycleCount |= (uint32(currByte&0x7F) << shift)
			shift += 7
		}
		byIdx++
	}
	p.gotCCBytes = byIdx
	return cycleCount, nil
}

func (p *PktProc) extractCtxtID(idx int) (uint32, error) {
	ctxtID := uint32(0)
	shift := 0
	for i := 0; i < p.numCtxtIDBytes; i++ {
		if idx+i >= len(p.currPacketData) {
			return 0, p.malformedPacketErr("Insufficient packet bytes for Context ID value.")
		}
		ctxtID |= uint32(p.currPacketData[idx+i]) << shift
		shift += 8
	}
	return ctxtID, nil
}

func (p *PktProc) extractTS() (uint64, uint8, int, error) {
	bCont := true
	tsIdx := 1
	b64BitVal := p.Config.TSPkt64()
	shift := 0

	tsVal := uint64(0)
	tsUpdateBits := uint8(0)

	for bCont {
		if tsIdx >= len(p.currPacketData) {
			return 0, 0, 0, p.malformedPacketErr("Insufficient packet bytes for Timestamp value.")
		}
		byteVal := p.currPacketData[tsIdx]
		if b64BitVal {
			if tsIdx < 9 {
				bCont = (byteVal & 0x80) == 0x80
				byteVal &= 0x7F
				tsUpdateBits += 7
			} else {
				bCont = false
				tsUpdateBits += 8
			}
		} else {
			if tsIdx < 7 {
				bCont = (byteVal & 0x80) == 0x80
				byteVal &= 0x7F
				tsUpdateBits += 7
			} else {
				byteVal &= 0x3F
				bCont = false
				tsUpdateBits += 6
			}
		}
		tsVal |= (uint64(byteVal) << shift)
		tsIdx++
		shift += 7
	}
	return tsVal, tsUpdateBits, tsIdx, nil
}

func (p *PktProc) extractAddress(offset int) (uint32, uint8) {
	addrVal := uint32(0)
	mask := uint8(0x7E)
	numBits := uint8(0x7)
	shift := 0
	nextShift := 0
	totalBits := uint8(0)

	for i := 0; i < p.numAddrBytes; i++ {
		if i == 4 {
			mask = 0x0F
			numBits = 4
			switch p.addrPktIsa {
			case ocsd.ISAJazelle:
				mask = 0x1F
				numBits = 5
			case ocsd.ISAArm:
				mask = 0x07
				numBits = 3
			}
		} else if i > 0 {
			mask = 0x7F
			numBits = 7
			if i == p.numAddrBytes-1 {
				mask = 0x3F
				numBits = 6
			}
		}

		shift = nextShift
		addrVal |= uint32(p.currPacketData[i+offset]&mask) << shift
		totalBits += numBits

		if i == 0 {
			if p.addrPktIsa == ocsd.ISAJazelle {
				addrVal >>= 1
				nextShift = 6
				totalBits--
			} else {
				nextShift = 7
			}
		} else {
			nextShift += 7
		}
	}

	if p.addrPktIsa == ocsd.ISAArm {
		addrVal <<= 1
		totalBits++
	}
	return addrVal, totalBits
}

// pkt processing fns
func (p *PktProc) pktISync() error {
	var currByte uint8
	pktIndex := len(p.currPacketData) - 1
	bGotBytes := false
	validByte := true

	if pktIndex == 0 {
		p.numCtxtIDBytes = p.Config.CtxtIDBytes()
		p.gotCtxtIDBytes = 0
		p.numPktBytesReq = 6 + p.numCtxtIDBytes
	}

	for validByte && !bGotBytes {
		if currByte, validByte = p.readByteVal(); validByte {
			pktIndex = len(p.currPacketData) - 1
			if pktIndex == 5 {
				altISA := (currByte >> 2) & 0x1
				reason := (currByte >> 5) & 0x3
				p.currPacket.ISyncReason = ocsd.ISyncReason(reason)
				p.currPacket.Context.CurrNS = (currByte & 0x08) != 0
				p.currPacket.Context.CurrAltISA = (currByte & 0x04) != 0
				p.currPacket.Context.CurrHyp = (currByte & 0x02) != 0

				isa := ocsd.ISAArm
				if (p.currPacketData[1] & 0x1) != 0 {
					if altISA != 0 {
						isa = ocsd.ISATee
					} else {
						isa = ocsd.ISAThumb2
					}
				}
				p.currPacket.UpdateISA(isa)

				if reason != 0 {
					p.needCycleCount = p.Config.EnaCycleAcc()
				} else {
					p.needCycleCount = false
				}
				p.gotCycleCount = false
				if p.needCycleCount {
					p.numPktBytesReq++
				}
				p.gotCCBytes = 0
			} else if pktIndex > 5 {
				if p.needCycleCount && !p.gotCycleCount {
					if pktIndex == 6 {
						p.gotCycleCount = (currByte & 0x40) == 0
					} else {
						p.gotCycleCount = (currByte&0x80) == 0 || pktIndex == 10
					}
					p.gotCCBytes++
					if !p.gotCycleCount {
						p.numPktBytesReq++
					}
				} else if p.numCtxtIDBytes > p.gotCtxtIDBytes {
					p.gotCtxtIDBytes++
				}
			}
			bGotBytes = p.numPktBytesReq == len(p.currPacketData)
		}
	}

	if bGotBytes {
		optIdx := 6

		address := uint32(p.currPacketData[1]) & 0xFE
		address |= uint32(p.currPacketData[2]) << 8
		address |= uint32(p.currPacketData[3]) << 16
		address |= uint32(p.currPacketData[4]) << 24
		p.currPacket.UpdateAddress(ocsd.VAddr(address), 32)

		if p.needCycleCount {
			cycleCount, err := p.extractCycleCount(optIdx)
			if err != nil {
				return err
			}
			p.currPacket.CycleCount = cycleCount
			p.currPacket.CCValid = true
			optIdx += p.gotCCBytes
		}

		if p.numCtxtIDBytes > 0 {
			ctxtID, err := p.extractCtxtID(optIdx)
			if err != nil {
				return err
			}
			p.currPacket.UpdateContextID(ctxtID)
		}
		p.processState = stateSendPkt
	}
	return nil
}

func (p *PktProc) pktTrigger() error {
	p.processState = stateSendPkt
	return nil
}

func (p *PktProc) pktWPointUpdate() error {
	bDone := false
	bBytesAvail := true
	var currByte uint8
	byteIdx := 0

	if len(p.currPacketData) == 1 {
		p.gotAddrBytes = false
		p.numAddrBytes = 0
		p.gotExcepBytes = false
		p.numExcepBytes = 0
		p.addrPktIsa = ocsd.ISAUnknown
	}

	for !bDone && bBytesAvail {
		if currByte, bBytesAvail = p.readByteVal(); bBytesAvail {
			byteIdx = len(p.currPacketData) - 1
			if !p.gotAddrBytes {
				if byteIdx <= 4 {
					if (currByte & 0x80) == 0x00 {
						p.gotAddrBytes = true
						bDone = true
						p.gotExcepBytes = true
					}
				} else {
					if (currByte & 0x40) == 0x00 {
						p.gotExcepBytes = true
					}
					p.gotAddrBytes = true
					bDone = p.gotExcepBytes

					p.addrPktIsa = ocsd.ISAArm
					if (currByte & 0x20) == 0x20 {
						p.addrPktIsa = ocsd.ISAJazelle
					} else if (currByte & 0x30) == 0x10 {
						p.addrPktIsa = ocsd.ISAThumb2
					}
				}
				p.numAddrBytes++
			} else if !p.gotExcepBytes {
				p.excepAltISA = 0
				if (currByte & 0x40) == 0x40 {
					p.excepAltISA = 1
				}
				p.gotExcepBytes = true
				p.numExcepBytes++
				bDone = true
			}
		}
	}

	if bDone {
		if p.addrPktIsa == ocsd.ISAUnknown {
			p.addrPktIsa = p.currPacket.CurrISA
		}

		if p.gotExcepBytes {
			if p.addrPktIsa == ocsd.ISATee && p.excepAltISA == 0 {
				p.addrPktIsa = ocsd.ISAThumb2
			} else if p.addrPktIsa == ocsd.ISAThumb2 && p.excepAltISA == 1 {
				p.addrPktIsa = ocsd.ISATee
			}
		}
		p.currPacket.UpdateISA(p.addrPktIsa)

		addrVal, totalBits := p.extractAddress(1)
		p.currPacket.UpdateAddress(ocsd.VAddr(addrVal), int(totalBits))
		p.processState = stateSendPkt
	}
	return nil
}

func (p *PktProc) pktIgnore() error {
	p.processState = stateSendPkt
	return nil
}

func (p *PktProc) pktCtxtID() error {
	pktIndex := len(p.currPacketData) - 1
	if pktIndex == 0 {
		p.numCtxtIDBytes = p.Config.CtxtIDBytes()
		p.gotCtxtIDBytes = 0
	}

	bGotBytes := p.numCtxtIDBytes == p.gotCtxtIDBytes
	bytesAvail := true

	for !bGotBytes && bytesAvail {
		bytesAvail = p.readByte()
		if bytesAvail {
			p.gotCtxtIDBytes++
		}
		bGotBytes = p.numCtxtIDBytes == p.gotCtxtIDBytes
	}

	if bGotBytes {
		if p.numCtxtIDBytes > 0 {
			ctxtID, err := p.extractCtxtID(1)
			if err != nil {
				return err
			}
			p.currPacket.UpdateContextID(ctxtID)
		}
		p.processState = stateSendPkt
	}
	return nil
}

func (p *PktProc) pktVMID() error {
	if currByte, ok := p.readByteVal(); ok {
		p.currPacket.UpdateVMID(currByte)
		p.processState = stateSendPkt
	}
	return nil
}

func (p *PktProc) pktAtom() error {
	pHdr := p.currPacketData[0]
	if !p.Config.EnaCycleAcc() {
		p.currPacket.SetAtomFromPHdr(pHdr)
		p.processState = stateSendPkt
	} else {
		bGotAllPktBytes := false
		byteAvail := true
		var currByte uint8

		if (pHdr & 0x40) == 0 {
			bGotAllPktBytes = true
		} else {
			for byteAvail && !bGotAllPktBytes {
				if currByte, byteAvail = p.readByteVal(); byteAvail {
					if (currByte&0x80) == 0 || len(p.currPacketData) == 5 {
						bGotAllPktBytes = true
					}
				}
			}
		}

		if bGotAllPktBytes {
			cycleCount, err := p.extractCycleCount(0)
			if err != nil {
				return err
			}
			p.currPacket.CycleCount = cycleCount
			p.currPacket.CCValid = true
			p.currPacket.SetCycleAccAtomFromPHdr(pHdr)
			p.processState = stateSendPkt
		}
	}
	return nil
}

func (p *PktProc) pktTimeStamp() error {
	var currByte uint8
	pktIndex := len(p.currPacketData) - 1
	bGotBytes := false
	byteAvail := true

	if pktIndex == 0 {
		p.gotTSBytes = false
		p.needCycleCount = p.Config.EnaCycleAcc()
		p.gotCCBytes = 0
		p.tsByteMax = 8
		if p.Config.TSPkt64() {
			p.tsByteMax = 10
		}
	}

	for byteAvail && !bGotBytes {
		if currByte, byteAvail = p.readByteVal(); byteAvail {
			if !p.gotTSBytes {
				if (currByte&0x80) == 0 || len(p.currPacketData) == p.tsByteMax {
					p.gotTSBytes = true
					if !p.needCycleCount {
						bGotBytes = true
					}
				}
			} else {
				ccContMask := uint8(0x80)
				if p.gotCCBytes == 0 {
					ccContMask = 0x40
				}
				if (currByte & ccContMask) == 0 {
					bGotBytes = true
				}
				p.gotCCBytes++
				if p.gotCCBytes == 5 {
					bGotBytes = true
				}
			}
		}
	}

	if bGotBytes {
		tsVal, tsUpdateBits, tsEndIdx, err := p.extractTS()
		if err != nil {
			return err
		}
		if p.needCycleCount {
			cycleCount, err := p.extractCycleCount(tsEndIdx)
			if err != nil {
				return err
			}
			p.currPacket.CycleCount = cycleCount
			p.currPacket.CCValid = true
		}
		p.currPacket.UpdateTimestamp(tsVal, tsUpdateBits)
		p.processState = stateSendPkt
	}
	return nil
}

func (p *PktProc) pktExceptionRet() error {
	p.processState = stateSendPkt
	return nil
}

func (p *PktProc) pktBranchAddr() error {
	currByte := p.currPacketData[0]
	bDone := false
	bBytesAvail := true
	byteIdx := 0

	if len(p.currPacketData) == 1 {
		p.gotAddrBytes = false
		p.numAddrBytes = 1
		p.needCycleCount = p.Config.EnaCycleAcc()
		p.gotCCBytes = 0
		p.gotExcepBytes = false
		p.numExcepBytes = 0
		p.addrPktIsa = ocsd.ISAUnknown

		if (currByte & 0x80) == 0 {
			p.gotAddrBytes = true
			if !p.needCycleCount {
				bDone = true
			}
			p.gotExcepBytes = true
		}
	}

	for !bDone && bBytesAvail {
		if currByte, bBytesAvail = p.readByteVal(); bBytesAvail {
			byteIdx = len(p.currPacketData) - 1
			if !p.gotAddrBytes {
				if byteIdx < 4 {
					if (currByte & 0x80) == 0x00 {
						if (currByte & 0x40) == 0x00 {
							p.gotExcepBytes = true
						}
						p.gotAddrBytes = true
						bDone = p.gotExcepBytes && !p.needCycleCount
					}
				} else {
					if (currByte & 0x40) == 0x00 {
						p.gotExcepBytes = true
					}
					p.gotAddrBytes = true
					bDone = p.gotExcepBytes && !p.needCycleCount

					p.addrPktIsa = ocsd.ISAArm
					if (currByte & 0x20) == 0x20 {
						p.addrPktIsa = ocsd.ISAJazelle
					} else if (currByte & 0x30) == 0x10 {
						p.addrPktIsa = ocsd.ISAThumb2
					}
				}
				p.numAddrBytes++
			} else if !p.gotExcepBytes {
				if p.numExcepBytes == 0 {
					if (currByte & 0x80) == 0x00 {
						p.gotExcepBytes = true
					}
					p.excepAltISA = 0
					if (currByte & 0x40) == 0x40 {
						p.excepAltISA = 1
					}
				} else {
					p.gotExcepBytes = true
				}
				p.numExcepBytes++

				if p.gotExcepBytes && !p.needCycleCount {
					bDone = true
				}
			} else if p.needCycleCount {
				if p.gotCCBytes == 0 {
					bDone = (currByte & 0x40) == 0x00
				} else {
					bDone = (currByte&0x80) == 0x00 || p.gotCCBytes == 4
				}
				p.gotCCBytes++
			} else {
				return p.malformedPacketErr("sequencing error analysing branch packet")
			}
		}
	}

	if bDone {
		if p.addrPktIsa == ocsd.ISAUnknown {
			p.addrPktIsa = p.currPacket.CurrISA
		}

		if p.gotExcepBytes {
			if p.addrPktIsa == ocsd.ISATee && p.excepAltISA == 0 {
				p.addrPktIsa = ocsd.ISAThumb2
			} else if p.addrPktIsa == ocsd.ISAThumb2 && p.excepAltISA == 1 {
				p.addrPktIsa = ocsd.ISATee
			}
		}
		p.currPacket.UpdateISA(p.addrPktIsa)

		addrVal, totalBits := p.extractAddress(0)
		p.currPacket.UpdateAddress(ocsd.VAddr(addrVal), int(totalBits))

		if p.numExcepBytes > 0 {
			E1 := p.currPacketData[p.numAddrBytes]
			ENum := uint16(E1>>1) & 0xF
			excep := ocsd.ExcpReserved

			currNS := (E1 & 0x1) != 0
			currHyp := false
			if p.numExcepBytes > 1 {
				E2 := p.currPacketData[p.numAddrBytes+1]
				currHyp = ((E2 >> 5) & 0x1) != 0
				ENum |= uint16(E2&0x1F) << 4
			}

			if ENum <= 0xF {
				v7ARExceptions := []ocsd.ArmV7Exception{
					ocsd.ExcpNoException, ocsd.ExcpDebugHalt, ocsd.ExcpSMC, ocsd.ExcpHyp,
					ocsd.ExcpAsyncDAbort, ocsd.ExcpJazelle, ocsd.ExcpReserved, ocsd.ExcpReserved,
					ocsd.ExcpReset, ocsd.ExcpUndef, ocsd.ExcpSVC, ocsd.ExcpPrefAbort,
					ocsd.ExcpSyncDataAbort, ocsd.ExcpGeneric, ocsd.ExcpIRQ, ocsd.ExcpFIQ,
				}
				excep = v7ARExceptions[ENum]
			}
			p.currPacket.SetException(excep, ENum, currNS, currHyp)
		}

		if p.needCycleCount {
			countIdx := p.numAddrBytes + p.numExcepBytes
			cycleCount, err := p.extractCycleCount(countIdx)
			if err != nil {
				return err
			}
			p.currPacket.CycleCount = cycleCount
			p.currPacket.CCValid = true
		}
		p.processState = stateSendPkt
	}
	return nil
}

func (p *PktProc) pktReserved() error {
	p.processState = stateSendPkt
	return nil
}

func (p *PktProc) buildIPacketTable() {
	for i := range 256 {
		if (i & 0x01) == 0x01 {
			p.iTable[i].pktType = PktBranchAddress
			p.iTable[i].action = decodeBranchAddr
		} else if (i & 0x81) == 0x80 {
			p.iTable[i].pktType = PktAtom
			p.iTable[i].action = decodeAtom
		} else {
			p.iTable[i].pktType = PktReserved
			p.iTable[i].action = decodeReserved
		}
	}

	p.iTable[0x00].pktType = PktASync
	p.iTable[0x00].action = decodeASync

	p.iTable[0x08].pktType = PktISync
	p.iTable[0x08].action = decodeISync

	p.iTable[0x72].pktType = PktWPointUpdate
	p.iTable[0x72].action = decodeWPointUpdate

	p.iTable[0x0C].pktType = PktTrigger
	p.iTable[0x0C].action = decodeTrigger

	p.iTable[0x6E].pktType = PktContextID
	p.iTable[0x6E].action = decodeCtxtID

	p.iTable[0x3C].pktType = PktVMID
	p.iTable[0x3C].action = decodeVMID

	p.iTable[0x42].pktType = PktTimestamp
	p.iTable[0x42].action = decodeTimeStamp
	p.iTable[0x46].pktType = PktTimestamp
	p.iTable[0x46].action = decodeTimeStamp

	p.iTable[0x76].pktType = PktExceptionRet
	p.iTable[0x76].action = decodeExceptionRet

	p.iTable[0x66].pktType = PktIgnore
	p.iTable[0x66].action = decodeIgnore
}
