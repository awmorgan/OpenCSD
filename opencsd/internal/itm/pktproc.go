package itm

import (
	"bytes"
	"errors"
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

type packetDecodeState int

const (
	decodeNone packetDecodeState = iota
	decodeData
	decodeAsync
	decodeLocalTS
	decodeExtension
	decodeGlobalTS1
	decodeGlobalTS2
)

// PktProc converts incoming byte stream into ITM packets
type PktProc struct {
	common.ProcBase[Packet]
	Config     *Config
	PktOutI    ocsd.PacketProcessor[Packet]
	PktRawMonI ocsd.PacketMonitor[Packet]

	procState processState

	currPacket  Packet
	bStreamSync bool
	dataIn      []byte
	dataInSize  uint32
	dataInUsed  uint32
	dataReader  *bytes.Reader
	packetIndex ocsd.TrcIndex

	headerByte        uint8
	packetData        []uint8
	sentNotSyncPacket bool
	syncStart         bool
	dumpUnsyncedBytes int

	decodeState packetDecodeState
}

// NewPktProc creates a new ITM packet processor.
func NewPktProc(cfg *Config, _ ocsd.Logger) *PktProc {
	instID := 0
	if cfg != nil {
		instID = int(cfg.TraceID())
	}
	p := &PktProc{
		ProcBase: common.ProcBase[Packet]{
			Name: fmt.Sprintf("PKTP_ITM_%d", instID),
		},
	}
	p.ResetStats()
	p.ConfigureSupportedOpModes(ocsd.OpflgPktprocCommon)
	p.resetProcessorState()
	if cfg != nil {
		_ = p.SetProtocolConfig(cfg)
	}
	return p
}

// SetPktOut attaches the downstream packet decoder.
func (p *PktProc) SetPktOut(out ocsd.PacketProcessor[Packet]) { p.PktOutI = out }

// PktOut returns the downstream packet decoder.
func (p *PktProc) PktOut() ocsd.PacketProcessor[Packet] { return p.PktOutI }

// SetPktRawMonitor attaches a raw packet monitor.
func (p *PktProc) SetPktRawMonitor(mon ocsd.PacketMonitor[Packet]) { p.PktRawMonI = mon }

func (p *PktProc) outputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	if p.PktOutI != nil {
		return p.PktOutI.PacketDataIn(ocsd.OpData, indexSOP, pkt)
	}
	return ocsd.RespCont
}

func (p *PktProc) outputRawPacketToMonitor(indexSOP ocsd.TrcIndex, pkt *Packet, pData []byte) {
	if p.PktRawMonI != nil && len(pData) > 0 {
		p.PktRawMonI.RawPacketDataMon(ocsd.OpData, indexSOP, pkt, pData)
	}
}

func (p *PktProc) outputOnAllInterfaces(indexSOP ocsd.TrcIndex, pkt *Packet, pktType PktType, pktData []byte) ocsd.DatapathResp {
	if len(pktData) > 0 {
		p.outputRawPacketToMonitor(indexSOP, pkt, pktData)
	}
	return p.outputDecodedPacket(indexSOP, pkt)
}

func (p *PktProc) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	var processed uint32 = 0
	var err error

	switch op {
	case ocsd.OpData:
		if len(dataBlock) == 0 {
			err = fmt.Errorf("%w: packet processor: zero length data block", ocsd.ErrInvalidParamVal)
			resp = ocsd.RespFatalInvalidParam
		} else {
			processed, resp, err = p.ProcessData(index, dataBlock)
		}
	case ocsd.OpEOT:
		resp = p.OnEOT()
		if out := p.PktOutI; out != nil && !ocsd.DataRespIsFatal(resp) {
			resp = out.PacketDataIn(ocsd.OpEOT, 0, nil)
		}
		if rawMon := p.PktRawMonI; rawMon != nil {
			rawMon.RawPacketDataMon(ocsd.OpEOT, 0, nil, nil)
		}
	case ocsd.OpFlush:
		resp = p.OnFlush()
		if out := p.PktOutI; ocsd.DataRespIsCont(resp) && out != nil {
			resp = out.PacketDataIn(ocsd.OpFlush, 0, nil)
		}
	case ocsd.OpReset:
		if out := p.PktOutI; out != nil {
			resp = out.PacketDataIn(ocsd.OpReset, index, nil)
		}
		if !ocsd.DataRespIsFatal(resp) {
			resp = p.OnReset()
		}
		if rawMon := p.PktRawMonI; rawMon != nil {
			rawMon.RawPacketDataMon(ocsd.OpReset, index, nil, nil)
		}
	default:
			err = fmt.Errorf("%w: packet processor: unknown datapath operation", ocsd.ErrInvalidParamVal)
		resp = ocsd.RespFatalInvalidOp
	}
	return processed, resp, err
}

func (p *PktProc) SetProtocolConfig(config *Config) error {
	if config != nil {
		p.Config = config
		return nil
	}
	return ocsd.ErrInvalidParamVal
}

func (p *PktProc) resetProcessorState() {
	p.setProcUnsynced()
	p.resetNextPacket()
	p.sentNotSyncPacket = false
	p.syncStart = false
	p.dumpUnsyncedBytes = 0
}

func (p *PktProc) resetNextPacket() {
	p.packetData = p.packetData[:0] // clear
	p.currPacket.Reset()
	p.decodeState = decodeNone
}

func (p *PktProc) setProcUnsynced() {
	p.procState = procWaitSync
	p.bStreamSync = false
}

func (p *PktProc) dataToProcess() bool {
	if p.procState == procSendPkt {
		return true
	}
	return p.dataReader != nil && p.dataReader.Len() > 0
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	var err error
	p.dataIn = dataBlock
	p.dataInSize = uint32(len(dataBlock))
	p.dataInUsed = 0
	p.dataReader = bytes.NewReader(dataBlock)

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
		resp = p.waitForSync(index)
		return resp, nil, true
	case procHdr:
		p.packetIndex = index + ocsd.TrcIndex(p.dataInUsed)
		err = p.ProcessHdr() // sets procState for valid headers.
		if errResp, loopErr, errHandled := p.handleProcError(err); errHandled {
			return errResp, loopErr, true
		}
		if p.procState != procData {
			break
		}
		fallthrough
	case procData:
		err = p.runDataDecodeState()
		if errResp, loopErr, errHandled := p.handleProcError(err); errHandled {
			return errResp, loopErr, true
		}
		if p.procState != procSendPkt {
			break
		}
		fallthrough
	case procSendPkt:
		resp = p.outputPacket()
		return resp, nil, true
	}
	return resp, nil, false
}

func (p *PktProc) handleProcError(err error) (resp ocsd.DatapathResp, outErr error, handled bool) {
	if err == nil {
		return ocsd.RespCont, nil, false
	}

	if (errors.Is(err, ocsd.ErrBadPacketSeq) || errors.Is(err, ocsd.ErrInvalidPcktHdr)) &&
		(p.ComponentOpMode()&ocsd.OpflgPktprocErrBadPkts) == 0 {
		resp = p.outputPacket()
		if (p.ComponentOpMode() & ocsd.OpflgPktprocUnsyncOnBadPkts) != 0 {
			p.procState = procWaitSync
		}
		return resp, nil, true
	}
	return ocsd.RespFatalInvalidData, err, true
}

func (p *PktProc) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if p.procState == procData {
		p.currPacket.UpdateErrType(PktIncompleteEOT)
		resp = p.outputPacket()
	}
	return resp
}

func (p *PktProc) OnReset() ocsd.DatapathResp {
	p.resetProcessorState()
	return ocsd.RespCont
}

func (p *PktProc) OnFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (p *PktProc) IsBadPacket() bool {
	return p.currPacket.IsBadPacket()
}

func (p *PktProc) outputPacket() ocsd.DatapathResp {
	resp := p.outputOnAllInterfaces(p.packetIndex, &p.currPacket, p.currPacket.Type, p.packetData)
	p.packetData = p.packetData[:0]
	p.resetNextPacket()
	if p.bStreamSync {
		p.procState = procHdr
	} else {
		p.procState = procWaitSync
	}
	return resp
}

// setBadSequenceError records a bad-sequence error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setBadSequenceError(msg string) error {
	p.currPacket.UpdateErrType(PktBadSequence)
	return fmt.Errorf("%w: %s", ocsd.ErrBadPacketSeq, msg)
}

// setReservedHdrError records a reserved-header error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setReservedHdrError(msg string) error {
	p.currPacket.SetPacketType(PktReserved)
	return fmt.Errorf("%w: %s", ocsd.ErrInvalidPcktHdr, msg)
}

func (p *PktProc) savePacketByte(val byte) {
	p.packetData = append(p.packetData, val)
}

func (p *PktProc) readByte() (byte, bool) {
	if p.dataReader != nil {
		b, err := p.dataReader.ReadByte()
		if err == nil {
			p.dataInUsed = p.dataInSize - uint32(p.dataReader.Len())
			p.savePacketByte(b)
			return b, true
		}
	}
	return 0, false
}

func (p *PktProc) ProcessHdr() error {
	b, ok := p.readByte()
	if !ok {
		return nil
	}
	p.headerByte = b

	if (b & 0x03) != 0x00 { // Stimulus packets
		if (b & 0x4) != 0 {
			p.currPacket.SetPacketType(PktDWT)
		} else {
			p.currPacket.SetPacketType(PktSWIT)
		}
		p.decodeState = decodeData
		p.procState = procData
	} else if (b & 0x0F) == 0x00 {
		switch b & 0xF0 {
		case 0x00:
			p.currPacket.SetPacketType(PktAsync)
			p.decodeState = decodeAsync
			p.procState = procData
		case 0x70:
			p.currPacket.SetPacketType(PktOverflow)
			p.procState = procSendPkt
		default:
			p.currPacket.SetPacketType(PktTSLocal)
			p.decodeState = decodeLocalTS
			p.procState = procData
		}
	} else if (b & 0x0B) == 0x08 {
		p.currPacket.SetPacketType(PktExtension)
		p.decodeState = decodeExtension
		p.procState = procData
	} else if (b & 0xDF) == 0x94 {
		if (b & 0x20) == 0x00 {
			p.currPacket.SetPacketType(PktTSGlobal1)
			p.decodeState = decodeGlobalTS1
		} else {
			p.currPacket.SetPacketType(PktTSGlobal2)
			p.decodeState = decodeGlobalTS2
		}
		p.procState = procData
	} else {
		return p.setReservedHdrError("")
	}
	return nil
}

func (p *PktProc) runDataDecodeState() error {
	switch p.decodeState {
	case decodeData:
		return p.PktData()
	case decodeAsync:
		return p.PktAsync()
	case decodeLocalTS:
		return p.PktLocalTS()
	case decodeExtension:
		return p.PktExtension()
	case decodeGlobalTS1:
		return p.PktGlobalTS1()
	case decodeGlobalTS2:
		return p.PktGlobalTS2()
	default:
		return p.setBadSequenceError("ITM packet decode state not set")
	}
}

func (p *PktProc) PktData() error {
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
	return nil
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

func (p *PktProc) extractContVal32() (uint32, error) {
	if len(p.packetData) == 0 {
		return 0, nil
	}
	var value uint32 = 0
	shift := 0
	idxMax := len(p.packetData) - 1

	for idx := 1; idx <= idxMax; idx++ {
		part := uint32(p.packetData[idx] & 0x7F)
		if shift >= 32 {
			return 0, p.setBadSequenceError("Continuation value exceeds 32-bit width")
		}
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				return 0, p.setBadSequenceError("Continuation value overflows 32-bit width")
			}
		}
		value |= (part << shift)
		shift += 7
	}
	return value, nil
}

func (p *PktProc) extractContVal64() (uint64, error) {
	if len(p.packetData) == 0 {
		return 0, nil
	}
	var value uint64 = 0
	shift := 0
	idxMax := len(p.packetData) - 1

	for idx := 1; idx <= idxMax; idx++ {
		part := uint64(p.packetData[idx] & 0x7F)
		if shift >= 64 {
			return 0, p.setBadSequenceError("Continuation value exceeds 64-bit width")
		}
		if shift > 57 {
			maxPart := (uint64(1) << uint(64-shift)) - 1
			if part > maxPart {
				return 0, p.setBadSequenceError("Continuation value overflows 64-bit width")
			}
		}
		value |= (part << shift)
		shift += 7
	}
	return value, nil
}

func (p *PktProc) PktLocalTS() error {
	const pktSizeLimit = 5
	bGotContVal := false

	if len(p.packetData) == 1 {
		if (p.headerByte & 0x80) != 0 {
			p.currPacket.SetSrcID((p.headerByte >> 4) & 0x3)
		} else {
			p.currPacket.SetSrcID(0)
			p.currPacket.SetValue(uint32((p.headerByte>>4)&0x7), 1)
			p.procState = procSendPkt
			return nil
		}
	}

	bGotContVal = p.readContBytes(pktSizeLimit)

	if bGotContVal {
		v, err := p.extractContVal32()
		if err != nil {
			return err
		}
		p.currPacket.SetValue(v, uint8(len(p.packetData)-1))
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("Local TS packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) PktGlobalTS1() error {
	const pktSizeLimit = 5
	bGotContVal := p.readContBytes(pktSizeLimit)

	if bGotContVal {
		if len(p.packetData) == 5 {
			b := p.packetData[4]
			p.currPacket.SetSrcID((b >> 5) & 0x3)
			p.packetData[4] = b & 0x1F
		}
		v, err := p.extractContVal32()
		if err != nil {
			return err
		}
		p.currPacket.SetValue(v, uint8(len(p.packetData)-1))
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("GTS1 packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) PktGlobalTS2() error {
	const pktSizeLimit = 7
	bGotContVal := p.readContBytes(pktSizeLimit)

	if bGotContVal {
		if len(p.packetData) <= 5 {
			v, err := p.extractContVal32()
			if err != nil {
				return err
			}
			p.currPacket.SetValue(v, uint8(len(p.packetData)-1))
		} else {
			v, err := p.extractContVal64()
			if err != nil {
				return err
			}
			p.currPacket.SetExtValue(v)
		}
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("GTS2 packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) PktExtension() error {
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
			var err error
			value, err = p.extractContVal32()
			if err != nil {
				return err
			}
			value <<= 3
		}
		value |= uint32((p.headerByte >> 4) & 0x7)
		p.currPacket.SetValue(value, 4)
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("Extension packet: Payload continuation value too long")
	}
	return nil
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

func (p *PktProc) PktAsync() error {
	bFoundAsync, bError := p.readAsyncSeq()
	if bFoundAsync {
		p.procState = procSendPkt
	} else if bError {
		return p.setBadSequenceError("Async Packet: unexpected none zero value")
	}
	return nil
}

func (p *PktProc) flushUnsyncedBytes() ocsd.DatapathResp {
	resp := ocsd.RespCont

	p.outputRawPacketToMonitor(p.packetIndex, &p.currPacket, p.packetData[:p.dumpUnsyncedBytes])

	if !p.sentNotSyncPacket {
		resp = p.outputDecodedPacket(p.packetIndex, &p.currPacket)
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
