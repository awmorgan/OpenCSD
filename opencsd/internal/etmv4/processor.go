package etmv4

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type ProcessState int

const (
	ProcHdr ProcessState = iota
	ProcData
	SendPkt
	SendUnsynced
	ProcErr
)

// TInfoSect are flags to indicate processing progress for these sections is complete.
type TInfoSect uint8

const (
	TInfoInfoSect TInfoSect = 0x01
	TInfoKeySect  TInfoSect = 0x02
	TInfoSpecSect TInfoSect = 0x04
	TInfoCyctSect TInfoSect = 0x08
	TInfoWndwSect TInfoSect = 0x10
	TInfoCtrl     TInfoSect = 0x20
	TInfoAllSect  TInfoSect = 0x1F
	TInfoAll      TInfoSect = 0x3F
)

type TInfoPktProg struct {
	SectFlags uint8
	CtrlBytes uint8
}

// pktHandler is a function that processes one byte of packet data.
type pktHandler func(lastByte uint8)

// tableEntry maps a header byte to a packet type and handler.
type tableEntry struct {
	pktType PktType
	fn      pktHandler
}

// Processor parses byte streams for ETMv4 packets.
// Ported from TrcPktProcEtmV4I.
type Processor struct {
	config Config

	// output interface
	pktOut interfaces.PktDataIn[TracePacket]

	processState ProcessState

	// packet data
	currPacketData       []byte
	currPacket           TracePacket
	pktFn                pktHandler
	packetIndex          ocsd.TrcIndex
	blockIndex           ocsd.TrcIndex
	updateOnUnsyncPktIdx ocsd.TrcIndex

	// syncing
	isSync            bool
	firstTraceInfo    bool
	sentNotsyncPacket bool
	dumpUnsyncedBytes int

	isInit bool // initialized

	// header byte lookup table
	iTable [256]tableEntry

	// TraceInfo packet parsing state
	tinfoSections TInfoPktProg

	// address and context state
	addrBytes     int
	addrIS        uint8
	bAddr64bit    bool
	vmidBytes     int
	ctxtidBytes   int
	bCtxtInfoDone bool
	addrDone      bool

	// timestamp state
	ccountDone bool // done or not needed
	tsDone     bool
	tsBytes    int

	// exception
	excepSize int

	// cycle count / speculative resolution
	countDone         bool
	commitDone        bool
	hasCount          bool
	ccF2MaxSpecCommit bool

	// Q packet state
	qType     int
	addrShort bool
	addrMatch bool
	qE        uint8

	// conditional result F1 state
	f1P1Done bool
	f1P2Done bool
	f1HasP2  bool
}

// Ensure the struct satisfies TrcDataIn
var _ interfaces.TrcDataIn = (*Processor)(nil)

// NewProcessor creates and initializes a new ETMv4 packet Processor.
func NewProcessor(config *Config) *Processor {
	p := &Processor{
		config:       *config,
		processState: ProcHdr,
	}
	p.buildIPacketTable()
	p.currPacket.ProtocolVersion = config.FullVersion()
	p.isInit = true
	return p
}

// SetPktOut attaches the packet processor output sink.
func (p *Processor) SetPktOut(cb interfaces.PktDataIn[TracePacket]) {
	p.pktOut = cb
}

// TraceDataIn implements interfaces.TrcDataIn.
func (p *Processor) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
	switch op {
	case ocsd.OpData:
		return p.processData(index, dataBlock)
	case ocsd.OpEOT:
		return 0, p.onEOT()
	case ocsd.OpReset:
		return 0, p.onReset()
	case ocsd.OpFlush:
		return 0, p.onFlush()
	}
	return 0, ocsd.RespCont
}

func (p *Processor) processData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
	if !p.isInit {
		return 0, ocsd.RespFatalNotInit
	}

	p.blockIndex = index
	resp := ocsd.RespCont
	consumed := 0

	for consumed < len(dataBlock) || p.processState == SendPkt {
		switch p.processState {
		case ProcHdr:
			p.packetIndex = p.blockIndex + ocsd.TrcIndex(consumed)
			if p.isSync {
				nextByte := dataBlock[consumed]
				p.pktFn = p.iTable[nextByte].fn
				p.currPacket.Type = p.iTable[nextByte].pktType
			} else {
				p.pktFn = p.iNotSync
				p.currPacket.Type = PktNotSync
			}
			p.processState = ProcData
			fallthrough

		case ProcData:
			for consumed < len(dataBlock) && p.processState == ProcData {
				nextByte := dataBlock[consumed]
				p.currPacketData = append(p.currPacketData, nextByte)
				consumed++
				if p.pktFn != nil {
					p.pktFn(nextByte)
				}
			}

		case SendPkt:
			resp = p.outputPacket()
			p.initPacketState()
			p.processState = ProcHdr

		case SendUnsynced:
			resp = p.outputUnsyncedRawPacket()
			if p.updateOnUnsyncPktIdx != 0 {
				p.packetIndex = p.updateOnUnsyncPktIdx
				p.updateOnUnsyncPktIdx = 0
			}
			p.processState = ProcData

		case ProcErr:
			return uint32(consumed), resp
		}

		if resp != ocsd.RespCont {
			break
		}
	}

	return uint32(consumed), resp
}

func (p *Processor) onEOT() ocsd.DatapathResp {
	if !p.isInit {
		return ocsd.RespFatalNotInit
	}
	if len(p.currPacketData) != 0 {
		p.currPacket.ErrType = PktIncompleteEOT
		resp := p.outputPacket()
		p.initPacketState()
		return resp
	}
	return ocsd.RespCont
}

func (p *Processor) onReset() ocsd.DatapathResp {
	if !p.isInit {
		return ocsd.RespFatalNotInit
	}
	p.initProcessorState()
	return ocsd.RespCont
}

func (p *Processor) onFlush() ocsd.DatapathResp {
	if !p.isInit {
		return ocsd.RespFatalNotInit
	}
	return ocsd.RespCont
}

func (p *Processor) initPacketState() {
	p.currPacketData = p.currPacketData[:0]
	p.currPacket = TracePacket{}
	p.currPacket.ProtocolVersion = p.config.FullVersion()
	p.updateOnUnsyncPktIdx = 0
}

func (p *Processor) initProcessorState() {
	p.initPacketState()
	p.pktFn = p.iNotSync
	p.packetIndex = 0
	p.isSync = false
	p.firstTraceInfo = false
	p.sentNotsyncPacket = false
	p.processState = ProcHdr
}

func (p *Processor) outputPacket() ocsd.DatapathResp {
	if p.pktOut == nil {
		return ocsd.RespCont
	}
	pkt := p.currPacket
	return p.pktOut.PacketDataIn(ocsd.OpData, p.packetIndex, &pkt) //nolint:gosec
}

func (p *Processor) outputUnsyncedRawPacket() ocsd.DatapathResp {
	n := p.dumpUnsyncedBytes
	if !p.sentNotsyncPacket {
		resp := p.outputPacket()
		p.sentNotsyncPacket = true
		if n <= len(p.currPacketData) {
			p.currPacketData = p.currPacketData[n:]
		} else {
			p.currPacketData = p.currPacketData[:0]
		}
		return resp
	}
	if n <= len(p.currPacketData) {
		p.currPacketData = p.currPacketData[n:]
	} else {
		p.currPacketData = p.currPacketData[:0]
	}
	return ocsd.RespCont
}

// ============================
// Packet handlers
// ============================

func (p *Processor) iNotSync(lastByte uint8) {
	if lastByte == 0x00 {
		if len(p.currPacketData) > 1 {
			p.dumpUnsyncedBytes = len(p.currPacketData) - 1
			p.processState = SendUnsynced
			p.updateOnUnsyncPktIdx = p.blockIndex + ocsd.TrcIndex(len(p.currPacketData)) - 1
		} else {
			p.packetIndex = p.blockIndex + ocsd.TrcIndex(len(p.currPacketData)) - 1
		}
		p.pktFn = p.iTable[lastByte].fn
	} else if len(p.currPacketData) >= 8 {
		p.dumpUnsyncedBytes = len(p.currPacketData)
		p.processState = SendUnsynced
		p.updateOnUnsyncPktIdx = p.blockIndex + ocsd.TrcIndex(len(p.currPacketData))
	}
}

func (p *Processor) iPktNoPayload(lastByte uint8) {
	switch p.currPacket.Type {
	case PktAddrMatch, ETE_PktSrcAddrMatch:
		p.currPacket.AddrExactMatchIdx = lastByte & 0x3
	case PktEvent:
		p.currPacket.EventVal = lastByte & 0xF
	case PktNumDsMkr, PktUnnumDsMkr:
		p.currPacket.DsmVal = lastByte & 0x7
	}
	p.processState = SendPkt
}

func (p *Processor) iPktReserved(lastByte uint8) {
	p.currPacket.ErrType = p.currPacket.Type
	p.currPacket.ErrHdrVal = lastByte
	p.currPacket.Type = PktReserved
	p.processState = SendPkt
}

func (p *Processor) iPktInvalidCfg(lastByte uint8) {
	p.currPacket.ErrType = p.currPacket.Type
	p.currPacket.ErrHdrVal = lastByte
	p.currPacket.Type = PktReservedCfg
	p.processState = SendPkt
}

func (p *Processor) iPktExtension(lastByte uint8) {
	if len(p.currPacketData) == 2 {
		if !p.isSync && lastByte != 0x00 {
			p.pktFn = p.iNotSync
			p.currPacket.Type = PktNotSync
			return
		}
		switch lastByte {
		case 0x03:
			p.currPacket.Type = PktDiscard
			p.processState = SendPkt
		case 0x05:
			p.currPacket.Type = PktOverflow
			p.processState = SendPkt
		case 0x00:
			p.currPacket.Type = PktAsync
			p.pktFn = p.iPktASync
		default:
			p.currPacket.ErrType = p.currPacket.Type
			p.currPacket.Type = PktBadSequence
			p.processState = SendPkt
		}
	}
}

func (p *Processor) iPktASync(lastByte uint8) {
	if lastByte != 0x00 {
		if !p.isSync && len(p.currPacketData) != 12 {
			p.pktFn = p.iNotSync
			p.currPacket.Type = PktNotSync
			return
		}
		p.processState = SendPkt
		if len(p.currPacketData) != 12 || lastByte != 0x80 {
			p.currPacket.Type = PktBadSequence
			p.currPacket.ErrType = PktAsync
		} else {
			p.isSync = true
		}
	} else if len(p.currPacketData) == 12 {
		if !p.isSync {
			p.dumpUnsyncedBytes = 1
			p.processState = SendUnsynced
		} else {
			p.currPacket.Type = PktBadSequence
			p.currPacket.ErrType = PktAsync
			p.processState = SendPkt
		}
	}
}

func (p *Processor) iPktTraceInfo(lastByte uint8) {
	switch len(p.currPacketData) {
	case 1: // header
		p.tinfoSections.SectFlags = 0
		p.tinfoSections.CtrlBytes = 1
	case 2: // first payload control byte
		p.tinfoSections.SectFlags = ^lastByte & uint8(TInfoAllSect)
		if (lastByte & 0x80) == 0x00 {
			p.tinfoSections.SectFlags |= uint8(TInfoCtrl)
		}
	default:
		switch {
		case p.tinfoSections.SectFlags&uint8(TInfoCtrl) == 0:
			if (lastByte & 0x80) == 0x00 {
				p.tinfoSections.SectFlags |= uint8(TInfoCtrl)
			}
			p.tinfoSections.CtrlBytes++
		case p.tinfoSections.SectFlags&uint8(TInfoInfoSect) == 0:
			if (lastByte & 0x80) == 0x00 {
				p.tinfoSections.SectFlags |= uint8(TInfoInfoSect)
			}
		case p.tinfoSections.SectFlags&uint8(TInfoKeySect) == 0:
			if (lastByte & 0x80) == 0x00 {
				p.tinfoSections.SectFlags |= uint8(TInfoKeySect)
			}
		case p.tinfoSections.SectFlags&uint8(TInfoSpecSect) == 0:
			if (lastByte & 0x80) == 0x00 {
				p.tinfoSections.SectFlags |= uint8(TInfoSpecSect)
			}
		case p.tinfoSections.SectFlags&uint8(TInfoCyctSect) == 0:
			if (lastByte & 0x80) == 0x00 {
				p.tinfoSections.SectFlags |= uint8(TInfoCyctSect)
			}
		case p.tinfoSections.SectFlags&uint8(TInfoWndwSect) == 0:
			if (lastByte & 0x80) == 0x00 {
				p.tinfoSections.SectFlags |= uint8(TInfoWndwSect)
			}
		}
	}

	if p.tinfoSections.SectFlags == uint8(TInfoAll) {
		idx := int(p.tinfoSections.CtrlBytes) + 1
		presSect := p.currPacketData[1] & uint8(TInfoAllSect)

		p.currPacket.TraceInfo = TraceInfo{} // clear

		if presSect&uint8(TInfoInfoSect) != 0 && idx < len(p.currPacketData) {
			var fieldVal uint32
			n := p.extractContField(p.currPacketData, idx, &fieldVal, 5)
			idx += n
			p.currPacket.TraceInfo.CCEnabled = (fieldVal & 0x1) != 0
			p.currPacket.TraceInfo.CondEnabled = uint8((fieldVal >> 1) & 0x7)
			p.currPacket.TraceInfo.P0Load = (fieldVal & (1 << 4)) != 0
			p.currPacket.TraceInfo.P0Store = (fieldVal & (1 << 5)) != 0
			p.currPacket.TraceInfo.InTransState = (fieldVal & (1 << 6)) != 0
		}
		if presSect&uint8(TInfoKeySect) != 0 && idx < len(p.currPacketData) {
			var fieldVal uint32
			n := p.extractContField(p.currPacketData, idx, &fieldVal, 5)
			idx += n
			p.currPacket.P0Key = fieldVal
		}
		if presSect&uint8(TInfoSpecSect) != 0 && idx < len(p.currPacketData) {
			var fieldVal uint32
			n := p.extractContField(p.currPacketData, idx, &fieldVal, 5)
			idx += n
			p.currPacket.CurrSpecDepth = fieldVal
			p.currPacket.TraceInfo.SpecFieldPresent = true
		}
		if presSect&uint8(TInfoCyctSect) != 0 && idx < len(p.currPacketData) {
			var fieldVal uint32
			n := p.extractContField(p.currPacketData, idx, &fieldVal, 5)
			idx += n
			p.currPacket.CCThreshold = fieldVal
		}
		// window section - unsupported in current ETE, consume but ignore.
		if presSect&uint8(TInfoWndwSect) != 0 && idx < len(p.currPacketData) {
			var fieldVal uint32
			p.extractContField(p.currPacketData, idx, &fieldVal, 5)
		}
		p.processState = SendPkt

		if !p.firstTraceInfo {
			p.currPacket.TraceInfo.InitialTInfo = true
			p.firstTraceInfo = true
		}
	}
}

func (p *Processor) iPktTimestamp(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		p.ccountDone = (lastByte & 0x1) == 0
		p.tsDone = false
		p.tsBytes = 0
	} else {
		if !p.tsDone {
			p.tsBytes++
			p.tsDone = (p.tsBytes == 9) || ((lastByte & 0x80) == 0)
		} else if !p.ccountDone {
			p.ccountDone = (lastByte & 0x80) == 0
		}
	}

	if p.tsDone && p.ccountDone {
		var tsVal uint64
		tsBytes := p.extractTSField64(p.currPacketData, 1, &tsVal)
		tsBits := tsBytes * 7
		if tsBytes >= 9 {
			tsBits = 64
		}
		if !p.currPacket.Valid.Timestamp && p.firstTraceInfo {
			tsBits = 64
		}
		p.currPacket.Timestamp = tsVal
		p.currPacket.TSBitsChanged = uint8(tsBits)
		p.currPacket.Valid.Timestamp = true

		if (p.currPacketData[0] & 0x1) == 0x1 {
			var countVal uint32
			idx := 1 + tsBytes
			p.extractContField(p.currPacketData, idx, &countVal, 3)
			ccMask := (uint32(1) << p.config.CcSize()) - 1
			countVal &= ccMask
			p.currPacket.CycleCount = countVal
			p.currPacket.Valid.CycleCount = true
		}
		p.processState = SendPkt
	}
}

func (p *Processor) iPktException(lastByte uint8) {
	switch len(p.currPacketData) {
	case 1:
		p.excepSize = 3
	case 2:
		if (lastByte & 0x80) == 0x00 {
			p.excepSize = 2
		}
		// ETE exception reset or trans failed need 3 bytes
		if p.config.MajVersion() >= 0x5 {
			excepType := (p.currPacketData[1] >> 1) & 0x1F
			if excepType == 0x0 || excepType == 0x18 {
				p.excepSize = 3
			}
		}
	}

	if len(p.currPacketData) == p.excepSize {
		excepType := uint16((p.currPacketData[1] >> 1) & 0x1F)
		addrInterp := (p.currPacketData[1] & 0x40) >> 5 | (p.currPacketData[1] & 0x1)
		mFaultPending := uint8(0)
		mType := false
		if p.config.CoreProf == ocsd.ProfileCortexM {
			mType = true
		}

		if (p.currPacketData[1] & 0x80) != 0 {
			excepType |= (uint16(p.currPacketData[2]) & 0x1F) << 5
			mFaultPending = (p.currPacketData[2] >> 5) & 0x1
		}

		p.currPacket.ExceptionInfo = ExceptionInfo{
			ExceptionType: excepType,
			AddrInterp:    addrInterp,
			MFaultPending: mFaultPending != 0,
			MType:         mType,
		}
		p.processState = SendPkt

		// ETE: map exception types to ETE packet types
		if p.config.MajVersion() >= 0x5 {
			switch excepType {
			case 0x18:
				p.currPacket.Type = ETE_PktTransFail
				p.currPacket.VAddr = 0
			case 0x0:
				p.currPacket.Type = ETE_PktPeReset
				p.currPacket.VAddr = 0
			}
		}
	}
}

func (p *Processor) iPktCycleCntF123(lastByte uint8) {
	format := p.currPacket.Type

	if len(p.currPacketData) == 1 {
		p.countDone = false
		p.commitDone = false
		p.ccF2MaxSpecCommit = false
		p.hasCount = true

		switch format {
		case PktCcntF3:
			if !p.config.CommitOpt1() {
				p.currPacket.CommitElements = (uint32(lastByte>>2)&0x3) + 1
			}
			p.currPacket.CycleCount = p.currPacket.CCThreshold + uint32(lastByte&0x3)
			p.processState = SendPkt

		case PktCcntF1:
			if (lastByte & 0x1) == 0x1 {
				p.hasCount = false
				p.countDone = true
			}
			if p.config.CommitOpt1() {
				p.commitDone = true
			}

		case PktCcntF2:
			if (lastByte & 0x1) == 0x1 {
				p.ccF2MaxSpecCommit = true
			}
		}
	} else if format == PktCcntF2 && len(p.currPacketData) == 2 {
		p.currPacket.CycleCount = p.currPacket.CCThreshold + uint32(lastByte&0xF)
		if !p.config.CommitOpt1() {
			commitOffset := 1
			if p.ccF2MaxSpecCommit {
				commitOffset = int(p.config.MaxSpecDepth()) - 15
			}
			commitElements := int(lastByte>>4&0xF) + commitOffset
			p.currPacket.CommitElements = uint32(commitElements)
		}
		p.processState = SendPkt
	} else {
		if !p.commitDone {
			p.commitDone = (lastByte & 0x80) == 0x00
		} else if !p.countDone {
			p.countDone = (lastByte & 0x80) == 0x00
		}
	}

	if format == PktCcntF1 && p.commitDone && p.countDone {
		idx := 1
		var fieldVal uint32
		if !p.config.CommitOpt1() {
			n := p.extractContField(p.currPacketData, idx, &fieldVal, 5)
			idx += n
			p.currPacket.CommitElements = fieldVal
		}
		if p.hasCount {
			p.extractContField(p.currPacketData, idx, &fieldVal, 3)
			p.currPacket.CycleCount = fieldVal + p.currPacket.CCThreshold
		} else {
			p.currPacket.CycleCount = 0
		}
		p.processState = SendPkt
	}
}

func (p *Processor) iPktSpeclRes(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		switch p.currPacket.Type {
		case PktMispredict, PktCancelF2:
			switch lastByte & 0x3 {
			case 0x1:
				p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x1, Num: 1} // E
			case 0x2:
				p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x3, Num: 2} // EE
			case 0x3:
				p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x0, Num: 1} // N
			}
			if p.currPacket.Type == PktCancelF2 {
				p.currPacket.CancelElements = 1
			} else {
				p.currPacket.CancelElements = 0
			}
			p.processState = SendPkt

		case PktCancelF3:
			if (lastByte & 0x1) != 0 {
				p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x1, Num: 1} // E
			}
			p.currPacket.CancelElements = uint32((lastByte>>1)&0x3) + 2
			p.processState = SendPkt
		}
	} else {
		if (lastByte & 0x80) == 0x00 {
			var fieldVal uint32
			p.extractContField(p.currPacketData, 1, &fieldVal, 5)
			if p.currPacket.Type == PktCommit {
				p.currPacket.CommitElements = fieldVal
			} else {
				p.currPacket.CancelElements = fieldVal
			}
			p.processState = SendPkt
		}
	}
}

func (p *Processor) iPktContext(lastByte uint8) {
	sendPacket := false

	if len(p.currPacketData) == 1 {
		if (lastByte & 0x1) == 0 {
			p.currPacket.Context.Updated = false
			p.processState = SendPkt
		}
	} else if len(p.currPacketData) == 2 {
		if (lastByte & 0xC0) == 0 {
			sendPacket = true
		} else {
			if (lastByte & 0x40) != 0 {
				p.vmidBytes = int(p.config.VmidSize()) / 8
			}
			if (lastByte & 0x80) != 0 {
				p.ctxtidBytes = int(p.config.CidSize()) / 8
			}
		}
	} else {
		if p.vmidBytes > 0 {
			p.vmidBytes--
		} else if p.ctxtidBytes > 0 {
			p.ctxtidBytes--
		}
		if p.ctxtidBytes == 0 && p.vmidBytes == 0 {
			sendPacket = true
		}
	}

	if sendPacket {
		p.extractAndSetContextInfo(p.currPacketData, 1)
		p.processState = SendPkt
	}
}

func (p *Processor) extractAndSetContextInfo(buf []byte, stIdx int) {
	if stIdx >= len(buf) {
		return
	}
	infoByte := buf[stIdx]
	p.currPacket.Context.Updated = true
	p.currPacket.Context.EL = infoByte & 0x3
	p.currPacket.Context.SF = (infoByte>>5)&0x1 != 0
	p.currPacket.Context.NS = (infoByte>>4)&0x1 != 0
	p.currPacket.Context.NSE = (infoByte>>3)&0x1 != 0

	nVMIDBytes := 0
	nCtxtIDBytes := 0
	if (infoByte & 0x40) != 0 {
		nVMIDBytes = int(p.config.VmidSize()) / 8
		p.currPacket.Context.UpdatedV = true
	}
	if (infoByte & 0x80) != 0 {
		nCtxtIDBytes = int(p.config.CidSize()) / 8
		p.currPacket.Context.UpdatedC = true
	}

	payloadIdx := stIdx + 1
	if nVMIDBytes > 0 && payloadIdx+nVMIDBytes <= len(buf) {
		var vmid uint32
		for i := 0; i < nVMIDBytes; i++ {
			vmid |= uint32(buf[payloadIdx+i]) << (i * 8)
		}
		p.currPacket.Context.VMID = vmid
		payloadIdx += nVMIDBytes
	}
	if nCtxtIDBytes > 0 && payloadIdx+nCtxtIDBytes <= len(buf) {
		var cid uint32
		for i := 0; i < nCtxtIDBytes; i++ {
			cid |= uint32(buf[payloadIdx+i]) << (i * 8)
		}
		p.currPacket.Context.CtxtID = cid
	}
	p.currPacket.Valid.Context = true
}

func (p *Processor) iPktAddrCtxt(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		p.addrIS = 0
		p.addrBytes = 4
		p.bAddr64bit = false
		p.vmidBytes = 0
		p.ctxtidBytes = 0
		p.bCtxtInfoDone = false

		switch p.currPacket.Type {
		case PktAddrCtxtL_32IS1:
			p.addrIS = 1
		case PktAddrCtxtL_32IS0:
			// defaults
		case PktAddrCtxtL_64IS1:
			p.addrIS = 1
			p.addrBytes = 8
			p.bAddr64bit = true
		case PktAddrCtxtL_64IS0:
			p.addrBytes = 8
			p.bAddr64bit = true
		}
	} else {
		if p.addrBytes == 0 {
			if !p.bCtxtInfoDone {
				p.bCtxtInfoDone = true
				if (lastByte & 0x40) != 0 {
					p.vmidBytes = int(p.config.VmidSize()) / 8
				}
				if (lastByte & 0x80) != 0 {
					p.ctxtidBytes = int(p.config.CidSize()) / 8
				}
			} else {
				if p.vmidBytes > 0 {
					p.vmidBytes--
				} else if p.ctxtidBytes > 0 {
					p.ctxtidBytes--
				}
			}
		} else {
			p.addrBytes--
		}

		if p.addrBytes == 0 && p.bCtxtInfoDone && p.vmidBytes == 0 && p.ctxtidBytes == 0 {
			stIdx := 1
			if p.bAddr64bit {
				var val64 uint64
				n := p.extract64BitLongAddr(p.currPacketData, stIdx, p.addrIS, &val64)
				stIdx += n
				p.currPacket.VAddr = ocsd.VAddr(val64)
				p.currPacket.VAddrISA = p.addrIS
			} else {
				var val32 uint32
				n := p.extract32BitLongAddr(p.currPacketData, stIdx, p.addrIS, &val32)
				stIdx += n
				p.currPacket.VAddr = ocsd.VAddr(val32)
				p.currPacket.VAddrISA = p.addrIS
			}
			p.extractAndSetContextInfo(p.currPacketData, stIdx)
			p.processState = SendPkt
		}
	}
}

func (p *Processor) iPktShortAddr(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		p.addrDone = false
		p.addrIS = 0
		if lastByte == uint8(PktAddrS_IS1)&0xFF || lastByte == uint8(ETE_PktSrcAddrS_IS1)&0xFF {
			p.addrIS = 1
		}
	} else if !p.addrDone {
		p.addrDone = (len(p.currPacketData) == 3) || ((lastByte & 0x80) == 0x00)
	}

	if p.addrDone {
		var addrVal uint32
		var bits int
		p.extractShortAddrFromBuf(p.currPacketData, 1, p.addrIS, &addrVal, &bits)
		p.currPacket.VAddr = p.updateShortAddress(p.currPacket.VAddr, addrVal, p.addrIS, bits)
		p.currPacket.VAddrISA = p.addrIS
		p.processState = SendPkt
	}
}

func (p *Processor) iPktLongAddr(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		p.addrIS = 0
		p.bAddr64bit = false
		p.addrBytes = 4

		switch p.currPacket.Type {
		case PktAddrL_32IS1, ETE_PktSrcAddrL_32IS1:
			p.addrIS = 1
		case PktAddrL_64IS1, ETE_PktSrcAddrL_64IS1:
			p.addrIS = 1
			p.addrBytes = 8
			p.bAddr64bit = true
		case PktAddrL_64IS0, ETE_PktSrcAddrL_64IS0:
			p.addrBytes = 8
			p.bAddr64bit = true
		}
	}

	if len(p.currPacketData) == 1+p.addrBytes {
		stIdx := 1
		if p.bAddr64bit {
			var val64 uint64
			p.extract64BitLongAddr(p.currPacketData, stIdx, p.addrIS, &val64)
			p.currPacket.VAddr = ocsd.VAddr(val64)
		} else {
			var val32 uint32
			p.extract32BitLongAddr(p.currPacketData, stIdx, p.addrIS, &val32)
			p.currPacket.VAddr = ocsd.VAddr(val32)
		}
		p.currPacket.VAddrISA = p.addrIS
		p.processState = SendPkt
	}
}

func (p *Processor) iPktQ(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		p.qType = int(lastByte & 0xF)
		p.addrBytes = 0
		p.countDone = false
		p.addrShort = true
		p.addrMatch = false
		p.addrIS = 1
		p.qE = 0

		switch p.qType {
		case 0x0, 0x1, 0x2:
			p.addrMatch = true
			p.qE = uint8(p.qType & 0x3)
			p.countDone = false // need to read count

		case 0xC:
			// count only, no address

		case 0x5:
			p.addrIS = 0
			p.addrBytes = 2
		case 0x6:
			p.addrBytes = 2

		case 0xA:
			p.addrIS = 0
			p.addrBytes = 4
			p.addrShort = false
		case 0xB:
			p.addrBytes = 4
			p.addrShort = false

		case 0xF:
			p.countDone = true // no count in type F

		default:
			p.currPacket.ErrType = p.currPacket.Type
			p.currPacket.Type = PktBadSequence
			p.processState = SendPkt
			return
		}
	} else {
		if p.addrBytes > 0 {
			if p.addrShort && p.addrBytes == 2 {
				if (lastByte & 0x80) == 0x00 {
					p.addrBytes--
				}
			}
			p.addrBytes--
		} else if !p.countDone {
			p.countDone = (lastByte & 0x80) == 0x00
		}
	}

	if p.addrBytes == 0 && p.countDone {
		idx := 1

		if p.addrMatch {
			p.currPacket.QPkt.AddrMatch = true
			p.currPacket.AddrExactMatchIdx = p.qE
		} else if len(p.currPacketData) > 1 {
			if p.addrShort {
				var qAddr uint32
				var bits int
				n := p.extractShortAddrFromBuf(p.currPacketData, idx, p.addrIS, &qAddr, &bits)
				idx += n
				p.currPacket.VAddr = p.updateShortAddress(p.currPacket.VAddr, qAddr, p.addrIS, bits)
				p.currPacket.VAddrISA = p.addrIS
			} else {
				var qAddr uint32
				n := p.extract32BitLongAddr(p.currPacketData, idx, p.addrIS, &qAddr)
				idx += n
				p.currPacket.VAddr = ocsd.VAddr(qAddr)
				p.currPacket.VAddrISA = p.addrIS
			}
		}

		if p.qType != 0xF {
			var qCount uint32
			p.extractContField(p.currPacketData, idx, &qCount, 5)
			p.currPacket.QPkt = QPkt{
				QCount:       qCount,
				AddrPresent:  !p.addrMatch,
				AddrMatch:    p.addrMatch,
				CountPresent: true,
				QType:        uint8(p.qType),
			}
		} else {
			p.currPacket.QPkt = QPkt{QType: 0xF}
		}
		p.processState = SendPkt
	}
}

func (p *Processor) iAtom(lastByte uint8) {
	var f4Patterns = [4]uint32{0xE, 0x0, 0xA, 0x5}

	switch p.currPacket.Type {
	case PktAtomF1:
		p.currPacket.Atom = ocsd.PktAtom{EnBits: uint32(lastByte & 0x1), Num: 1}

	case PktAtomF2:
		p.currPacket.Atom = ocsd.PktAtom{EnBits: uint32(lastByte & 0x3), Num: 2}

	case PktAtomF3:
		p.currPacket.Atom = ocsd.PktAtom{EnBits: uint32(lastByte & 0x7), Num: 3}

	case PktAtomF4:
		p.currPacket.Atom = ocsd.PktAtom{EnBits: f4Patterns[lastByte&0x3], Num: 4}

	case PktAtomF5:
		pattIdx := ((lastByte & 0x20) >> 3) | (lastByte & 0x3)
		switch pattIdx {
		case 5:
			p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x1E, Num: 5}
		case 1:
			p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x00, Num: 5}
		case 2:
			p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x0A, Num: 5}
		case 3:
			p.currPacket.Atom = ocsd.PktAtom{EnBits: 0x15, Num: 5}
		}

	case PktAtomF6:
		pattCount := uint32(lastByte&0x1F) + 3
		pattern := (uint32(1) << pattCount) - 1
		if (lastByte & 0x20) == 0x00 {
			pattern = 0
		}
		p.currPacket.Atom = ocsd.PktAtom{EnBits: pattern, Num: uint8(pattCount + 1)}
	}

	p.processState = SendPkt
}

func (p *Processor) iPktITE(lastByte uint8) {
	// Packet is always 10 bytes: Header, EL info byte, 8 bytes payload.
	if len(p.currPacketData) == 10 {
		var value uint64
		for i := 2; i < 10; i++ {
			value |= uint64(p.currPacketData[i]) << ((i - 2) * 8)
		}
		p.currPacket.ITEPkt = ITEPkt{
			EL:    p.currPacketData[1],
			Value: value,
		}
		p.processState = SendPkt
	}
}

// iPktCondInstr handles conditional instruction packets.
func (p *Processor) iPktCondInstr(lastByte uint8) {
	switch len(p.currPacketData) {
	case 1:
		if p.currPacket.Type == PktCondIF2 {
			p.currPacket.CondInstr.CondCKey = uint32(lastByte & 0x3)
			p.processState = SendPkt
		}
	case 2:
		if p.currPacket.Type == PktCondIF3 {
			numCElem := uint8((lastByte>>1)&0x3F) + (lastByte & 0x1)
			p.currPacket.CondInstr.NumCElem = numCElem
			p.currPacket.CondInstr.F3FinalElem = (lastByte & 0x1) == 0x1
			p.processState = SendPkt
		} else if (lastByte & 0x80) == 0x00 {
			var condKey uint32
			p.extractContField(p.currPacketData, 1, &condKey, 5)
			p.currPacket.CondInstr.CondCKey = condKey
			p.currPacket.CondInstr.CondKeySet = true
			p.processState = SendPkt
		}
	default:
		if (lastByte & 0x80) == 0x00 {
			var condKey uint32
			p.extractContField(p.currPacketData, 1, &condKey, 5)
			p.currPacket.CondInstr.CondCKey = condKey
			p.currPacket.CondInstr.CondKeySet = true
			p.processState = SendPkt
		}
	}
}

// iPktCondResult handles conditional result packets.
func (p *Processor) iPktCondResult(lastByte uint8) {
	if len(p.currPacketData) == 1 {
		p.f1P1Done = false
		p.f1P2Done = false
		p.f1HasP2 = false

		switch p.currPacket.Type {
		case PktCondResF1:
			p.f1HasP2 = true
			if (lastByte & 0xFC) == 0x6C {
				p.f1P2Done = true
				p.f1HasP2 = false
			}
		case PktCondResF2:
			if (lastByte & 0x4) != 0 {
				p.currPacket.CondResult.F2KeyIncr = 2
			} else {
				p.currPacket.CondResult.F2KeyIncr = 1
			}
			p.currPacket.CondResult.Res0 = lastByte & 0x3
			p.processState = SendPkt
		case PktCondResF3:
			// do nothing for first byte
		case PktCondResF4:
			p.currPacket.CondResult.Res0 = lastByte & 0x3
			p.processState = SendPkt
		}
	} else if p.currPacket.Type == PktCondResF3 && len(p.currPacketData) == 2 {
		f3Tokens := uint16(p.currPacketData[1])
		f3Tokens |= (uint16(p.currPacketData[0]) & 0xF) << 8
		p.currPacket.CondResult.F3Tokens = f3Tokens
		p.processState = SendPkt
	} else {
		if !p.f1P1Done {
			p.f1P1Done = (lastByte & 0x80) == 0x00
		} else if !p.f1P2Done {
			p.f1P2Done = (lastByte & 0x80) == 0x00
		}

		if p.f1P1Done && p.f1P2Done {
			var key0, key1 uint32
			var res0, res1 uint8
			stIdx := 1
			n := p.extractCondResult(p.currPacketData, stIdx, &key0, &res0)
			stIdx += n
			ci0 := p.currPacketData[0] & 0x1
			p.currPacket.CondResult.CondRKey0 = key0
			p.currPacket.CondResult.Res0 = res0
			p.currPacket.CondResult.CI0 = ci0 != 0

			if p.f1HasP2 {
				p.extractCondResult(p.currPacketData, stIdx, &key1, &res1)
				ci1 := (p.currPacketData[0] >> 1) & 0x1
				p.currPacket.CondResult.CondRKey1 = key1
				p.currPacket.CondResult.Res1 = res1
				p.currPacket.CondResult.CI1 = ci1 != 0
				p.currPacket.CondResult.KeyRes1Set = true
			}
			p.currPacket.CondResult.KeyRes0Set = true
			p.processState = SendPkt
		}
	}
}

// extractCondResult extracts a conditional result (key + result byte).
// Returns number of bytes consumed.
func (p *Processor) extractCondResult(buf []byte, stIdx int, key *uint32, result *uint8) int {
	idx := 0
	*key = 0
	incr := 0

	for idx < 6 {
		if stIdx+idx >= len(buf) {
			return idx
		}
		byteVal := buf[stIdx+idx]
		if idx == 0 {
			*result = byteVal
			*key = uint32((byteVal >> 4) & 0x7)
			incr = 3
		} else {
			*key |= uint32(byteVal&0x7F) << incr
			incr += 7
		}
		if (byteVal & 0x80) == 0 {
			idx++
			break
		}
		idx++
	}
	return idx
}

// ============================
// Extraction helpers
// ============================

// extractContField extracts a continuation-coded 32-bit value from the buffer starting at stIdx.
// Returns number of bytes consumed.
func (p *Processor) extractContField(buf []byte, stIdx int, value *uint32, byteLimit int) int {
	idx := 0
	lastByte := false
	*value = 0
	for !lastByte && idx < byteLimit {
		if stIdx+idx >= len(buf) {
			return idx
		}
		byteVal := buf[stIdx+idx]
		lastByte = (byteVal & 0x80) != 0x80
		*value |= uint32(byteVal&0x7F) << (idx * 7)
		idx++
	}
	return idx
}

// extractTSField64 extracts a 64-bit timestamp from the buffer starting at stIdx.
// Returns number of bytes consumed.
func (p *Processor) extractTSField64(buf []byte, stIdx int, value *uint64) int {
	const maxByteIdx = 8
	idx := 0
	lastByte := false
	*value = 0
	for !lastByte {
		if stIdx+idx >= len(buf) {
			return idx
		}
		byteVal := buf[stIdx+idx]
		byteValMask := uint8(0x7F)
		if idx == maxByteIdx {
			byteValMask = 0xFF
			lastByte = true
		} else {
			lastByte = (byteVal & 0x80) != 0x80
		}
		*value |= uint64(byteVal&byteValMask) << (idx * 7)
		idx++
	}
	return idx
}

// extractShortAddrFromBuf extracts a short address from the buffer.
// Returns number of bytes consumed.
func (p *Processor) extractShortAddrFromBuf(buf []byte, stIdx int, IS uint8, value *uint32, bits *int) int {
	isShift := 2
	if IS == 1 {
		isShift = 1
	}
	idx := 0
	*bits = 7
	*value = 0
	*value |= uint32(buf[stIdx+idx]&0x7F) << isShift

	if (buf[stIdx+idx] & 0x80) != 0 {
		idx++
		*value |= uint32(buf[stIdx+idx]) << (7 + isShift)
		*bits += 8
	}
	idx++
	*bits += isShift
	return idx
}

// updateShortAddress updates a VAddr with a short address value (clears lower bits, sets new ones).
func (p *Processor) updateShortAddress(existing ocsd.VAddr, addrVal uint32, IS uint8, bits int) ocsd.VAddr {
	mask := ocsd.VAddr((uint64(1) << bits) - 1)
	return (existing &^ mask) | ocsd.VAddr(addrVal)
}

// extract64BitLongAddr extracts an 8-byte 64-bit long address.
// Returns number of bytes consumed.
func (p *Processor) extract64BitLongAddr(buf []byte, stIdx int, IS uint8, value *uint64) int {
	*value = 0
	if IS == 0 {
		*value |= uint64(buf[stIdx+0]&0x7F) << 2
		*value |= uint64(buf[stIdx+1]&0x7F) << 9
	} else {
		*value |= uint64(buf[stIdx+0]&0x7F) << 1
		*value |= uint64(buf[stIdx+1]) << 8
	}
	*value |= uint64(buf[stIdx+2]) << 16
	*value |= uint64(buf[stIdx+3]) << 24
	*value |= uint64(buf[stIdx+4]) << 32
	*value |= uint64(buf[stIdx+5]) << 40
	*value |= uint64(buf[stIdx+6]) << 48
	*value |= uint64(buf[stIdx+7]) << 56
	return 8
}

// extract32BitLongAddr extracts a 4-byte 32-bit long address.
// Returns number of bytes consumed.
func (p *Processor) extract32BitLongAddr(buf []byte, stIdx int, IS uint8, value *uint32) int {
	*value = 0
	if IS == 0 {
		*value |= uint32(buf[stIdx+0]&0x7F) << 2
		*value |= uint32(buf[stIdx+1]&0x7F) << 9
	} else {
		*value |= uint32(buf[stIdx+0]&0x7F) << 1
		*value |= uint32(buf[stIdx+1]) << 8
	}
	*value |= uint32(buf[stIdx+2]) << 16
	*value |= uint32(buf[stIdx+3]) << 24
	return 4
}

// buildIPacketTable initialises p.iTable for header byte dispatch.
// Ported from TrcPktProcEtmV4I::BuildIPacketTable.
func (p *Processor) buildIPacketTable() {
	// default to reserved
	for i := 0; i < 256; i++ {
		p.iTable[i].pktType = PktReserved
		p.iTable[i].fn = p.iPktReserved
	}

	p.iTable[0x00].pktType = PktExtension
	p.iTable[0x00].fn = p.iPktExtension

	p.iTable[0x01].pktType = PktTraceInfo
	p.iTable[0x01].fn = p.iPktTraceInfo

	// timestamp b0000001x
	p.iTable[0x02].pktType = PktTimestamp
	p.iTable[0x02].fn = p.iPktTimestamp
	p.iTable[0x03].pktType = PktTimestamp
	p.iTable[0x03].fn = p.iPktTimestamp

	p.iTable[0x04].pktType = PktTraceOn
	p.iTable[0x04].fn = p.iPktNoPayload

	// V8M func return (only valid in certain configs)
	p.iTable[0x05].pktType = PktFuncRet
	if p.config.CoreProf == ocsd.ProfileCortexM && ocsd.IsV8Arch(p.config.ArchVer) && p.config.FullVersion() >= 0x42 {
		p.iTable[0x05].fn = p.iPktNoPayload
	}

	p.iTable[0x06].pktType = PktExcept
	p.iTable[0x06].fn = p.iPktException

	p.iTable[0x07].pktType = PktExceptRtn
	if p.config.MajVersion() >= 0x5 {
		p.iTable[0x07].fn = p.iPktInvalidCfg
	} else {
		p.iTable[0x07].fn = p.iPktNoPayload
	}

	// ETE TRANS/ITE packets
	if p.config.MajVersion() >= 0x5 {
		p.iTable[0x0A].pktType = ETE_PktTransSt
		p.iTable[0x0A].fn = p.iPktNoPayload
		p.iTable[0x0B].pktType = ETE_PktTransCommit
		p.iTable[0x0B].fn = p.iPktNoPayload

		if p.config.MinVersion() >= 0x3 {
			p.iTable[0x09].pktType = ETE_PktITE
			p.iTable[0x09].fn = p.iPktITE
		}
	}

	// cycle count F2/F1 - 0x0C-0x0F
	for i := 0; i < 2; i++ {
		p.iTable[0x0C+i].pktType = PktCcntF2
		p.iTable[0x0C+i].fn = p.iPktCycleCntF123
	}
	for i := 2; i < 4; i++ {
		p.iTable[0x0C+i].pktType = PktCcntF1
		p.iTable[0x0C+i].fn = p.iPktCycleCntF123
	}

	// cycle count F3 - 0x10-0x1F
	for i := 0; i < 16; i++ {
		p.iTable[0x10+i].pktType = PktCcntF3
		p.iTable[0x10+i].fn = p.iPktCycleCntF123
	}

	// NDSM 0x20-0x27
	for i := 0; i < 8; i++ {
		p.iTable[0x20+i].pktType = PktNumDsMkr
		if p.config.EnabledDataTrace() {
			p.iTable[0x20+i].fn = p.iPktNoPayload
		} else {
			p.iTable[0x20+i].fn = p.iPktInvalidCfg
		}
	}

	// UDSM 0x28-0x2C
	for i := 0; i < 5; i++ {
		p.iTable[0x28+i].pktType = PktUnnumDsMkr
		if p.config.EnabledDataTrace() {
			p.iTable[0x28+i].fn = p.iPktNoPayload
		} else {
			p.iTable[0x28+i].fn = p.iPktInvalidCfg
		}
	}

	// commit 0x2D
	p.iTable[0x2D].pktType = PktCommit
	p.iTable[0x2D].fn = p.iPktSpeclRes

	// cancel F1 0x2E-0x2F
	p.iTable[0x2E].pktType = PktCancelF1
	p.iTable[0x2E].fn = p.iPktSpeclRes
	p.iTable[0x2F].pktType = PktCancelF1Mispred
	p.iTable[0x2F].fn = p.iPktSpeclRes

	// mispredict 0x30-0x33
	for i := 0; i < 4; i++ {
		p.iTable[0x30+i].pktType = PktMispredict
		p.iTable[0x30+i].fn = p.iPktSpeclRes
	}

	// cancel F2 0x34-0x37
	for i := 0; i < 4; i++ {
		p.iTable[0x34+i].pktType = PktCancelF2
		p.iTable[0x34+i].fn = p.iPktSpeclRes
	}

	// cancel F3 0x38-0x3F
	for i := 0; i < 8; i++ {
		p.iTable[0x38+i].pktType = PktCancelF3
		p.iTable[0x38+i].fn = p.iPktSpeclRes
	}

	bCondValid := p.config.HasCondTrace() && p.config.EnabledCondITrace() != CondTrDis

	// cond I F2 0x40-0x42
	for i := 0; i < 3; i++ {
		p.iTable[0x40+i].pktType = PktCondIF2
		if bCondValid {
			p.iTable[0x40+i].fn = p.iPktCondInstr
		} else {
			p.iTable[0x40+i].fn = p.iPktInvalidCfg
		}
	}

	// cond flush 0x43
	p.iTable[0x43].pktType = PktCondFlush
	if bCondValid {
		p.iTable[0x43].fn = p.iPktNoPayload
	} else {
		p.iTable[0x43].fn = p.iPktInvalidCfg
	}

	// cond res F4 0x44-0x46
	for i := 0; i < 3; i++ {
		p.iTable[0x44+i].pktType = PktCondResF4
		if bCondValid {
			p.iTable[0x44+i].fn = p.iPktCondResult
		} else {
			p.iTable[0x44+i].fn = p.iPktInvalidCfg
		}
	}

	// cond res F2 0x48-0x4A, 0x4C-0x4E
	for i := 0; i < 3; i++ {
		p.iTable[0x48+i].pktType = PktCondResF2
		if bCondValid {
			p.iTable[0x48+i].fn = p.iPktCondResult
		} else {
			p.iTable[0x48+i].fn = p.iPktInvalidCfg
		}
	}
	for i := 0; i < 3; i++ {
		p.iTable[0x4C+i].pktType = PktCondResF2
		if bCondValid {
			p.iTable[0x4C+i].fn = p.iPktCondResult
		} else {
			p.iTable[0x4C+i].fn = p.iPktInvalidCfg
		}
	}

	// cond res F3 0x50-0x5F
	for i := 0; i < 16; i++ {
		p.iTable[0x50+i].pktType = PktCondResF3
		if bCondValid {
			p.iTable[0x50+i].fn = p.iPktCondResult
		} else {
			p.iTable[0x50+i].fn = p.iPktInvalidCfg
		}
	}

	// cond res F1 0x68-0x6B
	for i := 0; i < 4; i++ {
		p.iTable[0x68+i].pktType = PktCondResF1
		if bCondValid {
			p.iTable[0x68+i].fn = p.iPktCondResult
		} else {
			p.iTable[0x68+i].fn = p.iPktInvalidCfg
		}
	}

	// cond I F1 0x6C
	p.iTable[0x6C].pktType = PktCondIF1
	if bCondValid {
		p.iTable[0x6C].fn = p.iPktCondInstr
	} else {
		p.iTable[0x6C].fn = p.iPktInvalidCfg
	}

	// cond I F3 0x6D
	p.iTable[0x6D].pktType = PktCondIF3
	if bCondValid {
		p.iTable[0x6D].fn = p.iPktCondInstr
	} else {
		p.iTable[0x6D].fn = p.iPktInvalidCfg
	}

	// cond res F1 extra 0x6E-0x6F
	for i := 0; i < 2; i++ {
		p.iTable[0x6E+i].pktType = PktCondResF1
		if bCondValid {
			p.iTable[0x6E+i].fn = p.iPktCondResult
		} else {
			p.iTable[0x6E+i].fn = p.iPktInvalidCfg
		}
	}

	// ignore packet (ETM 4.3+) 0x70
	if p.config.FullVersion() >= 0x43 {
		p.iTable[0x70].pktType = PktIgnore
		p.iTable[0x70].fn = p.iPktNoPayload
	}

	// event trace 0x71-0x7F
	for i := 0; i < 15; i++ {
		p.iTable[0x71+i].pktType = PktEvent
		p.iTable[0x71+i].fn = p.iPktNoPayload
	}

	// context 0x80-0x81
	for i := 0; i < 2; i++ {
		p.iTable[0x80+i].pktType = PktCtxt
		p.iTable[0x80+i].fn = p.iPktContext
	}

	// addr with ctx 0x82-0x86
	p.iTable[0x82].pktType = PktAddrCtxtL_32IS0
	p.iTable[0x82].fn = p.iPktAddrCtxt
	p.iTable[0x83].pktType = PktAddrCtxtL_32IS1
	p.iTable[0x83].fn = p.iPktAddrCtxt
	p.iTable[0x85].pktType = PktAddrCtxtL_64IS0
	p.iTable[0x85].fn = p.iPktAddrCtxt
	p.iTable[0x86].pktType = PktAddrCtxtL_64IS1
	p.iTable[0x86].fn = p.iPktAddrCtxt

	// ETE TS marker 0x88
	if p.config.FullVersion() >= 0x46 {
		p.iTable[0x88].pktType = ETE_PktTSMarker
		p.iTable[0x88].fn = p.iPktNoPayload
	}

	// exact match addr 0x90-0x92
	for i := 0; i < 3; i++ {
		p.iTable[0x90+i].pktType = PktAddrMatch
		p.iTable[0x90+i].fn = p.iPktNoPayload
	}

	// short addr 0x95-0x96
	p.iTable[0x95].pktType = PktAddrS_IS0
	p.iTable[0x95].fn = p.iPktShortAddr
	p.iTable[0x96].pktType = PktAddrS_IS1
	p.iTable[0x96].fn = p.iPktShortAddr

	// long addr 32 0x9A-0x9B
	p.iTable[0x9A].pktType = PktAddrL_32IS0
	p.iTable[0x9A].fn = p.iPktLongAddr
	p.iTable[0x9B].pktType = PktAddrL_32IS1
	p.iTable[0x9B].fn = p.iPktLongAddr

	// long addr 64 0x9D-0x9E
	p.iTable[0x9D].pktType = PktAddrL_64IS0
	p.iTable[0x9D].fn = p.iPktLongAddr
	p.iTable[0x9E].pktType = PktAddrL_64IS1
	p.iTable[0x9E].fn = p.iPktLongAddr

	// Q packets 0xA0-0xAF
	for i := 0; i < 16; i++ {
		p.iTable[0xA0+i].pktType = PktQ
		switch i {
		case 0x3, 0x4, 0x7, 0x8, 0x9, 0xD, 0xE:
			// leave as reserved
		default:
			if p.config.HasQElem() {
				p.iTable[0xA0+i].fn = p.iPktQ
			}
		}
	}

	// ETE source address packets 0xB0-0xB9
	if p.config.FullVersion() >= 0x50 {
		for i := 0; i < 3; i++ {
			p.iTable[0xB0+i].pktType = ETE_PktSrcAddrMatch
			p.iTable[0xB0+i].fn = p.iPktNoPayload
		}
		p.iTable[0xB4].pktType = ETE_PktSrcAddrS_IS0
		p.iTable[0xB4].fn = p.iPktShortAddr
		p.iTable[0xB5].pktType = ETE_PktSrcAddrS_IS1
		p.iTable[0xB5].fn = p.iPktShortAddr
		p.iTable[0xB6].pktType = ETE_PktSrcAddrL_32IS0
		p.iTable[0xB6].fn = p.iPktLongAddr
		p.iTable[0xB7].pktType = ETE_PktSrcAddrL_32IS1
		p.iTable[0xB7].fn = p.iPktLongAddr
		p.iTable[0xB8].pktType = ETE_PktSrcAddrL_64IS0
		p.iTable[0xB8].fn = p.iPktLongAddr
		p.iTable[0xB9].pktType = ETE_PktSrcAddrL_64IS1
		p.iTable[0xB9].fn = p.iPktLongAddr
	}

	// atoms F6 0xC0-0xD4
	for i := 0xC0; i <= 0xD4; i++ {
		p.iTable[i].pktType = PktAtomF6
		p.iTable[i].fn = p.iAtom
	}
	// atoms F5 0xD5-0xD7
	for i := 0xD5; i <= 0xD7; i++ {
		p.iTable[i].pktType = PktAtomF5
		p.iTable[i].fn = p.iAtom
	}
	// atoms F2 0xD8-0xDB
	for i := 0xD8; i <= 0xDB; i++ {
		p.iTable[i].pktType = PktAtomF2
		p.iTable[i].fn = p.iAtom
	}
	// atoms F4 0xDC-0xDF
	for i := 0xDC; i <= 0xDF; i++ {
		p.iTable[i].pktType = PktAtomF4
		p.iTable[i].fn = p.iAtom
	}
	// atoms F6 0xE0-0xF4
	for i := 0xE0; i <= 0xF4; i++ {
		p.iTable[i].pktType = PktAtomF6
		p.iTable[i].fn = p.iAtom
	}
	// atom F5 0xF5
	p.iTable[0xF5].pktType = PktAtomF5
	p.iTable[0xF5].fn = p.iAtom
	// atoms F1 0xF6-0xF7
	for i := 0xF6; i <= 0xF7; i++ {
		p.iTable[i].pktType = PktAtomF1
		p.iTable[i].fn = p.iAtom
	}
	// atoms F3 0xF8-0xFF
	for i := 0xF8; i <= 0xFF; i++ {
		p.iTable[i].pktType = PktAtomF3
		p.iTable[i].fn = p.iAtom
	}
}