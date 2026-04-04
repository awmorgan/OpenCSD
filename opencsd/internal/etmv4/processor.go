package etmv4

import (
	"errors"
	"fmt"

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

type decodeAction int

const (
	decodeNotSync decodeAction = iota
	decodePktReserved
	decodePktExtension
	decodePktTraceInfo
	decodePktTimestamp
	decodePktNoPayload
	decodePktException
	decodePktInvalidCfg
	decodePktITE
	decodePktCycleCntF123
	decodePktSpeclRes
	decodePktCondInstr
	decodePktCondResult
	decodePktContext
	decodePktAddrCtxt
	decodePktShortAddr
	decodePktLongAddr
	decodePktQ
	decodeAtom
	decodePktASync
)

// Packet is a compatibility alias used by the stateless decoder API.
type Packet = TracePacket

var errDecodeNotImplemented = errors.New("decodeNextPacket: packet type not implemented")

// tableEntry maps a header byte to a packet type and handler.
type tableEntry struct {
	pktType PktType
	action  decodeAction
}

// Processor parses byte streams for ETMv4 packets.
// Ported from TrcPktProcEtmV4I.
type Processor struct {
	config Config

	// output interface
	pktOut ocsd.PacketProcessorExplicit[TracePacket]

	// raw packet monitor
	PktRawMonI ocsd.PacketMonitor

	processState ProcessState

	// packet data
	currPacketData       []byte
	currPacket           TracePacket
	currDecode           decodeAction
	packetIndex          ocsd.TrcIndex
	blockIndex           ocsd.TrcIndex
	blockBytesProcessed  int
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

func (p *Processor) ApplyFlags(flags uint32) error { return nil }

// Ensure the struct satisfies TrcDataProcessorExplicit
var _ ocsd.TrcDataProcessorExplicit = (*Processor)(nil)

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
func (p *Processor) SetPktOut(cb ocsd.PacketProcessorExplicit[TracePacket]) {
	p.pktOut = cb
}

func (p *Processor) SetPktRawMonitor(mon ocsd.PacketMonitor) {
	p.PktRawMonI = mon
}

// TraceDataIn implements ocsd.TrcDataProcessor.
func (p *Processor) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	switch op {
	case ocsd.OpData:
		return p.processData(index, dataBlock)
	case ocsd.OpEOT:
		return 0, ocsd.DataErrFromResp(p.onEOT(), nil)
	case ocsd.OpReset:
		return 0, ocsd.DataErrFromResp(p.onReset(), nil)
	case ocsd.OpFlush:
		return 0, ocsd.DataErrFromResp(p.onFlush(), nil)
	}
	return 0, nil
}

func (p *Processor) callPktOut(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *TracePacket) error {
	if p.pktOut == nil {
		return nil
	}
	switch op {
	case ocsd.OpData:
		return p.pktOut.TracePacketData(indexSOP, pkt)
	case ocsd.OpEOT:
		return p.pktOut.TracePacketEOT()
	case ocsd.OpFlush:
		return p.pktOut.TracePacketFlush()
	case ocsd.OpReset:
		return p.pktOut.TracePacketReset(indexSOP)
	default:
		return ocsd.ErrInvalidParamVal
	}
}

// TraceData is the explicit data-path entrypoint used by split interfaces.
func (p *Processor) TraceData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return p.TraceDataIn(ocsd.OpData, index, dataBlock)
}

// TraceDataEOT forwards an EOT control operation through the legacy multiplexer.
func (p *Processor) TraceDataEOT() error {
	_, err := p.TraceDataIn(ocsd.OpEOT, 0, nil)
	return err
}

// TraceDataFlush forwards a flush control operation through the legacy multiplexer.
func (p *Processor) TraceDataFlush() error {
	_, err := p.TraceDataIn(ocsd.OpFlush, 0, nil)
	return err
}

// TraceDataReset forwards a reset control operation through the legacy multiplexer.
func (p *Processor) TraceDataReset(index ocsd.TrcIndex) error {
	_, err := p.TraceDataIn(ocsd.OpReset, index, nil)
	return err
}

func (p *Processor) processData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	if !p.isInit {
		return 0, ocsd.ErrNotInit
	}

	p.blockIndex = index
	p.blockBytesProcessed = 0
	resp := ocsd.RespCont
	consumed := 0

	for ocsd.DataRespIsCont(resp) {
		if consumed >= len(dataBlock) && p.processState != SendPkt {
			break
		}

		if p.processState == ProcHdr && p.isSync && consumed < len(dataBlock) {
			packetIndex := p.blockIndex + ocsd.TrcIndex(consumed)
			pkt, bytesConsumed, err := decodeNextPacket(dataBlock, consumed)
			switch {
			case err == nil:
				if !p.canUseStatelessDecodeResult(pkt.Type) {
					break
				}
				p.packetIndex = packetIndex
				p.currPacket.Type = pkt.Type
				p.currPacket.Err = pkt.Err
				p.currPacket.ErrHdrVal = pkt.ErrHdrVal
				switch pkt.Type {
				case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
					p.currPacket.Atom = pkt.Atom
				case PktTraceInfo:
					p.currPacket.ClearTraceInfo()
					p.currPacket.TraceInfo = pkt.TraceInfo
					p.currPacket.P0Key = pkt.P0Key
					p.currPacket.CurrSpecDepth = pkt.CurrSpecDepth
					p.currPacket.CCThreshold = pkt.CCThreshold
					p.currPacket.Valid.TInfo = pkt.Valid.TInfo
					p.currPacket.Valid.SpecDepthValid = pkt.Valid.SpecDepthValid
					p.currPacket.Valid.CCThreshold = pkt.Valid.CCThreshold
					if !p.firstTraceInfo {
						p.currPacket.TraceInfo.InitialTInfo = true
						p.firstTraceInfo = true
					}
				case PktTimestamp:
					p.currPacket.Timestamp = pkt.Timestamp
					p.currPacket.TSBitsChanged = pkt.TSBitsChanged
					p.currPacket.CycleCount = pkt.CycleCount
					p.currPacket.Valid.Timestamp = pkt.Valid.Timestamp
					p.currPacket.Valid.CycleCount = pkt.Valid.CycleCount
				case PktCcntF3:
					if !p.config.CommitOpt1() {
						p.currPacket.CommitElements = pkt.CommitElements
						p.currPacket.Valid.CommitElem = true
					}
					p.currPacket.CycleCount = p.currPacket.CCThreshold + pkt.CycleCount
					p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
				case PktCcntF2:
					p.currPacket.CycleCount = p.currPacket.CCThreshold + pkt.CycleCount
					p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
				case PktCcntF1:
					if pkt.Valid.CycleCount {
						p.currPacket.CycleCount = p.currPacket.CCThreshold + pkt.CycleCount
						p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
					} else {
						p.currPacket.CycleCount = 0
						p.currPacket.Valid.CCExactMatch = false
					}
				case PktMispredict, PktCancelF2, PktCancelF3:
					p.currPacket.Atom = pkt.Atom
					p.currPacket.CancelElements = pkt.CancelElements
				case ETE_PktITE:
					p.currPacket.ITEPkt = pkt.ITEPkt
				case PktAddrL_32IS0, PktAddrL_32IS1, ETE_PktSrcAddrL_32IS0, ETE_PktSrcAddrL_32IS1:
					p.currPacket.VAddr = p.update32BitAddress(p.currPacket.VAddr, uint32(pkt.VAddr))
					if p.currPacket.VAddrValidBits < 32 {
						p.currPacket.VAddrValidBits = 32
					}
					p.currPacket.VAddrPktBits = pkt.VAddrPktBits
					p.currPacket.VAddrISA = pkt.VAddrISA
					p.currPacket.PushVAddr()
				case PktAddrMatch, ETE_PktSrcAddrMatch:
					p.currPacket.AddrExactMatchIdx = pkt.AddrExactMatchIdx
					p.currPacket.Valid.ExactMatchIdxValid = pkt.Valid.ExactMatchIdxValid
					p.currPacket.PopVAddrIdx(p.currPacket.AddrExactMatchIdx)
					p.currPacket.PushVAddr()
				case PktAddrS_IS0, PktAddrS_IS1, ETE_PktSrcAddrS_IS0, ETE_PktSrcAddrS_IS1:
					addr, validBits := p.updateShortAddress(p.currPacket.VAddr, p.currPacket.VAddrValidBits, uint32(pkt.VAddr), int(pkt.VAddrPktBits))
					p.currPacket.VAddr = addr
					p.currPacket.VAddrValidBits = validBits
					p.currPacket.VAddrPktBits = pkt.VAddrPktBits
					p.currPacket.VAddrISA = pkt.VAddrISA
					p.currPacket.PushVAddr()
				case PktAddrCtxtL_32IS0, PktAddrCtxtL_32IS1:
					p.currPacket.VAddr = p.update32BitAddress(p.currPacket.VAddr, uint32(pkt.VAddr))
					if p.currPacket.VAddrValidBits < 32 {
						p.currPacket.VAddrValidBits = 32
					}
					p.currPacket.VAddrPktBits = pkt.VAddrPktBits
					p.currPacket.VAddrISA = pkt.VAddrISA
					p.currPacket.PushVAddr()
					if pkt.Valid.Context {
						p.currPacket.Context.Updated = pkt.Context.Updated
						p.currPacket.Context.EL = pkt.Context.EL
						p.currPacket.Context.SF = pkt.Context.SF
						p.currPacket.Context.NS = pkt.Context.NS
						p.currPacket.Context.NSE = pkt.Context.NSE
						p.currPacket.Context.UpdatedV = pkt.Context.UpdatedV
						p.currPacket.Context.UpdatedC = pkt.Context.UpdatedC
						p.currPacket.Valid.Context = true
					}
				case PktAddrCtxtL_64IS0, PktAddrCtxtL_64IS1:
					p.currPacket.VAddr = pkt.VAddr
					p.currPacket.VAddrValidBits = pkt.VAddrValidBits
					p.currPacket.VAddrPktBits = pkt.VAddrPktBits
					p.currPacket.VAddrISA = pkt.VAddrISA
					p.currPacket.PushVAddr()
					if pkt.Valid.Context {
						p.currPacket.Context.Updated = pkt.Context.Updated
						p.currPacket.Context.EL = pkt.Context.EL
						p.currPacket.Context.SF = pkt.Context.SF
						p.currPacket.Context.NS = pkt.Context.NS
						p.currPacket.Context.NSE = pkt.Context.NSE
						p.currPacket.Context.UpdatedV = pkt.Context.UpdatedV
						p.currPacket.Context.UpdatedC = pkt.Context.UpdatedC
						p.currPacket.Valid.Context = true
					}
				case PktQ:
					p.currPacket.QPkt = pkt.QPkt
					if pkt.Valid.ExactMatchIdxValid {
						p.currPacket.AddrExactMatchIdx = pkt.AddrExactMatchIdx
						p.currPacket.Valid.ExactMatchIdxValid = true
					}
					if pkt.Valid.VAddrValid {
						if pkt.VAddrPktBits == 32 {
							p.currPacket.VAddr = p.update32BitAddress(p.currPacket.VAddr, uint32(pkt.VAddr))
							if p.currPacket.VAddrValidBits < 32 {
								p.currPacket.VAddrValidBits = 32
							}
						} else {
							addr, validBits := p.updateShortAddress(p.currPacket.VAddr, p.currPacket.VAddrValidBits, uint32(pkt.VAddr), int(pkt.VAddrPktBits))
							p.currPacket.VAddr = addr
							p.currPacket.VAddrValidBits = validBits
						}
						p.currPacket.VAddrPktBits = pkt.VAddrPktBits
						p.currPacket.VAddrISA = pkt.VAddrISA
						p.currPacket.Valid.VAddrValid = true
					}
				case PktCtxt:
					if pkt.Valid.Context {
						p.currPacket.Context.Updated = pkt.Context.Updated
						p.currPacket.Context.EL = pkt.Context.EL
						p.currPacket.Context.SF = pkt.Context.SF
						p.currPacket.Context.NS = pkt.Context.NS
						p.currPacket.Context.NSE = pkt.Context.NSE
						p.currPacket.Context.UpdatedV = pkt.Context.UpdatedV
						p.currPacket.Context.UpdatedC = pkt.Context.UpdatedC
						if pkt.Context.UpdatedV {
							p.currPacket.Context.VMID = pkt.Context.VMID
						}
						if pkt.Context.UpdatedC {
							p.currPacket.Context.CtxtID = pkt.Context.CtxtID
						}
						p.currPacket.Valid.Context = true
					}
				case PktNumDsMkr, PktUnnumDsMkr:
					p.currPacket.DsmVal = pkt.DsmVal
				case PktEvent:
					p.currPacket.EventVal = pkt.EventVal
				case PktAddrL_64IS0, PktAddrL_64IS1, ETE_PktSrcAddrL_64IS0, ETE_PktSrcAddrL_64IS1:
					p.currPacket.VAddr = pkt.VAddr
					p.currPacket.VAddrValidBits = pkt.VAddrValidBits
					p.currPacket.VAddrPktBits = pkt.VAddrPktBits
					p.currPacket.VAddrISA = pkt.VAddrISA
					p.currPacket.PushVAddr()
				case PktExcept:
					p.currPacket.ExceptionInfo = pkt.ExceptionInfo
					p.currPacket.ExceptionInfo.MType = p.config.CoreProf == ocsd.ProfileCortexM
					if p.config.MajVersion() >= 0x5 {
						switch p.currPacket.ExceptionInfo.ExceptionType {
						case 0x18:
							p.currPacket.Type = ETE_PktTransFail
							p.currPacket.VAddr = 0
						case 0x0:
							p.currPacket.Type = ETE_PktPeReset
							p.currPacket.VAddr = 0
						}
					}
				}
				p.currPacketData = append(p.currPacketData[:0], dataBlock[consumed:consumed+bytesConsumed]...)
				consumed += bytesConsumed
				p.blockBytesProcessed = consumed
				resp = p.outputPacket()
				p.resetPacketState()
				continue
			case errors.Is(err, errDecodeNotImplemented):
				// Fall back to the legacy state machine while migration is in progress.
			default:
				return uint32(consumed), err
			}
		}

		switch p.processState {
		case ProcHdr:
			if consumed >= len(dataBlock) {
				break
			}
			p.packetIndex = p.blockIndex + ocsd.TrcIndex(consumed)
			if p.isSync {
				nextByte := dataBlock[consumed]
				p.currDecode = p.iTable[nextByte].action
				p.currPacket.Type = p.iTable[nextByte].pktType
			} else {
				p.currDecode = decodeNotSync
				p.currPacket.Type = PktNotSync
			}
			p.processState = ProcData
			fallthrough

		case ProcData:
			for consumed < len(dataBlock) && p.processState == ProcData {
				nextByte := dataBlock[consumed]
				p.currPacketData = append(p.currPacketData, nextByte)
				consumed++
				p.blockBytesProcessed = consumed
				p.runDecodeAction(nextByte)
			}

		case SendPkt:
			resp = p.outputPacket()
			p.resetPacketState()
			p.processState = ProcHdr

		case SendUnsynced:
			resp = p.outputUnsyncedRawPacket()
			if p.updateOnUnsyncPktIdx != 0 {
				p.packetIndex = p.updateOnUnsyncPktIdx
				p.updateOnUnsyncPktIdx = 0
			}
			p.processState = ProcData

		case ProcErr:
			return uint32(consumed), ocsd.DataErrFromResp(resp, nil)
		}
	}

	return uint32(consumed), ocsd.DataErrFromResp(resp, nil)
}

// decodeNextPacket decodes a single packet starting at offset without using Processor state.
// During migration this only handles atom packet families and returns errDecodeNotImplemented
// for all other headers.
func decodeNextPacket(data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, fmt.Errorf("offset %d out of range", offset)
	}

	header := data[offset]
	if header == 0x00 {
		return decodeExtensionPacket(data, offset)
	}

	if header == 0x01 {
		return decodeTraceInfoPacket(data, offset)
	}

	if pkt, ok := decodeSimpleSpecResPacket(header); ok {
		return pkt, 1, nil
	}

	if header == 0x0C || header == 0x0D {
		return decodeCycleCntF2Packet(data, offset)
	}

	if header == 0x0E || header == 0x0F {
		return decodeCycleCntF1Packet(data, offset)
	}

	if header >= 0x10 && header <= 0x1F {
		return decodeCycleCntF3Packet(header), 1, nil
	}

	if pkt, consumed, ok := decodeSimpleNoPayloadPacket(header); ok {
		return pkt, consumed, nil
	}

	if header == 0x80 || header == 0x81 {
		return decodeContextPacket(data, offset)
	}

	if header >= uint8(PktAddrMatch) && header <= uint8(PktAddrMatch)+2 {
		pkt := Packet{Type: PktAddrMatch}
		pkt.AddrExactMatchIdx = header & 0x3
		pkt.Valid.ExactMatchIdxValid = true
		return pkt, 1, nil
	}

	if header >= uint8(ETE_PktSrcAddrMatch) && header <= uint8(ETE_PktSrcAddrMatch)+2 {
		pkt := Packet{Type: ETE_PktSrcAddrMatch}
		pkt.AddrExactMatchIdx = header & 0x3
		pkt.Valid.ExactMatchIdxValid = true
		return pkt, 1, nil
	}

	if header == uint8(PktAddrS_IS0) || header == uint8(PktAddrS_IS1) {
		return decodeShortAddrPacket(data, offset)
	}

	if header == uint8(PktAddrCtxtL_32IS0) || header == uint8(PktAddrCtxtL_32IS1) ||
		header == uint8(PktAddrCtxtL_64IS0) || header == uint8(PktAddrCtxtL_64IS1) {
		return decodeAddrContextPacket(data, offset)
	}

	if header == uint8(ETE_PktSrcAddrS_IS0) || header == uint8(ETE_PktSrcAddrS_IS1) {
		return decodeShortAddrPacket(data, offset)
	}

	if (header & 0xF0) == 0xA0 {
		return decodeQPacket(data, offset)
	}

	if header == uint8(PktAddrL_32IS0) || header == uint8(PktAddrL_32IS1) {
		return decodeLongAddr32Packet(data, offset)
	}

	if header == uint8(ETE_PktSrcAddrL_32IS0) || header == uint8(ETE_PktSrcAddrL_32IS1) {
		return decodeLongAddr32Packet(data, offset)
	}

	if header == uint8(PktAddrL_64IS0) || header == uint8(PktAddrL_64IS1) {
		return decodeLongAddr64Packet(data, offset)
	}

	if header == uint8(ETE_PktSrcAddrL_64IS0) || header == uint8(ETE_PktSrcAddrL_64IS1) {
		return decodeLongAddr64Packet(data, offset)
	}

	if header == 0x02 || header == 0x03 {
		return decodeTimestampPacket(data, offset)
	}

	if header == 0x06 {
		return decodeExceptionPacket(data, offset)
	}

	if header == uint8(ETE_PktITE) {
		return decodeITEPacket(data, offset)
	}

	atomType, atom, ok := decodeAtomPacket(header)
	if !ok {
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: atomType, Atom: atom}
	return pkt, 1, nil
}

func (p *Processor) canUseStatelessDecodeResult(pktType PktType) bool {
	switch pktType {
	case PktFuncRet:
		return p.config.CoreProf == ocsd.ProfileCortexM && ocsd.IsV8Arch(p.config.ArchVer) && p.config.FullVersion() >= 0x42
	case PktExceptRtn:
		return p.config.MajVersion() < 0x5
	case ETE_PktTransSt, ETE_PktTransCommit:
		return p.config.MajVersion() >= 0x5
	case ETE_PktITE:
		return p.config.MajVersion() >= 0x5 && p.config.MinVersion() >= 0x3
	case PktCondFlush:
		return p.config.HasCondTrace() && p.config.EnabledCondITrace() != CondTrDis
	case PktIgnore:
		return p.config.FullVersion() >= 0x43
	case ETE_PktTSMarker:
		return p.config.FullVersion() >= 0x46
	case ETE_PktSrcAddrMatch:
		return p.config.FullVersion() >= 0x50
	case ETE_PktSrcAddrS_IS0, ETE_PktSrcAddrS_IS1:
		return p.config.FullVersion() >= 0x50
	case ETE_PktSrcAddrL_32IS0, ETE_PktSrcAddrL_32IS1, ETE_PktSrcAddrL_64IS0, ETE_PktSrcAddrL_64IS1:
		return p.config.FullVersion() >= 0x50
	case PktNumDsMkr, PktUnnumDsMkr:
		return p.config.EnabledDataTrace()
	case PktCcntF2:
		// F2 commit element decode depends on max-spec depth when CommitOpt1 is disabled.
		return p.config.CommitOpt1()
	case PktCcntF1:
		// F1 commit element decode depends on CommitOpt1 mode.
		return p.config.CommitOpt1()
	case PktQ:
		return p.config.HasQElem()
	default:
		return true
	}
}

func decodeITEPacket(data []byte, offset int) (Packet, int, error) {
	if offset+10 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	var value uint64
	for i := range 8 {
		value |= uint64(data[offset+2+i]) << (i * 8)
	}

	pkt := Packet{Type: ETE_PktITE}
	pkt.ITEPkt = ITEPkt{
		EL:    data[offset+1],
		Value: value,
	}
	return pkt, 10, nil
}

func decodeExceptionPacket(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	byte1 := data[offset+1]
	excepType := uint16((byte1 >> 1) & 0x1F)
	addrInterp := (byte1&0x40)>>5 | (byte1 & 0x1)

	pkt := Packet{Type: PktExcept}
	pkt.ExceptionInfo.ExceptionType = excepType
	pkt.ExceptionInfo.AddrInterp = addrInterp

	if (byte1 & 0x80) == 0 {
		// Exception types 0x0 and 0x18 require config-aware sizing in ETE mode.
		if excepType == 0x0 || excepType == 0x18 {
			return Packet{}, 0, errDecodeNotImplemented
		}
		return pkt, 2, nil
	}

	if offset+3 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	byte2 := data[offset+2]
	pkt.ExceptionInfo.ExceptionType |= (uint16(byte2) & 0x1F) << 5
	pkt.ExceptionInfo.MFaultPending = ((byte2 >> 5) & 0x1) != 0
	return pkt, 3, nil
}

func decodeTraceInfoPacket(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	idx := offset + 1
	firstCtrl := data[idx]
	for {
		if idx >= len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		b := data[idx]
		idx++
		if (b & 0x80) == 0 {
			break
		}
	}

	pkt := Packet{Type: PktTraceInfo}
	presSect := firstCtrl & uint8(TInfoAllSect)

	if presSect&uint8(TInfoInfoSect) != 0 {
		fieldVal, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		idx += n
		pkt.TraceInfo.Val = uint16(fieldVal)
		pkt.TraceInfo.CCEnabled = (fieldVal & 0x1) != 0
		pkt.TraceInfo.CondEnabled = uint8((fieldVal >> 1) & 0x7)
		pkt.TraceInfo.P0Load = (fieldVal & (1 << 4)) != 0
		pkt.TraceInfo.P0Store = (fieldVal & (1 << 5)) != 0
		pkt.TraceInfo.InTransState = (fieldVal & (1 << 6)) != 0
		pkt.Valid.TInfo = true
	}

	if presSect&uint8(TInfoKeySect) != 0 {
		fieldVal, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		idx += n
		pkt.P0Key = fieldVal
	}

	if presSect&uint8(TInfoSpecSect) != 0 {
		fieldVal, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		idx += n
		pkt.CurrSpecDepth = fieldVal
		pkt.TraceInfo.SpecFieldPresent = true
		pkt.Valid.SpecDepthValid = true
	}

	if presSect&uint8(TInfoCyctSect) != 0 {
		fieldVal, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		idx += n
		pkt.CCThreshold = fieldVal
		pkt.Valid.CCThreshold = true
	}

	if presSect&uint8(TInfoWndwSect) != 0 {
		_, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		idx += n
	}

	return pkt, idx - offset, nil
}

func decodeExtensionPacket(data []byte, offset int) (Packet, int, error) {
	if offset+1 >= len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	subType := data[offset+1]
	switch subType {
	case 0x03:
		return Packet{Type: PktDiscard}, 2, nil
	case 0x05:
		return Packet{Type: PktOverflow}, 2, nil
	case 0x00:
		if offset+12 > len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		for i := offset + 2; i < offset+11; i++ {
			if data[i] != 0x00 {
				return Packet{Type: PktAsync, Err: ocsd.ErrBadPacketSeq}, 12, nil
			}
		}
		if data[offset+11] != 0x80 {
			return Packet{Type: PktAsync, Err: ocsd.ErrBadPacketSeq}, 12, nil
		}
		return Packet{Type: PktAsync}, 12, nil
	default:
		return Packet{}, 0, errDecodeNotImplemented
	}
}

func decodeSimpleNoPayloadPacket(header uint8) (Packet, int, bool) {
	if header == 0x04 {
		return Packet{Type: PktTraceOn}, 1, true
	}
	if header == 0x05 {
		return Packet{Type: PktFuncRet}, 1, true
	}
	if header == 0x07 {
		return Packet{Type: PktExceptRtn}, 1, true
	}
	if header == 0x0A {
		return Packet{Type: ETE_PktTransSt}, 1, true
	}
	if header == 0x0B {
		return Packet{Type: ETE_PktTransCommit}, 1, true
	}
	if header == 0x43 {
		return Packet{Type: PktCondFlush}, 1, true
	}
	if header >= 0x20 && header <= 0x27 {
		return Packet{Type: PktNumDsMkr, DsmVal: header & 0x7}, 1, true
	}
	if header >= 0x28 && header <= 0x2C {
		return Packet{Type: PktUnnumDsMkr, DsmVal: header & 0x7}, 1, true
	}
	if header == 0x70 {
		return Packet{Type: PktIgnore}, 1, true
	}
	if header == 0x88 {
		return Packet{Type: ETE_PktTSMarker}, 1, true
	}
	if header >= 0x71 && header <= 0x7F {
		return Packet{Type: PktEvent, EventVal: header & 0xF}, 1, true
	}
	return Packet{}, 0, false
}

func decodeCycleCntF3Packet(header uint8) Packet {
	pkt := Packet{Type: PktCcntF3}
	pkt.CommitElements = uint32((header>>2)&0x3) + 1
	pkt.CycleCount = uint32(header & 0x3)
	return pkt
}

func decodeCycleCntF2Packet(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: PktCcntF2}
	pkt.CycleCount = uint32(data[offset+1] & 0xF)
	return pkt, 2, nil
}

func decodeCycleCntF1Packet(data []byte, offset int) (Packet, int, error) {
	if offset >= len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	header := data[offset]
	pkt := Packet{Type: PktCcntF1}

	if (header & 0x1) == 0x1 {
		// CommitOpt1 mode: no count field.
		pkt.Valid.CycleCount = false
		pkt.CycleCount = 0
		return pkt, 1, nil
	}

	count, n, ok := decodeContField32(data, offset+1, 3)
	if !ok {
		return Packet{}, 0, errDecodeNotImplemented
	}
	pkt.CycleCount = count
	pkt.Valid.CycleCount = true
	return pkt, 1 + n, nil
}

func decodeSimpleSpecResPacket(header uint8) (Packet, bool) {
	switch {
	case header >= 0x30 && header <= 0x33:
		pkt := Packet{Type: PktMispredict}
		setSimpleSpecResPayload(&pkt, header&0x3, false)
		return pkt, true
	case header >= 0x34 && header <= 0x37:
		pkt := Packet{Type: PktCancelF2}
		setSimpleSpecResPayload(&pkt, header&0x3, true)
		return pkt, true
	case header >= 0x38 && header <= 0x3F:
		pkt := Packet{Type: PktCancelF3}
		if (header & 0x1) != 0 {
			pkt.Atom = ocsd.PktAtom{EnBits: 0x1, Num: 1}
		}
		pkt.CancelElements = uint32((header>>1)&0x3) + 2
		return pkt, true
	default:
		return Packet{}, false
	}
}

func setSimpleSpecResPayload(pkt *Packet, atomBits uint8, cancelF2 bool) {
	if pkt == nil {
		return
	}
	switch atomBits {
	case 0x1:
		pkt.Atom = ocsd.PktAtom{EnBits: 0x1, Num: 1}
	case 0x2:
		pkt.Atom = ocsd.PktAtom{EnBits: 0x3, Num: 2}
	case 0x3:
		pkt.Atom = ocsd.PktAtom{EnBits: 0x0, Num: 1}
	}
	if cancelF2 {
		pkt.CancelElements = 1
	} else {
		pkt.CancelElements = 0
	}
}

func decodeTimestampPacket(data []byte, offset int) (Packet, int, error) {
	if offset+1 >= len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	tsVal, tsBytes, ok := decodeTSField64(data, offset+1)
	if !ok {
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: PktTimestamp}
	pkt.Timestamp = tsVal
	tsBits := tsBytes * 7
	if tsBytes >= 9 {
		tsBits = 64
	}
	pkt.TSBitsChanged = uint8(tsBits)
	pkt.Valid.Timestamp = true

	consumed := 1 + tsBytes
	if (data[offset] & 0x1) != 0 {
		cc, ccBytes, ok := decodeContField32(data, offset+consumed, 3)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		pkt.CycleCount = cc
		pkt.Valid.CycleCount = true
		consumed += ccBytes
	}

	return pkt, consumed, nil
}

func decodeLongAddr64Packet(data []byte, offset int) (Packet, int, error) {
	if offset+9 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	header := data[offset]
	is := uint8(0)
	pktType := PktAddrL_64IS0
	if header == uint8(PktAddrL_64IS1) {
		is = 1
		pktType = PktAddrL_64IS1
	}
	if header == uint8(ETE_PktSrcAddrL_64IS0) {
		pktType = ETE_PktSrcAddrL_64IS0
	}
	if header == uint8(ETE_PktSrcAddrL_64IS1) {
		is = 1
		pktType = ETE_PktSrcAddrL_64IS1
	}

	value := decodeLongAddr64Value(data[offset+1:offset+9], is)
	pkt := Packet{
		Type:           pktType,
		VAddr:          ocsd.VAddr(value),
		VAddrValidBits: 64,
		VAddrPktBits:   64,
		VAddrISA:       is,
	}
	return pkt, 9, nil
}

func decodeLongAddr32Packet(data []byte, offset int) (Packet, int, error) {
	if offset+5 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	header := data[offset]
	is := uint8(0)
	pktType := PktAddrL_32IS0
	if header == uint8(PktAddrL_32IS1) {
		is = 1
		pktType = PktAddrL_32IS1
	}
	if header == uint8(ETE_PktSrcAddrL_32IS0) {
		pktType = ETE_PktSrcAddrL_32IS0
	}
	if header == uint8(ETE_PktSrcAddrL_32IS1) {
		is = 1
		pktType = ETE_PktSrcAddrL_32IS1
	}

	value := decodeLongAddr32Value(data[offset+1:offset+5], is)
	pkt := Packet{
		Type:           pktType,
		VAddr:          ocsd.VAddr(value),
		VAddrValidBits: 32,
		VAddrPktBits:   32,
		VAddrISA:       is,
	}
	return pkt, 5, nil
}

func decodeLongAddr32Value(addrBytes []byte, is uint8) uint32 {
	if len(addrBytes) < 4 {
		return 0
	}

	var value uint32
	if is == 0 {
		value |= uint32(addrBytes[0]&0x7F) << 2
		value |= uint32(addrBytes[1]&0x7F) << 9
	} else {
		value |= uint32(addrBytes[0]&0x7F) << 1
		value |= uint32(addrBytes[1]) << 8
	}
	value |= uint32(addrBytes[2]) << 16
	value |= uint32(addrBytes[3]) << 24
	return value
}

func decodeShortAddrPacket(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	header := data[offset]
	is := uint8(0)
	pktType := PktAddrS_IS0
	if header == uint8(PktAddrS_IS1) || header == uint8(ETE_PktSrcAddrS_IS1) {
		is = 1
		pktType = PktAddrS_IS1
	}
	if header == uint8(ETE_PktSrcAddrS_IS0) {
		pktType = ETE_PktSrcAddrS_IS0
	}
	if header == uint8(ETE_PktSrcAddrS_IS1) {
		pktType = ETE_PktSrcAddrS_IS1
	}

	value, bits, payloadConsumed, ok := decodeShortAddrPayload(data, offset+1, is)
	if !ok {
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{
		Type:           pktType,
		VAddr:          ocsd.VAddr(value),
		VAddrValidBits: uint8(bits),
		VAddrPktBits:   uint8(bits),
		VAddrISA:       is,
	}
	return pkt, 1 + payloadConsumed, nil
}

func decodeShortAddrPayload(data []byte, stIdx int, is uint8) (value uint32, bits int, consumed int, ok bool) {
	if stIdx < 0 || stIdx >= len(data) {
		return 0, 0, 0, false
	}

	isShift := 2
	if is == 1 {
		isShift = 1
	}

	first := data[stIdx]
	value = uint32(first&0x7F) << isShift
	bits = 7
	consumed = 1

	if (first & 0x80) != 0 {
		if stIdx+1 >= len(data) {
			return 0, 0, 0, false
		}
		value |= uint32(data[stIdx+1]) << (7 + isShift)
		bits += 8
		consumed++
	}

	bits += isShift
	return value, bits, consumed, true
}

func decodeQPacket(data []byte, offset int) (Packet, int, error) {
	header := data[offset]
	qType := header & 0xF

	pkt := Packet{Type: PktQ}

	switch qType {
	case 0x0, 0x1, 0x2:
		if offset+1 >= len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		count, n, ok := decodeContField32(data, offset+1, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		pkt.AddrExactMatchIdx = qType & 0x3
		pkt.Valid.ExactMatchIdxValid = true
		pkt.QPkt = QPkt{
			QCount:       count,
			AddrPresent:  false,
			AddrMatch:    true,
			CountPresent: true,
			QType:        qType,
		}
		return pkt, 1 + n, nil
	case 0x5, 0x6:
		if offset+1 >= len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		is := uint8(0)
		if qType == 0x6 {
			is = 1
		}
		addr, bits, nAddr, ok := decodeShortAddrPayload(data, offset+1, is)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		count, nCount, ok := decodeContField32(data, offset+1+nAddr, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		pkt.VAddr = ocsd.VAddr(addr)
		pkt.VAddrValidBits = uint8(bits)
		pkt.VAddrPktBits = uint8(bits)
		pkt.VAddrISA = is
		pkt.Valid.VAddrValid = true
		pkt.QPkt = QPkt{
			QCount:       count,
			AddrPresent:  true,
			AddrMatch:    false,
			CountPresent: true,
			QType:        qType,
		}
		return pkt, 1 + nAddr + nCount, nil
	case 0xA, 0xB:
		if offset+5 >= len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		is := uint8(0)
		if qType == 0xB {
			is = 1
		}
		addr := decodeLongAddr32Value(data[offset+1:offset+5], is)
		count, nCount, ok := decodeContField32(data, offset+5, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		pkt.VAddr = ocsd.VAddr(addr)
		pkt.VAddrValidBits = 32
		pkt.VAddrPktBits = 32
		pkt.VAddrISA = is
		pkt.Valid.VAddrValid = true
		pkt.QPkt = QPkt{
			QCount:       count,
			AddrPresent:  true,
			AddrMatch:    false,
			CountPresent: true,
			QType:        qType,
		}
		return pkt, 5 + nCount, nil
	case 0xC:
		if offset+1 >= len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		count, n, ok := decodeContField32(data, offset+1, 5)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		pkt.QPkt = QPkt{
			QCount:       count,
			AddrPresent:  true,
			AddrMatch:    false,
			CountPresent: true,
			QType:        qType,
		}
		return pkt, 1 + n, nil
	case 0xF:
		pkt.QPkt = QPkt{QType: qType}
		return pkt, 1, nil
	default:
		return Packet{}, 0, errDecodeNotImplemented
	}
}

func decodeContextPacket(data []byte, offset int) (Packet, int, error) {
	header := data[offset]

	if header == 0x80 {
		return Packet{Type: PktCtxt}, 1, nil
	}

	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	info := data[offset+1]
	if (info & 0xC0) != 0 {
		// VMID/CtxtID payload sizes depend on runtime config; use legacy parser.
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: PktCtxt}
	pkt.Context.Updated = true
	pkt.Context.EL = info & 0x3
	pkt.Context.NSE = ((info >> 3) & 0x1) != 0
	pkt.Context.SF = ((info >> 4) & 0x1) != 0
	pkt.Context.NS = ((info >> 5) & 0x1) != 0
	pkt.Valid.Context = true

	return pkt, 2, nil
}

func decodeAddrContextPacket(data []byte, offset int) (Packet, int, error) {
	header := data[offset]
	is := uint8(0)
	addrBytes := 4
	pktType := PktAddrCtxtL_32IS0

	switch header {
	case uint8(PktAddrCtxtL_32IS0):
		pktType = PktAddrCtxtL_32IS0
	case uint8(PktAddrCtxtL_32IS1):
		pktType = PktAddrCtxtL_32IS1
		is = 1
	case uint8(PktAddrCtxtL_64IS0):
		pktType = PktAddrCtxtL_64IS0
		addrBytes = 8
	case uint8(PktAddrCtxtL_64IS1):
		pktType = PktAddrCtxtL_64IS1
		is = 1
		addrBytes = 8
	default:
		return Packet{}, 0, errDecodeNotImplemented
	}

	minLen := 1 + addrBytes + 1
	if offset+minLen > len(data) {
		return Packet{}, 0, errDecodeNotImplemented
	}

	info := data[offset+1+addrBytes]
	if (info & 0xC0) != 0 {
		// VMID/CtxtID payload sizes depend on runtime config; use legacy parser.
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: pktType}
	if addrBytes == 8 {
		pkt.VAddr = ocsd.VAddr(decodeLongAddr64Value(data[offset+1:offset+9], is))
		pkt.VAddrValidBits = 64
		pkt.VAddrPktBits = 64
	} else {
		pkt.VAddr = ocsd.VAddr(decodeLongAddr32Value(data[offset+1:offset+5], is))
		pkt.VAddrValidBits = 32
		pkt.VAddrPktBits = 32
	}
	pkt.VAddrISA = is

	pkt.Context.Updated = true
	pkt.Context.EL = info & 0x3
	pkt.Context.NSE = ((info >> 3) & 0x1) != 0
	pkt.Context.SF = ((info >> 4) & 0x1) != 0
	pkt.Context.NS = ((info >> 5) & 0x1) != 0
	pkt.Valid.Context = true

	return pkt, minLen, nil
}

func decodeLongAddr64Value(addrBytes []byte, is uint8) uint64 {
	if len(addrBytes) < 8 {
		return 0
	}

	var value uint64
	if is == 0 {
		value |= uint64(addrBytes[0]&0x7F) << 2
		value |= uint64(addrBytes[1]&0x7F) << 9
	} else {
		value |= uint64(addrBytes[0]&0x7F) << 1
		value |= uint64(addrBytes[1]) << 8
	}
	value |= uint64(addrBytes[2]) << 16
	value |= uint64(addrBytes[3]) << 24
	value |= uint64(addrBytes[4]) << 32
	value |= uint64(addrBytes[5]) << 40
	value |= uint64(addrBytes[6]) << 48
	value |= uint64(addrBytes[7]) << 56
	return value
}

func decodeTSField64(data []byte, stIdx int) (uint64, int, bool) {
	const maxByteIdx = 8
	if stIdx < 0 || stIdx >= len(data) {
		return 0, 0, false
	}

	idx := 0
	lastByte := false
	var value uint64
	for !lastByte {
		if stIdx+idx >= len(data) {
			return 0, 0, false
		}
		byteVal := data[stIdx+idx]
		byteValMask := uint8(0x7F)
		if idx == maxByteIdx {
			byteValMask = 0xFF
			lastByte = true
		} else {
			lastByte = (byteVal & 0x80) == 0
		}
		value |= uint64(byteVal&byteValMask) << (idx * 7)
		idx++
	}
	return value, idx, true
}

func decodeContField32(data []byte, stIdx int, byteLimit int) (uint32, int, bool) {
	if stIdx < 0 || stIdx >= len(data) || byteLimit <= 0 {
		return 0, 0, false
	}

	var value uint32
	idx := 0
	for idx < byteLimit {
		if stIdx+idx >= len(data) {
			return 0, 0, false
		}
		byteVal := data[stIdx+idx]
		shift := idx * 7
		if shift >= 32 {
			return 0, 0, false
		}
		part := uint32(byteVal & 0x7F)
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				return 0, 0, false
			}
		}
		if idx == byteLimit-1 && (byteVal&0x80) != 0 {
			return 0, 0, false
		}
		value |= part << shift
		idx++
		if (byteVal & 0x80) == 0 {
			return value, idx, true
		}
	}

	return 0, 0, false
}

func decodeAtomPacket(header uint8) (PktType, ocsd.PktAtom, bool) {
	var f4Patterns = [4]uint32{0xE, 0x0, 0xA, 0x5}

	switch {
	case header >= 0xF6 && header <= 0xF7:
		return PktAtomF1, ocsd.PktAtom{EnBits: uint32(header & 0x1), Num: 1}, true
	case header >= 0xD8 && header <= 0xDB:
		return PktAtomF2, ocsd.PktAtom{EnBits: uint32(header & 0x3), Num: 2}, true
	case header >= 0xF8:
		return PktAtomF3, ocsd.PktAtom{EnBits: uint32(header & 0x7), Num: 3}, true
	case header >= 0xDC && header <= 0xDF:
		return PktAtomF4, ocsd.PktAtom{EnBits: f4Patterns[header&0x3], Num: 4}, true
	case (header >= 0xD5 && header <= 0xD7) || header == 0xF5:
		pattIdx := ((header & 0x20) >> 3) | (header & 0x3)
		switch pattIdx {
		case 5:
			return PktAtomF5, ocsd.PktAtom{EnBits: 0x1E, Num: 5}, true
		case 1:
			return PktAtomF5, ocsd.PktAtom{EnBits: 0x00, Num: 5}, true
		case 2:
			return PktAtomF5, ocsd.PktAtom{EnBits: 0x0A, Num: 5}, true
		case 3:
			return PktAtomF5, ocsd.PktAtom{EnBits: 0x15, Num: 5}, true
		default:
			return 0, ocsd.PktAtom{}, false
		}
	case (header >= 0xC0 && header <= 0xD4) || (header >= 0xE0 && header <= 0xF4):
		pattCount := uint32(header&0x1F) + 3
		pattern := (uint32(1) << pattCount) - 1
		if (header & 0x20) == 0x00 {
			pattern |= uint32(1) << pattCount
		}
		return PktAtomF6, ocsd.PktAtom{EnBits: pattern, Num: uint8(pattCount + 1)}, true
	default:
		return 0, ocsd.PktAtom{}, false
	}
}

func (p *Processor) onEOT() ocsd.DatapathResp {
	if !p.isInit {
		return ocsd.RespFatalNotInit
	}

	resp := ocsd.RespCont
	if len(p.currPacketData) != 0 {
		p.currPacket.Err = errIncompleteEOT
		resp = p.outputPacket()
		p.resetPacketState()
	}

	if p.pktOut != nil && !ocsd.DataRespIsFatal(resp) {
		resp = ocsd.DataRespFromErr(p.callPktOut(ocsd.OpEOT, 0, nil))
	}

	return resp
}

func (p *Processor) onReset() ocsd.DatapathResp {
	if !p.isInit {
		return ocsd.RespFatalNotInit
	}

	resp := ocsd.RespCont
	if p.pktOut != nil {
		resp = ocsd.DataRespFromErr(p.callPktOut(ocsd.OpReset, 0, nil))
	}
	if !ocsd.DataRespIsFatal(resp) {
		p.resetProcessorState()
	}
	return resp
}

func (p *Processor) onFlush() ocsd.DatapathResp {
	if !p.isInit {
		return ocsd.RespFatalNotInit
	}

	resp := ocsd.RespCont
	if p.pktOut != nil {
		resp = ocsd.DataRespFromErr(p.callPktOut(ocsd.OpFlush, 0, nil))
	}
	return resp
}

func (p *Processor) resetStartState() {
	p.currPacket = TracePacket{}
	p.currPacket.ProtocolVersion = p.config.FullVersion()
}

func (p *Processor) resetPacketState() {
	p.currPacketData = p.currPacketData[:0]

	p.currPacket.Type = 0
	p.currPacket.Err = nil
	p.currPacket.ErrHdrVal = 0

	p.currPacket.Valid.CycleCount = false
	p.currPacket.Valid.CCExactMatch = false
	p.currPacket.Valid.CommitElem = false
	p.currPacket.Valid.CancelElem = false
	p.currPacket.Valid.ExactMatchIdxValid = false

	p.currPacket.Atom.Num = 0
	p.currPacket.CondInstr = CondInstr{}
	p.currPacket.CondResult = CondResult{}
	p.currPacket.Context.Updated = false
	p.currPacket.Context.UpdatedV = false
	p.currPacket.Context.UpdatedC = false

	p.currPacket.TraceInfo.InitialTInfo = false
	p.currPacket.TraceInfo.SpecFieldPresent = false

	p.updateOnUnsyncPktIdx = 0
}

func (p *Processor) resetProcessorState() {
	p.resetStartState()
	p.resetPacketState()
	p.currDecode = decodeNotSync
	p.packetIndex = 0
	p.isSync = false
	p.firstTraceInfo = false
	p.sentNotsyncPacket = false
	p.processState = ProcHdr
}

func (p *Processor) runDecodeAction(lastByte uint8) {
	switch p.currDecode {
	case decodePktReserved:
		p.iPktReserved(lastByte)
	case decodePktExtension:
		p.iPktExtension(lastByte)
	case decodePktTraceInfo:
		p.iPktTraceInfo(lastByte)
	case decodePktTimestamp:
		p.iPktTimestamp(lastByte)
	case decodePktNoPayload:
		p.iPktNoPayload(lastByte)
	case decodePktException:
		p.iPktException(lastByte)
	case decodePktInvalidCfg:
		p.iPktInvalidCfg(lastByte)
	case decodePktITE:
		p.iPktITE()
	case decodePktCycleCntF123:
		p.iPktCycleCntF123(lastByte)
	case decodePktSpeclRes:
		p.iPktSpeclRes(lastByte)
	case decodePktCondInstr:
		p.iPktCondInstr(lastByte)
	case decodePktCondResult:
		p.iPktCondResult(lastByte)
	case decodePktContext:
		p.iPktContext(lastByte)
	case decodePktAddrCtxt:
		p.iPktAddrCtxt(lastByte)
	case decodePktShortAddr:
		p.iPktShortAddr(lastByte)
	case decodePktLongAddr:
		p.iPktLongAddr()
	case decodePktQ:
		p.iPktQ(lastByte)
	case decodeAtom:
		p.iAtom(lastByte)
	case decodePktASync:
		p.iPktASync(lastByte)
	default:
		p.iNotSync(lastByte)
	}
}

func (p *Processor) outputPacket() ocsd.DatapathResp {
	if p.PktRawMonI != nil {
		p.PktRawMonI.RawPacketDataMon(ocsd.OpData, p.packetIndex, &p.currPacket, p.currPacketData)
	}
	if p.pktOut == nil {
		return ocsd.RespCont
	}
	pkt := p.currPacket
	resp := ocsd.DataRespFromErr(p.callPktOut(ocsd.OpData, p.packetIndex, &pkt)) //nolint:gosec
	return resp
}

func (p *Processor) outputUnsyncedRawPacket() ocsd.DatapathResp {
	n := p.dumpUnsyncedBytes

	if p.PktRawMonI != nil && n > 0 && len(p.currPacketData) > 0 {
		monBytes := min(n, len(p.currPacketData))
		p.PktRawMonI.RawPacketDataMon(ocsd.OpData, p.packetIndex, &p.currPacket, p.currPacketData[:monBytes])
	}

	resp := ocsd.RespCont
	if !p.sentNotsyncPacket {
		if p.pktOut != nil {
			pkt := p.currPacket
			resp = ocsd.DataRespFromErr(p.callPktOut(ocsd.OpData, p.packetIndex, &pkt))
		}
		p.sentNotsyncPacket = true
	}

	if n <= len(p.currPacketData) {
		p.currPacketData = p.currPacketData[n:]
	} else {
		p.currPacketData = p.currPacketData[:0]
	}
	return resp
}

// ============================
// Packet handlers
// ============================

func (p *Processor) iNotSync(lastByte uint8) {
	if lastByte == 0x00 {
		if len(p.currPacketData) > 1 {
			p.dumpUnsyncedBytes = len(p.currPacketData) - 1
			p.processState = SendUnsynced
			p.updateOnUnsyncPktIdx = p.blockIndex + ocsd.TrcIndex(p.blockBytesProcessed) - 1
		} else {
			p.packetIndex = p.blockIndex + ocsd.TrcIndex(p.blockBytesProcessed) - 1
		}
		p.currDecode = p.iTable[lastByte].action
	} else if len(p.currPacketData) >= 8 {
		p.dumpUnsyncedBytes = len(p.currPacketData)
		p.processState = SendUnsynced
		p.updateOnUnsyncPktIdx = p.blockIndex + ocsd.TrcIndex(p.blockBytesProcessed)
	}
}

func (p *Processor) iPktNoPayload(lastByte uint8) {
	switch p.currPacket.Type {
	case PktAddrMatch, ETE_PktSrcAddrMatch:
		p.currPacket.AddrExactMatchIdx = lastByte & 0x3
		p.currPacket.Valid.ExactMatchIdxValid = true
		p.currPacket.PopVAddrIdx(p.currPacket.AddrExactMatchIdx)
		p.currPacket.PushVAddr()
	case PktEvent:
		p.currPacket.EventVal = lastByte & 0xF
	case PktNumDsMkr, PktUnnumDsMkr:
		p.currPacket.DsmVal = lastByte & 0x7
	}
	p.processState = SendPkt
}

func (p *Processor) iPktReserved(lastByte uint8) {
	p.currPacket.Err = errReservedHeader
	p.currPacket.ErrHdrVal = lastByte
	p.currPacket.Type = PktReserved
	p.processState = SendPkt
}

func (p *Processor) iPktInvalidCfg(lastByte uint8) {
	p.currPacket.Err = errReservedCfg
	p.currPacket.ErrHdrVal = lastByte
	p.processState = SendPkt
}

func (p *Processor) iPktExtension(lastByte uint8) {
	if len(p.currPacketData) == 2 {
		if !p.isSync && lastByte != 0x00 {
			p.currDecode = decodeNotSync
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
			p.currDecode = decodePktASync
		default:
			p.currPacket.Err = ocsd.ErrBadPacketSeq
			p.processState = SendPkt
		}
	}
}

func (p *Processor) iPktASync(lastByte uint8) {
	if lastByte != 0x00 {
		if !p.isSync && len(p.currPacketData) != 12 {
			p.currDecode = decodeNotSync
			p.currPacket.Type = PktNotSync
			return
		}
		p.processState = SendPkt
		if len(p.currPacketData) != 12 || lastByte != 0x80 {
			p.currPacket.Err = ocsd.ErrBadPacketSeq
		} else {
			p.isSync = true
		}
	} else if len(p.currPacketData) == 12 {
		if !p.isSync {
			p.dumpUnsyncedBytes = 1
			p.processState = SendUnsynced
		} else {
			p.currPacket.Err = ocsd.ErrBadPacketSeq
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

		p.currPacket.ClearTraceInfo()

		if presSect&uint8(TInfoInfoSect) != 0 && idx < len(p.currPacketData) {
			fieldVal, n := p.extractContField(p.currPacketData, idx, 5)
			idx += n
			p.currPacket.TraceInfo.Val = uint16(fieldVal)
			p.currPacket.TraceInfo.CCEnabled = (fieldVal & 0x1) != 0
			p.currPacket.TraceInfo.CondEnabled = uint8((fieldVal >> 1) & 0x7)
			p.currPacket.TraceInfo.P0Load = (fieldVal & (1 << 4)) != 0
			p.currPacket.TraceInfo.P0Store = (fieldVal & (1 << 5)) != 0
			p.currPacket.TraceInfo.InTransState = (fieldVal & (1 << 6)) != 0
			p.currPacket.Valid.TInfo = true
		}
		if presSect&uint8(TInfoKeySect) != 0 && idx < len(p.currPacketData) {
			fieldVal, n := p.extractContField(p.currPacketData, idx, 5)
			idx += n
			p.currPacket.P0Key = fieldVal
		}
		if presSect&uint8(TInfoSpecSect) != 0 && idx < len(p.currPacketData) {
			fieldVal, n := p.extractContField(p.currPacketData, idx, 5)
			idx += n
			p.currPacket.CurrSpecDepth = fieldVal
			p.currPacket.TraceInfo.SpecFieldPresent = true
			p.currPacket.Valid.SpecDepthValid = true
		}
		if presSect&uint8(TInfoCyctSect) != 0 && idx < len(p.currPacketData) {
			fieldVal, n := p.extractContField(p.currPacketData, idx, 5)
			idx += n
			p.currPacket.CCThreshold = fieldVal
			p.currPacket.Valid.CCThreshold = true
		}
		// window section - unsupported in current ETE, consume but ignore.
		if presSect&uint8(TInfoWndwSect) != 0 && idx < len(p.currPacketData) {
			_, _ = p.extractContField(p.currPacketData, idx, 5)
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
			idx := 1 + tsBytes
			countVal, _ := p.extractContField(p.currPacketData, idx, 3)
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
		addrInterp := (p.currPacketData[1]&0x40)>>5 | (p.currPacketData[1] & 0x1)
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
				p.currPacket.CommitElements = (uint32(lastByte>>2) & 0x3) + 1
				p.currPacket.Valid.CommitElem = true
			}
			p.currPacket.CycleCount = p.currPacket.CCThreshold + uint32(lastByte&0x3)
			p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
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
		p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
		if !p.config.CommitOpt1() {
			commitOffset := 1
			if p.ccF2MaxSpecCommit {
				commitOffset = int(p.config.MaxSpecDepth()) - 15
			}
			commitElements := int(lastByte>>4&0xF) + commitOffset
			p.currPacket.CommitElements = uint32(commitElements)
			p.currPacket.Valid.CommitElem = true
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
		var n int
		var fieldVal uint32
		if !p.config.CommitOpt1() {
			fieldVal, n = p.extractContField(p.currPacketData, idx, 5)
			idx += n
			p.currPacket.CommitElements = fieldVal
			p.currPacket.Valid.CommitElem = true
		}
		if p.hasCount {
			fieldVal, _ = p.extractContField(p.currPacketData, idx, 3)
			p.currPacket.CycleCount = fieldVal + p.currPacket.CCThreshold
			p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
		} else {
			p.currPacket.CycleCount = 0
			p.currPacket.Valid.CCExactMatch = false
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
			fieldVal, _ := p.extractContField(p.currPacketData, 1, 5)
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
	p.currPacket.Context.NSE = (infoByte>>3)&0x1 != 0
	p.currPacket.Context.SF = (infoByte>>4)&0x1 != 0
	p.currPacket.Context.NS = (infoByte>>5)&0x1 != 0

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
				p.currPacket.VAddrValidBits = 64
				p.currPacket.VAddrPktBits = 64
				p.currPacket.VAddrISA = p.addrIS
			} else {
				val32, n := p.extract32BitLongAddr(p.currPacketData, stIdx, p.addrIS)
				stIdx += n
				p.currPacket.VAddr = p.update32BitAddress(p.currPacket.VAddr, val32)
				if p.currPacket.VAddrValidBits < 32 {
					p.currPacket.VAddrValidBits = 32
				}
				p.currPacket.VAddrPktBits = 32
				p.currPacket.VAddrISA = p.addrIS
			}
			p.currPacket.PushVAddr()
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
		addrVal, bits, _ := p.extractShortAddrFromBuf(p.currPacketData, 1, p.addrIS)
		p.currPacket.VAddr, p.currPacket.VAddrValidBits = p.updateShortAddress(p.currPacket.VAddr, p.currPacket.VAddrValidBits, addrVal, bits)
		p.currPacket.VAddrPktBits = uint8(bits)
		p.currPacket.VAddrISA = p.addrIS
		p.currPacket.PushVAddr()
		p.processState = SendPkt
	}
}

func (p *Processor) iPktLongAddr() {
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
			p.currPacket.VAddrValidBits = 64
			p.currPacket.VAddrPktBits = 64
		} else {
			val32, _ := p.extract32BitLongAddr(p.currPacketData, stIdx, p.addrIS)
			p.currPacket.VAddr = p.update32BitAddress(p.currPacket.VAddr, val32)
			if p.currPacket.VAddrValidBits < 32 {
				p.currPacket.VAddrValidBits = 32
			}
			p.currPacket.VAddrPktBits = 32
		}
		p.currPacket.VAddrISA = p.addrIS
		p.currPacket.PushVAddr()
		p.processState = SendPkt
	}
}

func (p *Processor) update32BitAddress(currAddr ocsd.VAddr, newVal32 uint32) ocsd.VAddr {
	if p.currPacket.Valid.Context && p.currPacket.Context.SF {
		// Context is 64-bit, keep upper 32 bits, replace lower 32 bits
		mask := ocsd.VAddr(0xFFFFFFFF)
		return (currAddr & ^mask) | ocsd.VAddr(newVal32)
	}
	return ocsd.VAddr(newVal32)
}

func (p *Processor) markMalformedCurrentPacket(malformedType PktType) {
	if p.processState == SendPkt && errors.Is(p.currPacket.Err, ocsd.ErrBadPacketSeq) {
		return
	}
	p.currPacket.Err = fmt.Errorf("%w: malformed %s", ocsd.ErrBadPacketSeq, malformedType.String())
	p.processState = SendPkt
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
			p.currPacket.Err = ocsd.ErrBadPacketSeq
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
			p.currPacket.Valid.ExactMatchIdxValid = true
		} else if len(p.currPacketData) > 1 {
			if p.addrShort {
				qAddr, bits, n := p.extractShortAddrFromBuf(p.currPacketData, idx, p.addrIS)
				idx += n
				p.currPacket.VAddr, p.currPacket.VAddrValidBits = p.updateShortAddress(p.currPacket.VAddr, p.currPacket.VAddrValidBits, qAddr, bits)
				p.currPacket.VAddrISA = p.addrIS
				p.currPacket.VAddrPktBits = uint8(bits)
			} else {
				qAddr, n := p.extract32BitLongAddr(p.currPacketData, idx, p.addrIS)
				idx += n
				p.currPacket.VAddr = p.update32BitAddress(p.currPacket.VAddr, qAddr)
				if p.currPacket.VAddrValidBits < 32 {
					p.currPacket.VAddrValidBits = 32
				}
				p.currPacket.VAddrISA = p.addrIS
				p.currPacket.VAddrPktBits = 32
			}
			p.currPacket.Valid.VAddrValid = p.currPacket.VAddrValidBits > 0
		}

		if p.qType != 0xF {
			qCount, _ := p.extractContField(p.currPacketData, idx, 5)
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
			pattern |= (uint32(1) << pattCount)
		}
		p.currPacket.Atom = ocsd.PktAtom{EnBits: pattern, Num: uint8(pattCount + 1)}
	}

	p.processState = SendPkt
}

func (p *Processor) iPktITE() {
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
			condKey, _ := p.extractContField(p.currPacketData, 1, 5)
			p.currPacket.CondInstr.CondCKey = condKey
			p.currPacket.CondInstr.CondKeySet = true
			p.processState = SendPkt
		}
	default:
		if (lastByte & 0x80) == 0x00 {
			condKey, _ := p.extractContField(p.currPacketData, 1, 5)
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
			stIdx := 1
			key0, res0, n := p.extractCondResult(p.currPacketData, stIdx)
			stIdx += n
			ci0 := p.currPacketData[0] & 0x1
			p.currPacket.CondResult.CondRKey0 = key0
			p.currPacket.CondResult.Res0 = res0
			p.currPacket.CondResult.CI0 = ci0 != 0

			if p.f1HasP2 {
				key1, res1, _ := p.extractCondResult(p.currPacketData, stIdx)
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
func (p *Processor) extractCondResult(buf []byte, stIdx int) (key uint32, result uint8, consumed int) {
	idx := 0
	incr := 0

	for idx < 6 {
		if stIdx+idx >= len(buf) {
			return key, result, idx
		}
		byteVal := buf[stIdx+idx]
		if idx == 0 {
			result = byteVal & 0xF
			key = uint32((byteVal >> 4) & 0x7)
			incr = 3
		} else {
			key |= uint32(byteVal&0x7F) << incr
			incr += 7
		}
		if (byteVal & 0x80) == 0 {
			idx++
			break
		}
		idx++
	}
	return key, result, idx
}

// ============================
// Extraction helpers
// ============================

// extractContField extracts a continuation-coded 32-bit value from the buffer starting at stIdx.
// Returns number of bytes consumed.
func (p *Processor) extractContField(buf []byte, stIdx int, byteLimit int) (value uint32, consumed int) {
	if stIdx < 0 || stIdx >= len(buf) || byteLimit <= 0 {
		return 0, 0
	}
	idx := 0
	lastByte := false
	for !lastByte && idx < byteLimit {
		if stIdx+idx >= len(buf) {
			return value, idx
		}
		byteVal := buf[stIdx+idx]
		shift := idx * 7
		if shift >= 32 {
			p.markMalformedCurrentPacket(p.currPacket.Type)
			return 0, 0
		}
		part := uint32(byteVal & 0x7F)
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				p.markMalformedCurrentPacket(p.currPacket.Type)
				return 0, 0
			}
		}
		if idx == byteLimit-1 && (byteVal&0x80) != 0 {
			p.markMalformedCurrentPacket(p.currPacket.Type)
			return 0, 0
		}
		lastByte = (byteVal & 0x80) != 0x80
		value |= part << shift
		idx++
	}
	return value, idx
}

// extractTSField64 extracts a 64-bit timestamp from the buffer starting at stIdx.
// Returns number of bytes consumed.
func (p *Processor) extractTSField64(buf []byte, stIdx int, value *uint64) int {
	const maxByteIdx = 8
	if stIdx < 0 || stIdx >= len(buf) {
		return 0
	}
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
func (p *Processor) extractShortAddrFromBuf(buf []byte, stIdx int, IS uint8) (value uint32, bits int, consumed int) {
	if stIdx < 0 || stIdx >= len(buf) {
		p.markMalformedCurrentPacket(p.currPacket.Type)
		return 0, 0, 0
	}
	isShift := 2
	if IS == 1 {
		isShift = 1
	}
	idx := 0
	bits = 7
	value |= uint32(buf[stIdx+idx]&0x7F) << isShift

	if (buf[stIdx+idx] & 0x80) != 0 {
		idx++
		if stIdx+idx >= len(buf) {
			p.markMalformedCurrentPacket(p.currPacket.Type)
			return 0, 0, 0
		}
		value |= uint32(buf[stIdx+idx]) << (7 + isShift)
		bits += 8
	}
	idx++
	bits += isShift
	return value, bits, idx
}

// updateShortAddress updates a VAddr with a short address value (clears lower bits, sets new ones).
func (p *Processor) updateShortAddress(existing ocsd.VAddr, existingValidBits uint8, addrVal uint32, bits int) (ocsd.VAddr, uint8) {
	if bits <= 0 || bits > ocsd.MaxVABitsize {
		p.markMalformedCurrentPacket(p.currPacket.Type)
		return existing, existingValidBits
	}
	mask := ocsd.VAddr((uint64(1) << bits) - 1)
	updated := (existing &^ mask) | ocsd.VAddr(addrVal)
	updatedValidBits := existingValidBits
	if bits > int(updatedValidBits) {
		if bits > ocsd.MaxVABitsize {
			updatedValidBits = ocsd.MaxVABitsize
		} else {
			updatedValidBits = uint8(bits)
		}
	}
	return updated, updatedValidBits
}

// extract64BitLongAddr extracts an 8-byte 64-bit long address.
// Returns number of bytes consumed.
func (p *Processor) extract64BitLongAddr(buf []byte, stIdx int, IS uint8, value *uint64) int {
	if stIdx < 0 || stIdx+7 >= len(buf) {
		p.markMalformedCurrentPacket(p.currPacket.Type)
		*value = 0
		return 0
	}
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
func (p *Processor) extract32BitLongAddr(buf []byte, stIdx int, IS uint8) (value uint32, consumed int) {
	if stIdx < 0 || stIdx+3 >= len(buf) {
		p.markMalformedCurrentPacket(p.currPacket.Type)
		return 0, 0
	}
	if IS == 0 {
		value |= uint32(buf[stIdx+0]&0x7F) << 2
		value |= uint32(buf[stIdx+1]&0x7F) << 9
	} else {
		value |= uint32(buf[stIdx+0]&0x7F) << 1
		value |= uint32(buf[stIdx+1]) << 8
	}
	value |= uint32(buf[stIdx+2]) << 16
	value |= uint32(buf[stIdx+3]) << 24
	return value, 4
}

// buildIPacketTable initialises p.iTable for header byte dispatch.
// Ported from TrcPktProcEtmV4I::BuildIPacketTable.
func (p *Processor) buildIPacketTable() {
	// default to reserved
	for i := range 256 {
		p.iTable[i].pktType = PktReserved
		p.iTable[i].action = decodePktReserved
	}

	p.iTable[0x00].pktType = PktExtension
	p.iTable[0x00].action = decodePktExtension

	p.iTable[0x01].pktType = PktTraceInfo
	p.iTable[0x01].action = decodePktTraceInfo

	// timestamp b0000001x
	p.iTable[0x02].pktType = PktTimestamp
	p.iTable[0x02].action = decodePktTimestamp
	p.iTable[0x03].pktType = PktTimestamp
	p.iTable[0x03].action = decodePktTimestamp

	p.iTable[0x04].pktType = PktTraceOn
	p.iTable[0x04].action = decodePktNoPayload

	// V8M func return (only valid in certain configs)
	p.iTable[0x05].pktType = PktFuncRet
	if p.config.CoreProf == ocsd.ProfileCortexM && ocsd.IsV8Arch(p.config.ArchVer) && p.config.FullVersion() >= 0x42 {
		p.iTable[0x05].action = decodePktNoPayload
	}

	p.iTable[0x06].pktType = PktExcept
	p.iTable[0x06].action = decodePktException

	p.iTable[0x07].pktType = PktExceptRtn
	if p.config.MajVersion() >= 0x5 {
		p.iTable[0x07].action = decodePktInvalidCfg
	} else {
		p.iTable[0x07].action = decodePktNoPayload
	}

	// ETE TRANS/ITE packets
	if p.config.MajVersion() >= 0x5 {
		p.iTable[0x0A].pktType = ETE_PktTransSt
		p.iTable[0x0A].action = decodePktNoPayload
		p.iTable[0x0B].pktType = ETE_PktTransCommit
		p.iTable[0x0B].action = decodePktNoPayload

		if p.config.MinVersion() >= 0x3 {
			p.iTable[0x09].pktType = ETE_PktITE
			p.iTable[0x09].action = decodePktITE
		}
	}

	// cycle count F2/F1 - 0x0C-0x0F
	for i := range 2 {
		p.iTable[0x0C+i].pktType = PktCcntF2
		p.iTable[0x0C+i].action = decodePktCycleCntF123
	}
	for i := 2; i < 4; i++ {
		p.iTable[0x0C+i].pktType = PktCcntF1
		p.iTable[0x0C+i].action = decodePktCycleCntF123
	}

	// cycle count F3 - 0x10-0x1F
	for i := range 16 {
		p.iTable[0x10+i].pktType = PktCcntF3
		p.iTable[0x10+i].action = decodePktCycleCntF123
	}

	// NDSM 0x20-0x27
	for i := range 8 {
		p.iTable[0x20+i].pktType = PktNumDsMkr
		if p.config.EnabledDataTrace() {
			p.iTable[0x20+i].action = decodePktNoPayload
		} else {
			p.iTable[0x20+i].action = decodePktInvalidCfg
		}
	}

	// UDSM 0x28-0x2C
	for i := range 5 {
		p.iTable[0x28+i].pktType = PktUnnumDsMkr
		if p.config.EnabledDataTrace() {
			p.iTable[0x28+i].action = decodePktNoPayload
		} else {
			p.iTable[0x28+i].action = decodePktInvalidCfg
		}
	}

	// commit 0x2D
	p.iTable[0x2D].pktType = PktCommit
	p.iTable[0x2D].action = decodePktSpeclRes

	// cancel F1 0x2E-0x2F
	p.iTable[0x2E].pktType = PktCancelF1
	p.iTable[0x2E].action = decodePktSpeclRes
	p.iTable[0x2F].pktType = PktCancelF1Mispred
	p.iTable[0x2F].action = decodePktSpeclRes

	// mispredict 0x30-0x33
	for i := range 4 {
		p.iTable[0x30+i].pktType = PktMispredict
		p.iTable[0x30+i].action = decodePktSpeclRes
	}

	// cancel F2 0x34-0x37
	for i := range 4 {
		p.iTable[0x34+i].pktType = PktCancelF2
		p.iTable[0x34+i].action = decodePktSpeclRes
	}

	// cancel F3 0x38-0x3F
	for i := range 8 {
		p.iTable[0x38+i].pktType = PktCancelF3
		p.iTable[0x38+i].action = decodePktSpeclRes
	}

	bCondValid := p.config.HasCondTrace() && p.config.EnabledCondITrace() != CondTrDis

	// cond I F2 0x40-0x42
	for i := range 3 {
		p.iTable[0x40+i].pktType = PktCondIF2
		if bCondValid {
			p.iTable[0x40+i].action = decodePktCondInstr
		} else {
			p.iTable[0x40+i].action = decodePktInvalidCfg
		}
	}

	// cond flush 0x43
	p.iTable[0x43].pktType = PktCondFlush
	if bCondValid {
		p.iTable[0x43].action = decodePktNoPayload
	} else {
		p.iTable[0x43].action = decodePktInvalidCfg
	}

	// cond res F4 0x44-0x46
	for i := range 3 {
		p.iTable[0x44+i].pktType = PktCondResF4
		if bCondValid {
			p.iTable[0x44+i].action = decodePktCondResult
		} else {
			p.iTable[0x44+i].action = decodePktInvalidCfg
		}
	}

	// cond res F2 0x48-0x4A, 0x4C-0x4E
	for i := range 3 {
		p.iTable[0x48+i].pktType = PktCondResF2
		if bCondValid {
			p.iTable[0x48+i].action = decodePktCondResult
		} else {
			p.iTable[0x48+i].action = decodePktInvalidCfg
		}
	}
	for i := range 3 {
		p.iTable[0x4C+i].pktType = PktCondResF2
		if bCondValid {
			p.iTable[0x4C+i].action = decodePktCondResult
		} else {
			p.iTable[0x4C+i].action = decodePktInvalidCfg
		}
	}

	// cond res F3 0x50-0x5F
	for i := range 16 {
		p.iTable[0x50+i].pktType = PktCondResF3
		if bCondValid {
			p.iTable[0x50+i].action = decodePktCondResult
		} else {
			p.iTable[0x50+i].action = decodePktInvalidCfg
		}
	}

	// cond res F1 0x68-0x6B
	for i := range 4 {
		p.iTable[0x68+i].pktType = PktCondResF1
		if bCondValid {
			p.iTable[0x68+i].action = decodePktCondResult
		} else {
			p.iTable[0x68+i].action = decodePktInvalidCfg
		}
	}

	// cond I F1 0x6C
	p.iTable[0x6C].pktType = PktCondIF1
	if bCondValid {
		p.iTable[0x6C].action = decodePktCondInstr
	} else {
		p.iTable[0x6C].action = decodePktInvalidCfg
	}

	// cond I F3 0x6D
	p.iTable[0x6D].pktType = PktCondIF3
	if bCondValid {
		p.iTable[0x6D].action = decodePktCondInstr
	} else {
		p.iTable[0x6D].action = decodePktInvalidCfg
	}

	// cond res F1 extra 0x6E-0x6F
	for i := range 2 {
		p.iTable[0x6E+i].pktType = PktCondResF1
		if bCondValid {
			p.iTable[0x6E+i].action = decodePktCondResult
		} else {
			p.iTable[0x6E+i].action = decodePktInvalidCfg
		}
	}

	// ignore packet (ETM 4.3+) 0x70
	if p.config.FullVersion() >= 0x43 {
		p.iTable[0x70].pktType = PktIgnore
		p.iTable[0x70].action = decodePktNoPayload
	}

	// event trace 0x71-0x7F
	for i := range 15 {
		p.iTable[0x71+i].pktType = PktEvent
		p.iTable[0x71+i].action = decodePktNoPayload
	}

	// context 0x80-0x81
	for i := range 2 {
		p.iTable[0x80+i].pktType = PktCtxt
		p.iTable[0x80+i].action = decodePktContext
	}

	// addr with ctx 0x82-0x86
	p.iTable[0x82].pktType = PktAddrCtxtL_32IS0
	p.iTable[0x82].action = decodePktAddrCtxt
	p.iTable[0x83].pktType = PktAddrCtxtL_32IS1
	p.iTable[0x83].action = decodePktAddrCtxt
	p.iTable[0x85].pktType = PktAddrCtxtL_64IS0
	p.iTable[0x85].action = decodePktAddrCtxt
	p.iTable[0x86].pktType = PktAddrCtxtL_64IS1
	p.iTable[0x86].action = decodePktAddrCtxt

	// ETE TS marker 0x88
	if p.config.FullVersion() >= 0x46 {
		p.iTable[0x88].pktType = ETE_PktTSMarker
		p.iTable[0x88].action = decodePktNoPayload
	}

	// exact match addr 0x90-0x92
	for i := range 3 {
		p.iTable[0x90+i].pktType = PktAddrMatch
		p.iTable[0x90+i].action = decodePktNoPayload
	}

	// short addr 0x95-0x96
	p.iTable[0x95].pktType = PktAddrS_IS0
	p.iTable[0x95].action = decodePktShortAddr
	p.iTable[0x96].pktType = PktAddrS_IS1
	p.iTable[0x96].action = decodePktShortAddr

	// long addr 32 0x9A-0x9B
	p.iTable[0x9A].pktType = PktAddrL_32IS0
	p.iTable[0x9A].action = decodePktLongAddr
	p.iTable[0x9B].pktType = PktAddrL_32IS1
	p.iTable[0x9B].action = decodePktLongAddr

	// long addr 64 0x9D-0x9E
	p.iTable[0x9D].pktType = PktAddrL_64IS0
	p.iTable[0x9D].action = decodePktLongAddr
	p.iTable[0x9E].pktType = PktAddrL_64IS1
	p.iTable[0x9E].action = decodePktLongAddr

	// Q packets 0xA0-0xAF
	for i := range 16 {
		p.iTable[0xA0+i].pktType = PktQ
		switch i {
		case 0x3, 0x4, 0x7, 0x8, 0x9, 0xD, 0xE:
			// leave as reserved
		default:
			if p.config.HasQElem() {
				p.iTable[0xA0+i].action = decodePktQ
			}
		}
	}

	// ETE source address packets 0xB0-0xB9
	if p.config.FullVersion() >= 0x50 {
		for i := range 3 {
			p.iTable[0xB0+i].pktType = ETE_PktSrcAddrMatch
			p.iTable[0xB0+i].action = decodePktNoPayload
		}
		p.iTable[0xB4].pktType = ETE_PktSrcAddrS_IS0
		p.iTable[0xB4].action = decodePktShortAddr
		p.iTable[0xB5].pktType = ETE_PktSrcAddrS_IS1
		p.iTable[0xB5].action = decodePktShortAddr
		p.iTable[0xB6].pktType = ETE_PktSrcAddrL_32IS0
		p.iTable[0xB6].action = decodePktLongAddr
		p.iTable[0xB7].pktType = ETE_PktSrcAddrL_32IS1
		p.iTable[0xB7].action = decodePktLongAddr
		p.iTable[0xB8].pktType = ETE_PktSrcAddrL_64IS0
		p.iTable[0xB8].action = decodePktLongAddr
		p.iTable[0xB9].pktType = ETE_PktSrcAddrL_64IS1
		p.iTable[0xB9].action = decodePktLongAddr
	}

	// atoms F6 0xC0-0xD4
	for i := 0xC0; i <= 0xD4; i++ {
		p.iTable[i].pktType = PktAtomF6
		p.iTable[i].action = decodeAtom
	}
	// atoms F5 0xD5-0xD7
	for i := 0xD5; i <= 0xD7; i++ {
		p.iTable[i].pktType = PktAtomF5
		p.iTable[i].action = decodeAtom
	}
	// atoms F2 0xD8-0xDB
	for i := 0xD8; i <= 0xDB; i++ {
		p.iTable[i].pktType = PktAtomF2
		p.iTable[i].action = decodeAtom
	}
	// atoms F4 0xDC-0xDF
	for i := 0xDC; i <= 0xDF; i++ {
		p.iTable[i].pktType = PktAtomF4
		p.iTable[i].action = decodeAtom
	}
	// atoms F6 0xE0-0xF4
	for i := 0xE0; i <= 0xF4; i++ {
		p.iTable[i].pktType = PktAtomF6
		p.iTable[i].action = decodeAtom
	}
	// atom F5 0xF5
	p.iTable[0xF5].pktType = PktAtomF5
	p.iTable[0xF5].action = decodeAtom
	// atoms F1 0xF6-0xF7
	for i := 0xF6; i <= 0xF7; i++ {
		p.iTable[i].pktType = PktAtomF1
		p.iTable[i].action = decodeAtom
	}
	// atoms F3 0xF8-0xFF
	for i := 0xF8; i <= 0xFF; i++ {
		p.iTable[i].pktType = PktAtomF3
		p.iTable[i].action = decodeAtom
	}
}
