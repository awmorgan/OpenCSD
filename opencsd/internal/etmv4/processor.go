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
	SendUnsynced
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

// Packet is a compatibility alias used by the stateless decoder API.
type Packet = TracePacket

var errDecodeNeedMoreData = errors.New("decodeNextPacket: need more data")
var errDecodeNotImplemented = errors.New("decodeNextPacket: packet type not implemented")

var decodeNextPacketWithConfigFn = decodeNextPacketWithConfig

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
		if consumed >= len(dataBlock) {
			break
		}

		if p.processState == ProcHdr && p.isSync && consumed < len(dataBlock) {
			packetIndex := p.blockIndex + ocsd.TrcIndex(consumed)
			pkt, bytesConsumed, err := decodeNextPacketWithConfigFn(p.config, dataBlock, consumed)
			switch {
			case err == nil:
				p.packetIndex = packetIndex
				p.applyDecodedPacket(pkt)
				p.currPacketData = append(p.currPacketData[:0], dataBlock[consumed:consumed+bytesConsumed]...)
				consumed += bytesConsumed
				p.blockBytesProcessed = consumed
				resp = p.emitCurrentPacket()
				continue
			case errors.Is(err, errDecodeNeedMoreData):
				// Packet spans block boundary; ProcData loop will accumulate remaining bytes.
			case errors.Is(err, errDecodeNotImplemented):
				// Fall back to the legacy state loop while migration is in progress.
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
				p.currPacket.Type = packetTypeForHeader(p.config, dataBlock[consumed])
			} else {
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
				if p.isSync {
					pkt, bytesConsumed, err := decodeNextPacketWithConfigFn(p.config, p.currPacketData, 0)
					if err != nil {
						if !errors.Is(err, errDecodeNeedMoreData) {
							return uint32(consumed), err
						}
					} else if bytesConsumed == len(p.currPacketData) {
						p.applyDecodedPacket(pkt)
						resp = p.emitCurrentPacket()
					}
				} else {
					if p.processUnsyncedByte(nextByte) {
						resp = p.emitCurrentPacket()
					}
				}
			}

		case SendUnsynced:
			resp = p.outputUnsyncedRawPacket()
			if p.updateOnUnsyncPktIdx != 0 {
				p.packetIndex = p.updateOnUnsyncPktIdx
				p.updateOnUnsyncPktIdx = 0
			}
			p.processState = ProcData
		}
	}

	return uint32(consumed), ocsd.DataErrFromResp(resp, nil)
}

func packetTypeForHeader(config Config, header uint8) PktType {
	switch {
	case header == 0x00:
		return PktExtension
	case header == 0x01:
		return PktTraceInfo
	case header == 0x02 || header == 0x03:
		return PktTimestamp
	case header == 0x04:
		return PktTraceOn
	case header == 0x05:
		return PktFuncRet
	case header == 0x06:
		return PktExcept
	case header == 0x07:
		return PktExceptRtn
	case header == uint8(ETE_PktITE) && config.MajVersion() >= 0x5 && config.MinVersion() >= 0x3:
		return ETE_PktITE
	case header == 0x0A && config.MajVersion() >= 0x5:
		return ETE_PktTransSt
	case header == 0x0B && config.MajVersion() >= 0x5:
		return ETE_PktTransCommit
	case header >= 0x0C && header <= 0x0D:
		return PktCcntF2
	case header >= 0x0E && header <= 0x0F:
		return PktCcntF1
	case header >= 0x10 && header <= 0x1F:
		return PktCcntF3
	case header >= 0x20 && header <= 0x27:
		return PktNumDsMkr
	case header >= 0x28 && header <= 0x2C:
		return PktUnnumDsMkr
	case header == 0x2D:
		return PktCommit
	case header == 0x2E:
		return PktCancelF1
	case header == 0x2F:
		return PktCancelF1Mispred
	case header >= 0x30 && header <= 0x33:
		return PktMispredict
	case header >= 0x34 && header <= 0x37:
		return PktCancelF2
	case header >= 0x38 && header <= 0x3F:
		return PktCancelF3
	case header >= 0x40 && header <= 0x42:
		return PktCondIF2
	case header == 0x43:
		return PktCondFlush
	case header >= 0x44 && header <= 0x46:
		return PktCondResF4
	case (header >= 0x48 && header <= 0x4A) || (header >= 0x4C && header <= 0x4E):
		return PktCondResF2
	case header >= 0x50 && header <= 0x5F:
		return PktCondResF3
	case header >= 0x68 && header <= 0x6B:
		return PktCondResF1
	case header == 0x6C:
		return PktCondIF1
	case header == 0x6D:
		return PktCondIF3
	case header >= 0x6E && header <= 0x6F:
		return PktCondResF1
	case header == 0x70 && config.FullVersion() >= 0x43:
		return PktIgnore
	case header >= 0x71 && header <= 0x7F:
		return PktEvent
	case header == 0x80 || header == 0x81:
		return PktCtxt
	case header == uint8(PktAddrCtxtL_32IS0):
		return PktAddrCtxtL_32IS0
	case header == uint8(PktAddrCtxtL_32IS1):
		return PktAddrCtxtL_32IS1
	case header == uint8(PktAddrCtxtL_64IS0):
		return PktAddrCtxtL_64IS0
	case header == uint8(PktAddrCtxtL_64IS1):
		return PktAddrCtxtL_64IS1
	case header == 0x88 && config.FullVersion() >= 0x46:
		return ETE_PktTSMarker
	case header >= uint8(PktAddrMatch) && header <= uint8(PktAddrMatch)+2:
		return PktAddrMatch
	case header == uint8(PktAddrS_IS0):
		return PktAddrS_IS0
	case header == uint8(PktAddrS_IS1):
		return PktAddrS_IS1
	case header == uint8(PktAddrL_32IS0):
		return PktAddrL_32IS0
	case header == uint8(PktAddrL_32IS1):
		return PktAddrL_32IS1
	case header == uint8(PktAddrL_64IS0):
		return PktAddrL_64IS0
	case header == uint8(PktAddrL_64IS1):
		return PktAddrL_64IS1
	case (header & 0xF0) == 0xA0:
		return PktQ
	case config.FullVersion() >= 0x50 && header >= uint8(ETE_PktSrcAddrMatch) && header <= uint8(ETE_PktSrcAddrMatch)+2:
		return ETE_PktSrcAddrMatch
	case config.FullVersion() >= 0x50 && header == uint8(ETE_PktSrcAddrS_IS0):
		return ETE_PktSrcAddrS_IS0
	case config.FullVersion() >= 0x50 && header == uint8(ETE_PktSrcAddrS_IS1):
		return ETE_PktSrcAddrS_IS1
	case config.FullVersion() >= 0x50 && header == uint8(ETE_PktSrcAddrL_32IS0):
		return ETE_PktSrcAddrL_32IS0
	case config.FullVersion() >= 0x50 && header == uint8(ETE_PktSrcAddrL_32IS1):
		return ETE_PktSrcAddrL_32IS1
	case config.FullVersion() >= 0x50 && header == uint8(ETE_PktSrcAddrL_64IS0):
		return ETE_PktSrcAddrL_64IS0
	case config.FullVersion() >= 0x50 && header == uint8(ETE_PktSrcAddrL_64IS1):
		return ETE_PktSrcAddrL_64IS1
	case (header >= 0xC0 && header <= 0xD4) || (header >= 0xE0 && header <= 0xF4):
		return PktAtomF6
	case (header >= 0xD5 && header <= 0xD7) || header == 0xF5:
		return PktAtomF5
	case header >= 0xD8 && header <= 0xDB:
		return PktAtomF2
	case header >= 0xDC && header <= 0xDF:
		return PktAtomF4
	case header >= 0xF6 && header <= 0xF7:
		return PktAtomF1
	case header >= 0xF8:
		return PktAtomF3
	default:
		return PktReserved
	}
}

func decodeNextPacketWithConfig(config Config, data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, fmt.Errorf("offset %d out of range", offset)
	}

	header := data[offset]
	if pkt, override := decodeConfigHeaderOverride(config, header); override {
		return pkt, 1, nil
	}

	switch {
	case header == 0x81:
		return decodeContextPacketWithConfig(config, data, offset)
	case header == uint8(PktAddrCtxtL_32IS0) || header == uint8(PktAddrCtxtL_32IS1) ||
		header == uint8(PktAddrCtxtL_64IS0) || header == uint8(PktAddrCtxtL_64IS1):
		return decodeAddrContextPacketWithConfig(config, data, offset)
	case header == 0x0C || header == 0x0D:
		return decodeCycleCntF2PacketWithConfig(config, data, offset)
	case header == 0x0E || header == 0x0F:
		return decodeCycleCntF1PacketWithConfig(config, data, offset)
	case header == 0x06:
		return decodeExceptionPacketWithConfig(config, data, offset)
	default:
		return decodeNextPacket(data, offset)
	}
}

func decodeConfigHeaderOverride(config Config, header uint8) (Packet, bool) {
	reservedHeaderPkt := func(pktType PktType) Packet {
		return Packet{Type: pktType, Err: errReservedHeader, ErrHdrVal: header}
	}
	reservedCfgPkt := func(pktType PktType) Packet {
		return Packet{Type: pktType, Err: errReservedCfg, ErrHdrVal: header}
	}

	if header == 0x05 {
		v8mFuncRetValid := config.CoreProf == ocsd.ProfileCortexM && ocsd.IsV8Arch(config.ArchVer) && config.FullVersion() >= 0x42
		if !v8mFuncRetValid {
			return reservedHeaderPkt(PktFuncRet), true
		}
	}

	if header == 0x07 && config.MajVersion() >= 0x5 {
		return reservedCfgPkt(PktExceptRtn), true
	}

	if header == uint8(ETE_PktITE) {
		if config.MajVersion() < 0x5 || config.MinVersion() < 0x3 {
			return reservedHeaderPkt(PktReserved), true
		}
	}

	if (header == 0x0A || header == 0x0B) && config.MajVersion() < 0x5 {
		return reservedHeaderPkt(PktReserved), true
	}

	if header >= 0x20 && header <= 0x27 && !config.EnabledDataTrace() {
		return reservedCfgPkt(PktNumDsMkr), true
	}
	if header >= 0x28 && header <= 0x2C && !config.EnabledDataTrace() {
		return reservedCfgPkt(PktUnnumDsMkr), true
	}

	condValid := config.HasCondTrace() && config.EnabledCondITrace() != CondTrDis
	if !condValid {
		switch {
		case header >= 0x40 && header <= 0x42:
			return reservedCfgPkt(PktCondIF2), true
		case header == 0x43:
			return reservedCfgPkt(PktCondFlush), true
		case header >= 0x44 && header <= 0x46:
			return reservedCfgPkt(PktCondResF4), true
		case (header >= 0x48 && header <= 0x4A) || (header >= 0x4C && header <= 0x4E):
			return reservedCfgPkt(PktCondResF2), true
		case header >= 0x50 && header <= 0x5F:
			return reservedCfgPkt(PktCondResF3), true
		case header >= 0x68 && header <= 0x6B:
			return reservedCfgPkt(PktCondResF1), true
		case header == 0x6C:
			return reservedCfgPkt(PktCondIF1), true
		case header == 0x6D:
			return reservedCfgPkt(PktCondIF3), true
		case header >= 0x6E && header <= 0x6F:
			return reservedCfgPkt(PktCondResF1), true
		}
	}

	if (header & 0xF0) == 0xA0 {
		qType := header & 0xF
		if !config.HasQElem() {
			return reservedHeaderPkt(PktQ), true
		}
		switch qType {
		case 0x3, 0x4, 0x7, 0x8, 0x9, 0xD, 0xE:
			return reservedHeaderPkt(PktQ), true
		}
	}

	if header == 0x70 && config.FullVersion() < 0x43 {
		return reservedHeaderPkt(PktReserved), true
	}

	if header == 0x88 && config.FullVersion() < 0x46 {
		return reservedHeaderPkt(PktReserved), true
	}

	if header >= 0xB0 && header <= 0xB9 && config.FullVersion() < 0x50 {
		return reservedHeaderPkt(PktReserved), true
	}

	return Packet{}, false
}

func (p *Processor) applyDecodedContext(ctx Context) {
	p.currPacket.Context.Updated = ctx.Updated
	p.currPacket.Context.EL = ctx.EL
	p.currPacket.Context.SF = ctx.SF
	p.currPacket.Context.NS = ctx.NS
	p.currPacket.Context.NSE = ctx.NSE
	p.currPacket.Context.UpdatedV = ctx.UpdatedV
	p.currPacket.Context.UpdatedC = ctx.UpdatedC
	if ctx.UpdatedV {
		p.currPacket.Context.VMID = ctx.VMID
	}
	if ctx.UpdatedC {
		p.currPacket.Context.CtxtID = ctx.CtxtID
	}
	p.currPacket.Valid.Context = true
}

func (p *Processor) applyDecodedPacket(pkt Packet) {
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
		if pkt.Valid.CommitElem {
			p.currPacket.CommitElements = pkt.CommitElements
			p.currPacket.Valid.CommitElem = true
		}
	case PktCcntF1:
		if pkt.Valid.CycleCount {
			p.currPacket.CycleCount = p.currPacket.CCThreshold + pkt.CycleCount
			p.currPacket.Valid.CCExactMatch = p.currPacket.CycleCount == p.currPacket.CCThreshold
		} else {
			p.currPacket.CycleCount = 0
			p.currPacket.Valid.CCExactMatch = false
		}
		if pkt.Valid.CommitElem {
			p.currPacket.CommitElements = pkt.CommitElements
			p.currPacket.Valid.CommitElem = true
		}
	case PktMispredict, PktCancelF2, PktCancelF3:
		p.currPacket.Atom = pkt.Atom
		p.currPacket.CancelElements = pkt.CancelElements
	case PktCommit:
		p.currPacket.CommitElements = pkt.CommitElements
	case PktCancelF1, PktCancelF1Mispred:
		p.currPacket.CancelElements = pkt.CancelElements
	case PktCondIF1, PktCondIF2:
		p.currPacket.CondInstr.CondCKey = pkt.CondInstr.CondCKey
		p.currPacket.CondInstr.CondKeySet = pkt.CondInstr.CondKeySet
	case PktCondIF3:
		p.currPacket.CondInstr.NumCElem = pkt.CondInstr.NumCElem
		p.currPacket.CondInstr.F3FinalElem = pkt.CondInstr.F3FinalElem
	case PktCondResF1:
		p.currPacket.CondResult = pkt.CondResult
	case PktCondResF2:
		p.currPacket.CondResult.F2KeyIncr = pkt.CondResult.F2KeyIncr
		p.currPacket.CondResult.Res0 = pkt.CondResult.Res0
	case PktCondResF4:
		p.currPacket.CondResult.Res0 = pkt.CondResult.Res0
	case PktCondResF3:
		p.currPacket.CondResult.F3Tokens = pkt.CondResult.F3Tokens
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
	case PktAddrL_64IS0, PktAddrL_64IS1, ETE_PktSrcAddrL_64IS0, ETE_PktSrcAddrL_64IS1:
		p.currPacket.VAddr = pkt.VAddr
		p.currPacket.VAddrValidBits = pkt.VAddrValidBits
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
			p.applyDecodedContext(pkt.Context)
		}
	case PktAddrCtxtL_64IS0, PktAddrCtxtL_64IS1:
		p.currPacket.VAddr = pkt.VAddr
		p.currPacket.VAddrValidBits = pkt.VAddrValidBits
		p.currPacket.VAddrPktBits = pkt.VAddrPktBits
		p.currPacket.VAddrISA = pkt.VAddrISA
		p.currPacket.PushVAddr()
		if pkt.Valid.Context {
			p.applyDecodedContext(pkt.Context)
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
			p.applyDecodedContext(pkt.Context)
		}
	case PktNumDsMkr, PktUnnumDsMkr:
		p.currPacket.DsmVal = pkt.DsmVal
	case PktEvent:
		p.currPacket.EventVal = pkt.EventVal
	case PktExcept, ETE_PktPeReset, ETE_PktTransFail:
		p.currPacket.ExceptionInfo = pkt.ExceptionInfo
		if pkt.Type == ETE_PktPeReset || pkt.Type == ETE_PktTransFail {
			p.currPacket.VAddr = 0
		}
	}
}

// decodeNextPacket decodes a single packet starting at offset without using Processor state.
// It returns errDecodeNeedMoreData when more bytes are required to complete a packet.
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

	if header >= 0x40 && header <= 0x42 {
		return decodeCondIF2Packet(header), 1, nil
	}

	if header == 0x6C {
		return decodeCondIF1Packet(data, offset)
	}

	if (header >= 0x68 && header <= 0x6B) || (header >= 0x6E && header <= 0x6F) {
		return decodeCondResF1Packet(data, offset)
	}

	if header == 0x6D {
		return decodeCondIF3Packet(data, offset)
	}

	if (header >= 0x48 && header <= 0x4A) || (header >= 0x4C && header <= 0x4E) {
		return decodeCondResF2Packet(header)
	}

	if header >= 0x44 && header <= 0x46 {
		return decodeCondResF4Packet(header)
	}

	if header >= 0x50 && header <= 0x5F {
		return decodeCondResF3Packet(data, offset)
	}

	if header == uint8(PktCommit) || header == uint8(PktCancelF1) || header == uint8(PktCancelF1Mispred) {
		return decodeVariableSpecResPacket(data, offset)
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
	if ok {
		pkt := Packet{Type: atomType, Atom: atom}
		return pkt, 1, nil
	}

	// Any synchronized but otherwise-unclaimed header is architecturally reserved.
	pkt := Packet{Type: PktReserved}
	pkt.Err = errReservedHeader
	pkt.ErrHdrVal = header
	return pkt, 1, nil
}
func decodeITEPacket(data []byte, offset int) (Packet, int, error) {
	if offset+10 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
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
		return Packet{}, 0, errDecodeNeedMoreData
	}

	byte1 := data[offset+1]
	excepType := uint16((byte1 >> 1) & 0x1F)
	addrInterp := (byte1&0x40)>>5 | (byte1 & 0x1)

	pkt := Packet{Type: PktExcept}
	pkt.ExceptionInfo.ExceptionType = excepType
	pkt.ExceptionInfo.AddrInterp = addrInterp

	if (byte1 & 0x80) == 0 {
		// Without config context, default to the 2-byte exception form.
		// Config-aware decode promotes these to ETE-specific 3-byte packets when required.
		return pkt, 2, nil
	}

	if offset+3 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	byte2 := data[offset+2]
	pkt.ExceptionInfo.ExceptionType |= (uint16(byte2) & 0x1F) << 5
	pkt.ExceptionInfo.MFaultPending = ((byte2 >> 5) & 0x1) != 0
	return pkt, 3, nil
}

func decodeExceptionPacketWithConfig(config Config, data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	byte1 := data[offset+1]
	excepType := uint16((byte1 >> 1) & 0x1F)
	addrInterp := (byte1&0x40)>>5 | (byte1 & 0x1)
	hasExtType := (byte1 & 0x80) != 0

	requireThreeBytes := hasExtType
	if config.MajVersion() >= 0x5 && (excepType == 0x0 || excepType == 0x18) {
		requireThreeBytes = true
	}

	pkt := Packet{Type: PktExcept}
	pkt.ExceptionInfo.ExceptionType = excepType
	pkt.ExceptionInfo.AddrInterp = addrInterp
	pkt.ExceptionInfo.MType = config.CoreProf == ocsd.ProfileCortexM

	consumed := 2
	if requireThreeBytes {
		if offset+3 > len(data) {
			return Packet{}, 0, errDecodeNeedMoreData
		}
		if hasExtType {
			byte2 := data[offset+2]
			pkt.ExceptionInfo.ExceptionType |= (uint16(byte2) & 0x1F) << 5
			pkt.ExceptionInfo.MFaultPending = ((byte2 >> 5) & 0x1) != 0
		}
		consumed = 3
	}

	if config.MajVersion() >= 0x5 {
		switch pkt.ExceptionInfo.ExceptionType {
		case 0x18:
			pkt.Type = ETE_PktTransFail
			pkt.VAddr = 0
		case 0x0:
			pkt.Type = ETE_PktPeReset
			pkt.VAddr = 0
		}
	}

	return pkt, consumed, nil
}

func decodeTraceInfoPacket(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	idx := offset + 1
	firstCtrl := data[idx]
	for {
		if idx >= len(data) {
			return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
		}
		idx += n
		pkt.P0Key = fieldVal
	}

	if presSect&uint8(TInfoSpecSect) != 0 {
		fieldVal, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
		}
		idx += n
		pkt.CurrSpecDepth = fieldVal
		pkt.TraceInfo.SpecFieldPresent = true
		pkt.Valid.SpecDepthValid = true
	}

	if presSect&uint8(TInfoCyctSect) != 0 {
		fieldVal, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
		}
		idx += n
		pkt.CCThreshold = fieldVal
		pkt.Valid.CCThreshold = true
	}

	if presSect&uint8(TInfoWndwSect) != 0 {
		_, n, ok := decodeContField32(data, idx, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
		}
		idx += n
	}

	return pkt, idx - offset, nil
}

func decodeExtensionPacket(data []byte, offset int) (Packet, int, error) {
	if offset+1 >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	subType := data[offset+1]
	switch subType {
	case 0x03:
		return Packet{Type: PktDiscard}, 2, nil
	case 0x05:
		return Packet{Type: PktOverflow}, 2, nil
	case 0x00:
		// Async packet: 12 bytes of form {0x00 ×11, 0x80}.
		// Early-abort on the first non-zero byte in positions 2-10 to match the
		// reference decoder's iPktASync behaviour, which outputs the packet immediately
		// upon seeing the bad byte rather than waiting for a full 12-byte window.
		for i := 2; i < 12; i++ {
			if offset+i >= len(data) {
				return Packet{}, 0, errDecodeNeedMoreData
			}
			b := data[offset+i]
			if i < 11 {
				if b != 0x00 {
					return Packet{Type: PktAsync, Err: ocsd.ErrBadPacketSeq}, i + 1, nil
				}
			} else { // i == 11
				if b != 0x80 {
					return Packet{Type: PktAsync, Err: ocsd.ErrBadPacketSeq}, 12, nil
				}
				return Packet{Type: PktAsync}, 12, nil
			}
		}
		return Packet{Type: PktAsync}, 12, nil // unreachable
	default:
		return Packet{Type: PktExtension, Err: ocsd.ErrBadPacketSeq}, 2, nil
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
		return Packet{}, 0, errDecodeNeedMoreData
	}

	pkt := Packet{Type: PktCcntF2}
	pkt.CycleCount = uint32(data[offset+1] & 0xF)
	return pkt, 2, nil
}

func decodeCycleCntF2PacketWithConfig(config Config, data []byte, offset int) (Packet, int, error) {
	pkt, consumed, err := decodeCycleCntF2Packet(data, offset)
	if err != nil {
		return Packet{}, 0, err
	}

	if !config.CommitOpt1() {
		commitOffset := 1
		if (data[offset] & 0x1) == 0x1 {
			commitOffset = int(config.MaxSpecDepth()) - 15
		}
		commitElements := int((data[offset+1]>>4)&0xF) + commitOffset
		pkt.CommitElements = uint32(commitElements)
		pkt.Valid.CommitElem = true
	}

	return pkt, consumed, nil
}

func decodeCycleCntF1Packet(data []byte, offset int) (Packet, int, error) {
	if offset >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
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
		return Packet{}, 0, errDecodeNeedMoreData
	}
	pkt.CycleCount = count
	pkt.Valid.CycleCount = true
	return pkt, 1 + n, nil
}

func decodeCycleCntF1PacketWithConfig(config Config, data []byte, offset int) (Packet, int, error) {
	if offset >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	header := data[offset]
	pkt := Packet{Type: PktCcntF1}

	if config.CommitOpt1() {
		return decodeCycleCntF1Packet(data, offset)
	}

	idx := offset + 1
	commit, n, ok := decodeContField32(data, idx, 5)
	if !ok {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	idx += n
	pkt.CommitElements = commit
	pkt.Valid.CommitElem = true

	if (header & 0x1) == 0x1 {
		pkt.Valid.CycleCount = false
		pkt.CycleCount = 0
		return pkt, idx - offset, nil
	}

	count, n, ok := decodeContField32(data, idx, 3)
	if !ok {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	idx += n
	pkt.CycleCount = count
	pkt.Valid.CycleCount = true

	return pkt, idx - offset, nil
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

func decodeVariableSpecResPacket(data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	header := data[offset]
	fieldVal, n, ok := decodeContField32(data, offset+1, 5)
	if !ok {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	switch header {
	case uint8(PktCommit):
		pkt := Packet{Type: PktCommit}
		pkt.CommitElements = fieldVal
		return pkt, 1 + n, nil
	case uint8(PktCancelF1), uint8(PktCancelF1Mispred):
		pktType := PktCancelF1
		if header == uint8(PktCancelF1Mispred) {
			pktType = PktCancelF1Mispred
		}
		pkt := Packet{Type: pktType}
		pkt.CancelElements = fieldVal
		return pkt, 1 + n, nil
	default:
		return Packet{}, 0, fmt.Errorf("decodeVariableSpecResPacket: invalid header 0x%02X", header)
	}
}

func decodeCondIF2Packet(header uint8) Packet {
	pkt := Packet{Type: PktCondIF2}
	pkt.CondInstr.CondCKey = uint32(header & 0x3)
	return pkt
}

func decodeCondIF1Packet(data []byte, offset int) (Packet, int, error) {
	fieldVal, n, ok := decodeContField32(data, offset+1, 5)
	if !ok {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	pkt := Packet{Type: PktCondIF1}
	pkt.CondInstr.CondCKey = fieldVal
	pkt.CondInstr.CondKeySet = true
	return pkt, 1 + n, nil
}

func decodeCondIF3Packet(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	payload := data[offset+1]
	pkt := Packet{Type: PktCondIF3}
	pkt.CondInstr.NumCElem = uint8((payload>>1)&0x3F) + (payload & 0x1)
	pkt.CondInstr.F3FinalElem = (payload & 0x1) == 0x1
	return pkt, 2, nil
}

func decodeCondResF2Packet(header uint8) (Packet, int, error) {
	pkt := Packet{Type: PktCondResF2}
	if (header & 0x4) != 0 {
		pkt.CondResult.F2KeyIncr = 2
	} else {
		pkt.CondResult.F2KeyIncr = 1
	}
	pkt.CondResult.Res0 = header & 0x3
	return pkt, 1, nil
}

func decodeCondResF4Packet(header uint8) (Packet, int, error) {
	pkt := Packet{Type: PktCondResF4}
	pkt.CondResult.Res0 = header & 0x3
	return pkt, 1, nil
}

func decodeCondResF1Packet(data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	header := data[offset]
	pkt := Packet{Type: PktCondResF1}

	ci0 := header & 0x1
	ci1 := (header >> 1) & 0x1

	idx := offset + 1
	key0, res0, n0, ok := decodeCondResultField(data, idx)
	if !ok {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	pkt.CondResult.CondRKey0 = key0
	pkt.CondResult.Res0 = res0
	pkt.CondResult.CI0 = ci0 != 0
	pkt.CondResult.KeyRes0Set = true
	idx += n0

	// For headers 0x6E/0x6F only one result field is present.
	if (header & 0xFC) != 0x6C {
		key1, res1, n1, ok := decodeCondResultField(data, idx)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
		}
		pkt.CondResult.CondRKey1 = key1
		pkt.CondResult.Res1 = res1
		pkt.CondResult.CI1 = ci1 != 0
		pkt.CondResult.KeyRes1Set = true
		idx += n1
	}

	return pkt, idx - offset, nil
}

func decodeCondResultField(data []byte, stIdx int) (key uint32, result uint8, consumed int, ok bool) {
	if stIdx < 0 || stIdx >= len(data) {
		return 0, 0, 0, false
	}

	idx := 0
	incr := 0
	for idx < 6 {
		if stIdx+idx >= len(data) {
			return 0, 0, 0, false
		}
		byteVal := data[stIdx+idx]
		if idx == 0 {
			result = byteVal & 0xF
			key = uint32((byteVal >> 4) & 0x7)
			incr = 3
		} else {
			key |= uint32(byteVal&0x7F) << incr
			incr += 7
		}
		idx++
		if (byteVal & 0x80) == 0 {
			return key, result, idx, true
		}
	}

	return 0, 0, 0, false
}

func decodeCondResF3Packet(data []byte, offset int) (Packet, int, error) {
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	pkt := Packet{Type: PktCondResF3}
	f3Tokens := uint16(data[offset+1])
	f3Tokens |= (uint16(data[offset]) & 0xF) << 8
	pkt.CondResult.F3Tokens = f3Tokens
	return pkt, 2, nil
}

func decodeTimestampPacket(data []byte, offset int) (Packet, int, error) {
	if offset+1 >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	tsVal, tsBytes, ok := decodeTSField64(data, offset+1)
	if !ok {
		return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
		}
		pkt.CycleCount = cc
		pkt.Valid.CycleCount = true
		consumed += ccBytes
	}

	return pkt, consumed, nil
}

func decodeLongAddr64Packet(data []byte, offset int) (Packet, int, error) {
	if offset+9 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
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
		return Packet{}, 0, errDecodeNeedMoreData
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
		return Packet{}, 0, errDecodeNeedMoreData
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
		return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
		}
		count, n, ok := decodeContField32(data, offset+1, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
		}
		is := uint8(0)
		if qType == 0x6 {
			is = 1
		}
		addr, bits, nAddr, ok := decodeShortAddrPayload(data, offset+1, is)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
		}
		count, nCount, ok := decodeContField32(data, offset+1+nAddr, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
		}
		is := uint8(0)
		if qType == 0xB {
			is = 1
		}
		addr := decodeLongAddr32Value(data[offset+1:offset+5], is)
		count, nCount, ok := decodeContField32(data, offset+5, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
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
			return Packet{}, 0, errDecodeNeedMoreData
		}
		count, n, ok := decodeContField32(data, offset+1, 5)
		if !ok {
			return Packet{}, 0, errDecodeNeedMoreData
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
	case 0x3, 0x4, 0x7, 0x8, 0x9, 0xD, 0xE:
		return Packet{Type: PktReserved, Err: errReservedHeader, ErrHdrVal: header}, 1, nil
	default:
		return Packet{}, 0, errDecodeNeedMoreData
	}
}

func decodeContextPacket(data []byte, offset int) (Packet, int, error) {
	header := data[offset]

	if header == 0x80 {
		return Packet{Type: PktCtxt}, 1, nil
	}

	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	info := data[offset+1]
	if (info & 0xC0) != 0 {
		return Packet{}, 0, fmt.Errorf("decodeContextPacket: context IDs require config-aware decode")
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

func decodeContextPacketWithConfig(config Config, data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}
	if data[offset] != 0x81 {
		return Packet{}, 0, fmt.Errorf("decodeContextPacketWithConfig: invalid header 0x%02X", data[offset])
	}
	if offset+2 > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	info := data[offset+1]
	vmidBytes := 0
	ctxtIDBytes := 0
	if (info & 0x40) != 0 {
		vmidBytes = int(config.VmidSize()) / 8
	}
	if (info & 0x80) != 0 {
		ctxtIDBytes = int(config.CidSize()) / 8
	}

	consumed := 2 + vmidBytes + ctxtIDBytes
	if offset+consumed > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	pkt := Packet{Type: PktCtxt}
	pkt.Context.Updated = true
	pkt.Context.EL = info & 0x3
	pkt.Context.NSE = ((info >> 3) & 0x1) != 0
	pkt.Context.SF = ((info >> 4) & 0x1) != 0
	pkt.Context.NS = ((info >> 5) & 0x1) != 0

	payloadIdx := offset + 2
	if vmidBytes > 0 {
		pkt.Context.UpdatedV = true
		var vmid uint32
		for i := 0; i < vmidBytes; i++ {
			vmid |= uint32(data[payloadIdx+i]) << (i * 8)
		}
		pkt.Context.VMID = vmid
		payloadIdx += vmidBytes
	}
	if ctxtIDBytes > 0 {
		pkt.Context.UpdatedC = true
		var cid uint32
		for i := 0; i < ctxtIDBytes; i++ {
			cid |= uint32(data[payloadIdx+i]) << (i * 8)
		}
		pkt.Context.CtxtID = cid
	}

	pkt.Valid.Context = true
	return pkt, consumed, nil
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
		return Packet{}, 0, fmt.Errorf("decodeAddrContextPacket: invalid header 0x%02X", header)
	}

	minLen := 1 + addrBytes + 1
	if offset+minLen > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	info := data[offset+1+addrBytes]
	if (info & 0xC0) != 0 {
		return Packet{}, 0, fmt.Errorf("decodeAddrContextPacket: context IDs require config-aware decode")
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

func decodeAddrContextPacketWithConfig(config Config, data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

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
		return Packet{}, 0, fmt.Errorf("decodeAddrContextPacketWithConfig: invalid header 0x%02X", header)
	}

	minLen := 1 + addrBytes + 1
	if offset+minLen > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
	}

	info := data[offset+1+addrBytes]
	vmidBytes := 0
	ctxtIDBytes := 0
	if (info & 0x40) != 0 {
		vmidBytes = int(config.VmidSize()) / 8
	}
	if (info & 0x80) != 0 {
		ctxtIDBytes = int(config.CidSize()) / 8
	}

	consumed := minLen + vmidBytes + ctxtIDBytes
	if offset+consumed > len(data) {
		return Packet{}, 0, errDecodeNeedMoreData
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

	payloadIdx := offset + minLen
	if vmidBytes > 0 {
		pkt.Context.UpdatedV = true
		var vmid uint32
		for i := 0; i < vmidBytes; i++ {
			vmid |= uint32(data[payloadIdx+i]) << (i * 8)
		}
		pkt.Context.VMID = vmid
		payloadIdx += vmidBytes
	}
	if ctxtIDBytes > 0 {
		pkt.Context.UpdatedC = true
		var cid uint32
		for i := 0; i < ctxtIDBytes; i++ {
			cid |= uint32(data[payloadIdx+i]) << (i * 8)
		}
		pkt.Context.CtxtID = cid
	}

	pkt.Valid.Context = true
	return pkt, consumed, nil
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
	p.packetIndex = 0
	p.isSync = false
	p.firstTraceInfo = false
	p.sentNotsyncPacket = false
	p.processState = ProcHdr
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

func (p *Processor) emitCurrentPacket() ocsd.DatapathResp {
	resp := p.outputPacket()
	p.resetPacketState()
	p.processState = ProcHdr
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

func (p *Processor) processUnsyncedByte(lastByte uint8) bool {
	switch p.currPacket.Type {
	case PktAsync:
		return p.processUnsyncedASync(lastByte)
	default:
		if !p.isSync && len(p.currPacketData) > 0 && p.currPacketData[0] == 0x00 && len(p.currPacketData) <= 2 {
			return p.processUnsyncedExtension(lastByte)
		}
		p.processUnsyncedNotSync(lastByte)
		return false
	}
}

func (p *Processor) processUnsyncedNotSync(lastByte uint8) {
	if lastByte == 0x00 {
		if len(p.currPacketData) > 1 {
			p.queueUnsyncedDump(len(p.currPacketData)-1, p.blockIndex+ocsd.TrcIndex(p.blockBytesProcessed)-1)
		} else {
			p.packetIndex = p.blockIndex + ocsd.TrcIndex(p.blockBytesProcessed) - 1
		}
	} else if len(p.currPacketData) >= 8 {
		p.queueUnsyncedDump(len(p.currPacketData), p.blockIndex+ocsd.TrcIndex(p.blockBytesProcessed))
	}
}

func (p *Processor) queueUnsyncedDump(bytes int, updateIdx ocsd.TrcIndex) {
	p.dumpUnsyncedBytes = bytes
	p.processState = SendUnsynced
	p.updateOnUnsyncPktIdx = updateIdx
}

func (p *Processor) processUnsyncedExtension(lastByte uint8) bool {
	if len(p.currPacketData) == 1 {
		p.packetIndex = p.blockIndex + ocsd.TrcIndex(p.blockBytesProcessed) - 1
		return false
	}

	if len(p.currPacketData) == 2 {
		if !p.isSync && lastByte != 0x00 {
			p.currPacket.Type = PktNotSync
			return false
		}
		switch lastByte {
		case 0x03:
			p.currPacket.Type = PktDiscard
			return true
		case 0x05:
			p.currPacket.Type = PktOverflow
			return true
		case 0x00:
			p.currPacket.Type = PktAsync
			return false
		default:
			p.currPacket.Err = ocsd.ErrBadPacketSeq
			return true
		}
	}

	return false
}

func (p *Processor) processUnsyncedASync(lastByte uint8) bool {
	if lastByte != 0x00 {
		if !p.isSync && len(p.currPacketData) != 12 {
			p.currPacket.Type = PktNotSync
			return false
		}
		if len(p.currPacketData) != 12 || lastByte != 0x80 {
			p.currPacket.Err = ocsd.ErrBadPacketSeq
		} else {
			p.isSync = true
		}
		return true
	} else if len(p.currPacketData) == 12 {
		if !p.isSync {
			p.queueUnsyncedDump(1, 0)
		} else {
			p.currPacket.Err = ocsd.ErrBadPacketSeq
			return true
		}
	}

	return false
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
	if errors.Is(p.currPacket.Err, ocsd.ErrBadPacketSeq) {
		return
	}
	p.currPacket.Err = fmt.Errorf("%w: malformed %s", ocsd.ErrBadPacketSeq, malformedType.String())
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
