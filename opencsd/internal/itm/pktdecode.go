package itm

import (
	"fmt"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type decoderState int

const (
	dcdNoSync decoderState = iota
	dcdWaitSync
	dcdDecodePkts
)

// PktDecode decodes ITM packets into generic ITM-SW trace packets.
type PktDecode struct {
	common.DecoderBase
	Config       *Config
	CurrPacketIn *Packet
	lastErr      error

	currState decoderState

	itmInfo       ocsd.SWTItmInfo
	localTSCount  uint64
	globalTS      uint64
	stimPage      uint8
	needGTS2      bool
	prevOverflow  bool
	gtsFreqChange bool

	unsyncInfo common.UnsyncInfo
	csID       uint8
	outputElem ocsd.TraceElement
}

// NewPktDecode creates a new ITM packet decoder.
func NewPktDecode(cfg *Config) *PktDecode {
	instID := 0
	if cfg != nil {
		instID = int(cfg.TraceID())
	}
	d := &PktDecode{
		DecoderBase: common.DecoderBase{
			Name:          fmt.Sprintf("DCD_ITM_%d", instID),
			UsesMemAccess: true,
			UsesIDecode:   true,
		},
	}
	d.configureDecoder()
	if cfg != nil {
		_ = d.SetProtocolConfig(cfg)
	}
	return d
}

// SetTraceElemOut satisfies dcdtree's traceElemSetterOwner interface.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) { d.TraceElemOut = out }

// SetMemAccess satisfies dcdtree's memAccSetterOwner interface.
func (d *PktDecode) SetMemAccess(mem common.TargetMemAccess) { d.MemAccess = mem }

// SetInstrDecode satisfies dcdtree's instrDecodeSetterOwner interface.
func (d *PktDecode) SetInstrDecode(dec common.InstrDecode) { d.InstrDecode = dec }

// SetProtocolConfig sets the ITM hardware configuration.
func (d *PktDecode) SetProtocolConfig(cfg *Config) error {
	d.Config = cfg
	if d.Config == nil {
		return ocsd.ErrNotInit
	}
	d.csID = d.Config.TraceID()
	d.ConfigInitOK = true
	return nil
}

func (d *PktDecode) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *Packet) ocsd.DatapathResp {
	resp := ocsd.RespCont
	d.lastErr = nil
	if reason := d.DecodeNotReadyReason(); reason != "" {
		d.lastErr = fmt.Errorf("%w: %s", ocsd.ErrNotInit, reason)
		return ocsd.RespFatalNotInit
	}

	switch op {
	case ocsd.OpData:
		if pktIn == nil {
			d.lastErr = ocsd.ErrInvalidParamVal
			resp = ocsd.RespFatalInvalidParam
		} else {
			d.CurrPacketIn = pktIn
			d.IndexCurrPkt = indexSOP
			resp = d.ProcessPacket()
		}
	case ocsd.OpEOT:
		resp = d.OnEOT()
	case ocsd.OpFlush:
		resp = d.OnFlush()
	case ocsd.OpReset:
		resp = d.OnReset()
	default:
		d.lastErr = ocsd.ErrInvalidParamVal
		resp = ocsd.RespFatalInvalidOp
	}
	return resp
}

func (d *PktDecode) ProcessPacket() ocsd.DatapathResp {
	var resp ocsd.DatapathResp
	for {
		var next decoderState
		var done bool
		switch d.currState {
		case dcdNoSync:
			next, resp, done = d.handleNoSync()
		case dcdWaitSync:
			next, resp, done = d.handleWaitSync()
		case dcdDecodePkts:
			next, resp, done = d.handleDecodePkts()
		default:
			return ocsd.RespCont
		}
		d.currState = next
		if done {
			return resp
		}
	}
}

func (d *PktDecode) handleNoSync() (decoderState, ocsd.DatapathResp, bool) {
	d.outputElem.SetType(ocsd.GenElemNoSync)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncInfo(d.unsyncInfo))
	resp := d.OutputTraceElement(d.csID, &d.outputElem)
	return dcdWaitSync, resp, false // continue to waitSync
}

func (d *PktDecode) handleWaitSync() (decoderState, ocsd.DatapathResp, bool) {
	if d.CurrPacketIn.Type == PktAsync {
		return dcdDecodePkts, ocsd.RespCont, true
	}
	return dcdWaitSync, ocsd.RespCont, true
}

func (d *PktDecode) handleDecodePkts() (decoderState, ocsd.DatapathResp, bool) {
	return dcdDecodePkts, d.decodePacket(), true
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(d.csID, &d.outputElem)
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
	// d.resetDecoder() // C++ has it commented out
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	// don't currently save unsent packets so nothing to flush
	return ocsd.RespCont
}

func (d *PktDecode) TraceID() uint8 {
	return d.csID
}

func (d *PktDecode) configureDecoder() {
	d.csID = 0

	// base decoder state - ITM requires no memory and instruction decode.
	d.UsesMemAccess = false
	d.UsesIDecode = false
	d.unsyncInfo = common.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) resetDecoder() {
	d.outputElem.Init()
	d.currState = dcdNoSync

	d.localTSCount = 0
	d.globalTS = 0
	d.stimPage = 0
	d.needGTS2 = true
	d.prevOverflow = false
	d.gtsFreqChange = false
}

func (d *PktDecode) decodePacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	globalTSLowMask := []uint64{
		0x00000007F, // [ 6:0]
		0x000003FFF, // [13:0]
		0x0001FFFFF, // [20:0]
		0x003FFFFFF, // [25:0]
	}
	globalTSHiMask := ^globalTSLowMask[3]

	sendPacket := false
	srcID := d.CurrPacketIn.SrcID

	localTSTCTypes := []ocsd.SWTItmType{
		ocsd.TSSync,
		ocsd.TSDelay,
		ocsd.TSPKTDelay,
		ocsd.TSPKTTSDelay,
	}

	d.itmInfo = ocsd.SWTItmInfo{}

	switch d.CurrPacketIn.Type {
	case PktBadSequence, PktReserved:
		resp = ocsd.RespFatalInvalidData
		d.unsyncInfo = common.UnsyncBadPacket
		fallthrough
	case PktNotSync:
		d.resetDecoder()

	case PktAsync, PktIncompleteEOT:
		// do nothing

	case PktDWT:
		d.itmInfo.PktType = ocsd.DWTPayload
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktSWIT:
		d.itmInfo.PktType = ocsd.SWITPayload
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value
		srcID = (srcID & 0x1F) | (d.stimPage << 5)
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktExtension:
		if (srcID&0x80) == 0 && (srcID&0x1F) == 2 {
			d.stimPage = uint8(d.CurrPacketIn.Value)
		}

	case PktOverflow:
		d.localTSCount = 0
		d.prevOverflow = true

	case PktTSGlobal1:
		if !d.needGTS2 {
			d.needGTS2 = (srcID & 0x2) != 0
		}
		if !d.gtsFreqChange {
			d.gtsFreqChange = (srcID & 0x1) != 0
		}

		d.globalTS &= ^globalTSLowMask[d.CurrPacketIn.ValSz-1]
		d.globalTS |= uint64(d.CurrPacketIn.Value)

		if !d.needGTS2 {
			d.itmInfo.PktType = ocsd.TSGlobal
			d.outputElem.SetTS(d.globalTS, d.gtsFreqChange)
			d.gtsFreqChange = false
			sendPacket = true
		}

	case PktTSGlobal2:
		d.itmInfo.PktType = ocsd.TSGlobal
		d.globalTS &= ^globalTSHiMask
		d.globalTS |= (d.CurrPacketIn.ExtValue() << 26)
		d.outputElem.SetTS(d.globalTS, d.gtsFreqChange)
		d.gtsFreqChange = false
		d.needGTS2 = false
		sendPacket = true

	case PktTSLocal:
		d.itmInfo.PktType = localTSTCTypes[srcID&0x3]
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value

		prescale := uint64(1)
		if d.Config != nil {
			prescale = uint64(d.Config.TSPrescaleValue())
		}
		d.localTSCount += uint64(d.itmInfo.Value) * prescale
		d.outputElem.SetTS(d.localTSCount, false)
		sendPacket = true
	}

	if sendPacket {
		if d.prevOverflow {
			d.itmInfo.Overflow = 1
			d.prevOverflow = false
		}
		d.outputElem.SetType(ocsd.GenElemITMTrace)
		d.outputElem.SetSWTITMInfo(d.itmInfo)
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
	}

	return resp
}
