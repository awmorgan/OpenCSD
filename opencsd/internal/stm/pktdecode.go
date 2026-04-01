package stm

import (
	"encoding/binary"
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

// PktDecode converts incoming STM packets to generic output packets.
type PktDecode struct {
	common.DecoderBase
	Config       *Config
	CurrPacketIn *Packet
	lastErr      error

	currState  decoderState
	unsyncInfo common.UnsyncInfo

	swtPacketInfo ocsd.SWTInfo

	payloadBuffer     []byte
	payloadSize       int
	payloadUsed       int
	payloadOddNibble  bool
	numPktCorrelation int

	csID uint8

	decodePass1 bool
	outputElem  ocsd.TraceElement
}

// NewPktDecode creates a new STM packet decoder.
func NewPktDecode(cfg *Config, _ ocsd.Logger) *PktDecode {
	instIDNum := 0
	if cfg != nil {
		instIDNum = int(cfg.TraceID())
	}
	d := &PktDecode{
		DecoderBase: common.DecoderBase{
			Name: fmt.Sprintf("DCD_STM_%d", instIDNum),
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

// SetProtocolConfig sets the STM hardware configuration.
func (d *PktDecode) SetProtocolConfig(config *Config) error {
	d.Config = config
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
	d.decodePass1 = true

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
	resp, done := d.decodePacket()
	return dcdDecodePkts, resp, done
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(d.csID, &d.outputElem)
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (d *PktDecode) TraceID() uint8 {
	return d.csID
}

func (d *PktDecode) configureDecoder() {
	d.numPktCorrelation = 1
	d.csID = 0

	d.UsesMemAccess = false
	d.UsesIDecode = false
	d.unsyncInfo = common.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) resetDecoder() {
	d.currState = dcdNoSync
	d.payloadSize = 0
	d.payloadUsed = 0
	d.payloadOddNibble = false
	d.outputElem.Init()
	d.swtPacketInfo = ocsd.SWTInfo{}
	d.resetPayloadBuffer()
}

func (d *PktDecode) resetPayloadBuffer() {
	d.payloadBuffer = make([]byte, d.numPktCorrelation*8)
}

func (d *PktDecode) decodePacket() (resp ocsd.DatapathResp, done bool) {
	resp = ocsd.RespCont
	sendPacket := false
	done = true
	d.outputElem.SetType(ocsd.GenElemSWTrace)
	d.clearSWTPerPcktInfo()

	switch d.CurrPacketIn.Type {
	case PktBadSequence, PktReserved:
		resp = ocsd.RespFatalInvalidData
		d.unsyncInfo = common.UnsyncBadPacket
		fallthrough
	case PktNotSync:
		d.resetDecoder()
	case PktVersion:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
	case PktAsync, PktIncompleteEOT:
		// no action required
	case PktNull:
		if d.CurrPacketIn.IsTSPkt() {
			sendPacket = true
		}
	case PktFreq:
		d.swtPacketInfo.SetFrequency(true)
		sendPacket = d.updatePayload()
	case PktTrig:
		d.swtPacketInfo.SetTriggerEvent(true)
		sendPacket = d.updatePayload()
	case PktGErr:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetGlobalErr(true)
		d.swtPacketInfo.SetIDValid(false)
		sendPacket = d.updatePayload()
	case PktMErr:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetMasterErr(true)
		sendPacket = d.updatePayload()
	case PktM8:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetIDValid(true)
	case PktC8, PktC16:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
	case PktFlag:
		d.swtPacketInfo.SetMarkerPacket(true)
		sendPacket = true
	case PktD4, PktD8, PktD16, PktD32, PktD64:
		sendPacket = d.updatePayload()
	}

	if sendPacket {
		if d.CurrPacketIn.IsTSPkt() {
			d.outputElem.SetTS(d.CurrPacketIn.Timestamp, true)
			d.swtPacketInfo.SetHasTimestamp(true)
		}
		d.outputElem.SetSWTInfo(d.swtPacketInfo)
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
	}

	return resp, done
}

func (d *PktDecode) clearSWTPerPcktInfo() {
	d.swtPacketInfo.FlagBits &= ocsd.SwtIDValidMask
}

func (d *PktDecode) updatePayload() bool {
	d.swtPacketInfo.SetPayloadNumPackets(1)

	switch d.CurrPacketIn.Type {
	case PktD4:
		d.swtPacketInfo.SetPayloadPktBitsize(4)
		d.payloadBuffer[0] = d.CurrPacketIn.Payload.D8
	case PktD8, PktTrig, PktGErr, PktMErr:
		d.swtPacketInfo.SetPayloadPktBitsize(8)
		d.payloadBuffer[0] = d.CurrPacketIn.Payload.D8
	case PktD16:
		d.swtPacketInfo.SetPayloadPktBitsize(16)
		binary.LittleEndian.PutUint16(d.payloadBuffer, d.CurrPacketIn.Payload.D16)
	case PktD32, PktFreq:
		d.swtPacketInfo.SetPayloadPktBitsize(32)
		binary.LittleEndian.PutUint32(d.payloadBuffer, d.CurrPacketIn.Payload.D32)
	case PktD64:
		d.swtPacketInfo.SetPayloadPktBitsize(64)
		binary.LittleEndian.PutUint64(d.payloadBuffer, d.CurrPacketIn.Payload.D64)
	}

	d.outputElem.SetExtendedDataPtr(d.payloadBuffer)
	if d.CurrPacketIn.IsMarkerPkt() {
		d.swtPacketInfo.SetMarkerPacket(true)
	}
	return true
}
