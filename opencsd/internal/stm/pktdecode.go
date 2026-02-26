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
	common.PktDecodeBase[Packet, Config]

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
	outputElem  common.TraceElement
}

// NewPktDecode creates a new STM packet decoder.
func NewPktDecode(instIDNum int) *PktDecode {
	d := &PktDecode{}
	d.InitPktDecodeBase(fmt.Sprintf("%s_%d", "DCD_STM", instIDNum))

	d.FnProcessPacket = d.processPacket
	d.FnOnEOT = d.onEOT
	d.FnOnReset = d.onReset
	d.FnOnFlush = d.onFlush
	d.FnOnProtocolConfig = d.onProtocolConfig
	d.FnGetTraceID = d.getTraceID

	d.initDecoder()
	return d
}

func (d *PktDecode) processPacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	bPktDone := false

	d.decodePass1 = true

	for !bPktDone {
		switch d.currState {
		case dcdNoSync:
			d.outputElem.SetType(common.GenElemNoSync)
			d.outputElem.SetUnSyncEOTReason(d.unsyncInfo)
			resp = d.OutputTraceElement(&d.outputElem)
			d.currState = dcdWaitSync
		case dcdWaitSync:
			if d.CurrPacketIn.Type == PktAsync {
				d.currState = dcdDecodePkts
			}
			bPktDone = true
		case dcdDecodePkts:
			resp = d.decodePacket(&bPktDone)
		}
	}
	return resp
}

func (d *PktDecode) onEOT() ocsd.DatapathResp {
	d.outputElem.SetType(common.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(common.UnsyncEOT)
	return d.OutputTraceElement(&d.outputElem)
}

func (d *PktDecode) onReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) onFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (d *PktDecode) onProtocolConfig() ocsd.Err {
	if d.Config == nil {
		return ocsd.ErrNotInit
	}
	d.csID = d.Config.TraceID()
	return ocsd.OK
}

func (d *PktDecode) getTraceID() uint8 {
	return d.csID
}

func (d *PktDecode) initDecoder() {
	d.numPktCorrelation = 1
	d.csID = 0

	d.SetUsesMemAccess(false)
	d.SetUsesIDecode(false)
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
	d.initPayloadBuffer()
}

func (d *PktDecode) initPayloadBuffer() {
	d.payloadBuffer = make([]byte, d.numPktCorrelation*8)
}

func (d *PktDecode) decodePacket(bPktDone *bool) ocsd.DatapathResp {
	resp := ocsd.RespCont
	bSendPacket := false

	*bPktDone = true
	d.outputElem.SetType(common.GenElemSWTrace)
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
			bSendPacket = true
		}
	case PktFreq:
		d.swtPacketInfo.SetFrequency(true)
		d.updatePayload(&bSendPacket)
	case PktTrig:
		d.swtPacketInfo.SetTriggerEvent(true)
		d.updatePayload(&bSendPacket)
	case PktGErr:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetGlobalErr(true)
		d.swtPacketInfo.SetIDValid(false)
		d.updatePayload(&bSendPacket)
	case PktMErr:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetMasterErr(true)
		d.updatePayload(&bSendPacket)
	case PktM8:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetIDValid(true)
	case PktC8, PktC16:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
	case PktFlag:
		d.swtPacketInfo.SetMarkerPacket(true)
		bSendPacket = true
	case PktD4, PktD8, PktD16, PktD32, PktD64:
		d.updatePayload(&bSendPacket)
	}

	if bSendPacket {
		if d.CurrPacketIn.IsTSPkt() {
			d.outputElem.SetTS(d.CurrPacketIn.Timestamp, true)
			d.swtPacketInfo.SetHasTimestamp(true)
		}
		d.outputElem.SetSWTInfo(d.swtPacketInfo)
		resp = d.OutputTraceElement(&d.outputElem)
	}

	return resp
}

func (d *PktDecode) clearSWTPerPcktInfo() {
	d.swtPacketInfo.FlagBits &= ocsd.SwtIDValidMask
}

func (d *PktDecode) updatePayload(bSendPacket *bool) {
	*bSendPacket = true
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
}
