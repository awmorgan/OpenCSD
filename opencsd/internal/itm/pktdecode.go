package itm

import (
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
	common.PktDecodeBase[Packet, Config]

	currState decoderState

	itmInfo        common.SWTItmInfo
	localTSCount   uint64
	globalTS       uint64
	stimPage       uint8
	bNeedGTS2      bool
	bPrevOverflow  bool
	bGTSFreqChange bool

	unsyncInfo common.UnsyncInfo
	csID       uint8
	outputElem common.TraceElement
}

// NewPktDecode creates a new ITM packet decoder.
func NewPktDecode(instID int) *PktDecode {
	d := &PktDecode{}
	d.InitPktDecodeBase("DCD_ITM")
	d.FnProcessPacket = d.processPacket
	d.FnOnEOT = d.onEOT
	d.FnOnReset = d.onReset
	d.FnOnFlush = d.onFlush
	d.FnOnProtocolConfig = d.onProtocolConfig
	d.FnGetTraceID = d.getTraceID

	d.initDecoder()
	return d
}

// SetProtocolConfig sets the ITM hardware configuration.
func (d *PktDecode) SetProtocolConfig(cfg *Config) ocsd.Err {
	return d.PktDecodeBase.SetProtocolConfig(cfg)
}

func (d *PktDecode) processPacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	bPktDone := false

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
			resp = d.decodePacket()
			bPktDone = true
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
	// d.resetDecoder() // C++ has it commented out
	return ocsd.RespCont
}

func (d *PktDecode) onFlush() ocsd.DatapathResp {
	// don't currently save unsent packets so nothing to flush
	return ocsd.RespCont
}

func (d *PktDecode) onProtocolConfig() ocsd.Err {
	if d.Config == nil {
		return ocsd.ErrNotInit
	}

	// static config - copy of CSID for easy reference
	d.csID = d.Config.TraceID()
	return ocsd.OK
}

func (d *PktDecode) getTraceID() uint8 {
	return d.csID
}

func (d *PktDecode) initDecoder() {
	d.csID = 0

	// base decoder state - ITM requires no memory and instruction decode.
	d.SetUsesMemAccess(false)
	d.SetUsesIDecode(false)
	d.unsyncInfo = common.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) resetDecoder() {
	d.outputElem.Init()
	d.currState = dcdNoSync

	d.localTSCount = 0
	d.globalTS = 0
	d.stimPage = 0
	d.bNeedGTS2 = true
	d.bPrevOverflow = false
	d.bGTSFreqChange = false
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

	bSendPacket := false
	srcID := d.CurrPacketIn.SrcID

	localTSTCTypes := []common.SWTItmType{
		common.TSSync,
		common.TSDelay,
		common.TSPKTDelay,
		common.TSPKTTSDelay,
	}

	d.itmInfo = common.SWTItmInfo{}

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
		d.itmInfo.PktType = common.DWTPayload
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value
		d.itmInfo.PayloadSrcID = srcID
		bSendPacket = true

	case PktSWIT:
		d.itmInfo.PktType = common.SWITPayload
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value
		srcID = (srcID & 0x1F) | (d.stimPage << 5)
		d.itmInfo.PayloadSrcID = srcID
		bSendPacket = true

	case PktExtension:
		if (srcID&0x80) == 0 && (srcID&0x1F) == 2 {
			d.stimPage = uint8(d.CurrPacketIn.Value)
		}

	case PktOverflow:
		d.localTSCount = 0
		d.bPrevOverflow = true

	case PktTSGlobal1:
		if !d.bNeedGTS2 {
			d.bNeedGTS2 = (srcID & 0x2) != 0
		}
		if !d.bGTSFreqChange {
			d.bGTSFreqChange = (srcID & 0x1) != 0
		}

		d.globalTS &= ^globalTSLowMask[d.CurrPacketIn.ValSz-1]
		d.globalTS |= uint64(d.CurrPacketIn.Value)

		if !d.bNeedGTS2 {
			d.itmInfo.PktType = common.TSGlobal
			d.outputElem.SetTS(d.globalTS, d.bGTSFreqChange)
			d.bGTSFreqChange = false
			bSendPacket = true
		}

	case PktTSGlobal2:
		d.itmInfo.PktType = common.TSGlobal
		d.globalTS &= ^globalTSHiMask
		d.globalTS |= (d.CurrPacketIn.GetExtValue() << 26)
		d.outputElem.SetTS(d.globalTS, d.bGTSFreqChange)
		d.bGTSFreqChange = false
		d.bNeedGTS2 = false
		bSendPacket = true

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
		bSendPacket = true
	}

	if bSendPacket {
		if d.bPrevOverflow {
			d.itmInfo.Overflow = 1
			d.bPrevOverflow = false
		}
		d.outputElem.SetType(common.GenElemITMTrace)
		d.outputElem.SetSWTITMInfo(d.itmInfo)
		resp = d.OutputTraceElement(&d.outputElem)
	}

	return resp
}
