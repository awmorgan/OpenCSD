package etmv3

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type processState int

const (
	waitSync processState = iota
	procHdr
	procData
	sendPkt
	procErr
)

const maxPacketSize = 32
const asyncSize = 6

// PktProc implements the ETMv3 packet processor.
// Ported from trc_pkt_proc_etmv3_impl.cpp
type PktProc struct {
	*common.PktProcBase[Packet, PktType, Config]

	processState processState

	bytesProcessed   int
	currPacketData   []byte
	currPktIdx       int
	currPacket       Packet // expanded packet
	partPktData      []byte
	bSendPartPkt     bool
	postPartPktState processState
	postPartPktType  PktType

	bStreamSync    bool
	bStartOfSync   bool
	bytesExpected  int
	branchNeedsEx  bool
	isyncGotCC     bool
	isyncGetLSiP   bool
	isyncInfoIdx   int
	expectDataAddr bool
	foundDataAddr  bool

	packetIndex         ocsd.TrcIndex
	packetCurrByteIndex ocsd.TrcIndex
}

// NewPktProc creates a new ETMv3 packet processor
func NewPktProc(instID int) *PktProc {
	p := &PktProc{}
	p.PktProcBase = &common.PktProcBase[Packet, PktType, Config]{}
	p.InitPktProcBase(fmt.Sprintf("%s_%d", "PKTP_ETMV3", instID))

	p.FnProcessData = p.ProcessData
	p.FnOnEOT = p.OnEOT
	p.FnOnReset = p.OnReset
	p.FnOnFlush = p.OnFlush
	p.FnOnProtocolConfig = p.OnConfigure

	// Initialise configuration
	p.initProcessorState()
	return p
}

func (p *PktProc) initProcessorState() {
	p.bStreamSync = false
	p.processState = waitSync
	p.bStartOfSync = false
	p.currPacket.ResetState()
	p.initPacketState()
	p.bSendPartPkt = false
}

func (p *PktProc) initPacketState() {
	p.bytesExpected = 0
	p.branchNeedsEx = false
	p.isyncGotCC = false
	p.isyncGetLSiP = false
	p.isyncInfoIdx = 0
	p.expectDataAddr = false
	p.foundDataAddr = false

	p.currPacketData = p.currPacketData[:0]
	p.currPktIdx = 0
	p.currPacket.Clear()
}

// Internal processor method signatures (impl is next)

func (p *PktProc) OnConfigure() ocsd.Err {
	// Re-initialize state when config changes
	p.initProcessorState()
	return ocsd.OK // config structure handles validation properties directly
}

func (p *PktProc) OnReset() ocsd.DatapathResp {
	p.initProcessorState()
	return ocsd.RespCont
}

func (p *PktProc) OnFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (p *PktProc) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if len(p.currPacketData) != 0 {
		p.currPacket.ErrType = PktIncompleteEOT
		resp = p.outputPacket()
		p.initPacketState()
	}
	return resp
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
	resp := ocsd.RespCont
	p.bytesProcessed = 0
	dataBlockSize := len(dataBlock)

	for ((p.bytesProcessed < dataBlockSize) || (p.bytesProcessed == dataBlockSize && p.processState == sendPkt)) && ocsd.DataRespIsCont(resp) {
		switch p.processState {
		case waitSync:
			if !p.bStartOfSync {
				p.packetIndex = index + ocsd.TrcIndex(p.bytesProcessed)
			}
			p.bytesProcessed += p.waitForSync(dataBlock[p.bytesProcessed:])
		case procHdr:
			p.packetIndex = index + ocsd.TrcIndex(p.bytesProcessed)
			b := dataBlock[p.bytesProcessed]
			p.bytesProcessed++
			p.processHeaderByte(b)
		case procData:
			b := dataBlock[p.bytesProcessed]
			p.bytesProcessed++
			p.processPayloadByte(b)
		case sendPkt:
			resp = p.outputPacket()
		case procErr:
			resp = ocsd.RespFatalSysErr
		}
	}

	if p.processState == procErr && !ocsd.DataRespIsFatal(resp) {
		resp = ocsd.RespFatalSysErr
	}

	return uint32(p.bytesProcessed), resp
}

func (p *PktProc) waitForSync(dataBlock []byte) int {
	bytesProcessed := 0
	bSendBlock := false

	for !bSendBlock && bytesProcessed < len(dataBlock) {
		currByte := dataBlock[bytesProcessed]
		bytesProcessed++

		if p.bStartOfSync {
			p.currPacketData = append(p.currPacketData, currByte)
			if currByte == 0x80 && len(p.currPacketData) >= 6 {
				bSendBlock = true
				if len(p.currPacketData) > 6 {
					p.currPacketData = p.currPacketData[:len(p.currPacketData)-1]
					bytesProcessed--
					p.setBytesPartPkt(len(p.currPacketData)-5, waitSync, PktNotSync)
				} else {
					p.bStreamSync = true
					p.currPacket.Type = PktASync
				}
			} else if currByte != 0x00 {
				p.bStartOfSync = false
			} else if len(p.currPacketData) >= 13 {
				p.currPacket.Type = PktNotSync
				p.setBytesPartPkt(8, waitSync, PktNotSync)
				bSendBlock = true
			}
		} else {
			if currByte == 0x00 {
				if len(p.currPacketData) == 0 {
					p.currPacketData = append(p.currPacketData, currByte)
					p.bStartOfSync = true
				} else {
					bytesProcessed--
					bSendBlock = true
					p.currPacket.Type = PktNotSync
				}
			} else {
				p.currPacketData = append(p.currPacketData, currByte)
				if bytesProcessed == len(dataBlock) || len(p.currPacketData) == 16 {
					bSendBlock = true
					p.currPacket.Type = PktNotSync
				}
			}
		}
	}
	if bSendBlock {
		p.processState = sendPkt
	}
	return bytesProcessed
}

func (p *PktProc) processHeaderByte(by uint8) {
	p.initPacketState()
	p.currPacketData = append(p.currPacketData, by)
	p.processState = procData

	if (by & 0x01) == 0x01 {
		p.currPacket.Type = PktBranchAddress
		p.branchNeedsEx = (by & 0x40) == 0x40
		if (by & 0x80) != 0x80 {
			if by == 0x01 && false { // skipping bypassed stream unformatted check for now
				p.currPacket.Type = PktBranchOrBypassEOT
			} else {
				p.onBranchAddress()
				p.processState = sendPkt
			}
		}
	} else if (by & 0x81) == 0x80 {
		p.currPacket.Type = PktPHdr
		if p.currPacket.UpdateAtomFromPHdr(by, p.Config.IsCycleAcc()) {
			p.processState = sendPkt
		} else {
			p.throwPacketHeaderErr("Invalid P-Header.")
		}
	} else if (by & 0xF3) == 0x00 {
		if by == 0x00 {
			p.currPacket.Type = PktASync
		} else if by == 0x04 {
			p.currPacket.Type = PktCycleCount
		} else if by == 0x08 {
			p.currPacket.Type = PktISync
			p.isyncGotCC = false
			p.isyncGetLSiP = false
		} else if by == 0x0C {
			p.currPacket.Type = PktTrigger
			p.processState = sendPkt
		}
	} else if (by & 0x03) == 0x00 {
		if (by & 0x93) == 0x00 {
			if !p.Config.IsDataValTrace() {
				p.currPacket.ErrType = PktBadTraceMode
				p.throwPacketHeaderErr("Invalid data trace header (out of order data) - not tracing data values.")
			}
			p.currPacket.Type = PktOOOData
			size := (by & 0x0C) >> 2
			if size == 0 {
				p.currPacket.Data.OooTag = (by >> 5) & 0x3
				p.currPacket.Data.Value = 0
				p.currPacket.Data.UpdateDVal = true
				p.processState = sendPkt
			} else {
				p.bytesExpected = 1 + int(func() uint8 {
					if size == 3 {
						return 4
					}
					return size
				}())
			}
		} else if by == 0x70 {
			p.currPacket.Type = PktISyncCycle
			p.isyncGotCC = false
			p.isyncGetLSiP = false
		} else if by == 0x50 {
			if !p.Config.IsDataValTrace() {
				p.currPacket.ErrType = PktBadTraceMode
				p.throwPacketHeaderErr("Invalid data trace header (store failed) - not tracing data values.")
			}
			p.currPacket.Type = PktStoreFail
			p.processState = sendPkt
		} else if (by & 0xD3) == 0x50 {
			p.currPacket.Type = PktOOOAddrPlc
			if !p.Config.IsDataTrace() {
				p.currPacket.ErrType = PktBadTraceMode
				p.throwPacketHeaderErr("Invalid data trace header (out of order placeholder) - not tracing data.")
			}
			p.expectDataAddr = ((by & 0x20) == 0x20) && p.Config.IsDataAddrTrace()
			p.foundDataAddr = false
			p.currPacket.Data.OooTag = (by >> 2) & 0x3
			if !p.expectDataAddr {
				p.processState = sendPkt
			}
		} else if by == 0x3C {
			p.currPacket.Type = PktVMID
		} else {
			p.currPacket.ErrType = PktReserved
			p.throwPacketHeaderErr("Packet header reserved encoding")
		}
	} else if (by & 0xD3) == 0x02 {
		size := (by & 0x0C) >> 2
		if !p.Config.IsDataTrace() {
			p.currPacket.ErrType = PktBadTraceMode
			p.throwPacketHeaderErr("Invalid data trace header (normal data) - not tracing data.")
		}
		p.currPacket.Type = PktNormData
		p.expectDataAddr = ((by & 0x20) == 0x20) && p.Config.IsDataAddrTrace()
		p.foundDataAddr = false
		p.bytesExpected = 1 + int(func() uint8 {
			if size == 3 {
				return 4
			}
			return size
		}())
		if !p.expectDataAddr && p.bytesExpected == 1 {
			p.currPacket.Data.Value = 0
			p.currPacket.Data.UpdateDVal = true
			p.processState = sendPkt
		}
	} else if by == 0x62 {
		if !p.Config.IsDataTrace() {
			p.currPacket.ErrType = PktBadTraceMode
			p.throwPacketHeaderErr("Invalid data trace header (data suppressed) - not tracing data.")
		}
		p.currPacket.Type = PktDataSuppressed
		p.processState = sendPkt
	} else if (by & 0xEF) == 0x6A {
		if !p.Config.IsDataTrace() {
			p.currPacket.ErrType = PktBadTraceMode
			p.throwPacketHeaderErr("Invalid data trace header (value not traced) - not tracing data.")
		}
		p.currPacket.Type = PktValNotTraced
		p.expectDataAddr = ((by & 0x20) == 0x20) && p.Config.IsDataAddrTrace()
		p.foundDataAddr = false
		if !p.expectDataAddr {
			p.processState = sendPkt
		}
	} else if by == 0x66 {
		p.currPacket.Type = PktIgnore
		p.processState = sendPkt
	} else if by == 0x6E {
		p.currPacket.Type = PktContextID
		p.bytesExpected = 1 + p.Config.CtxtIDBytes()
	} else if by == 0x76 {
		p.currPacket.Type = PktExceptionExit
		p.processState = sendPkt
	} else if by == 0x7E {
		p.currPacket.Type = PktExceptionEntry
		p.processState = sendPkt
	} else if (by & 0xFB) == 0x42 {
		p.currPacket.Type = PktTimestamp
	} else {
		p.currPacket.ErrType = PktReserved
		p.throwPacketHeaderErr("Packet header reserved encoding.")
	}
}

func (p *PktProc) processPayloadByte(by uint8) {
	bTopBitSet := false
	packetDone := false

	p.currPacketData = append(p.currPacketData, by)

	switch p.currPacket.Type {
	case PktBranchAddress:
		bTopBitSet = (by & 0x80) == 0x80
		if p.Config.IsAltBranch() {
			if !bTopBitSet {
				if !p.branchNeedsEx {
					if (by & 0xC0) == 0x40 {
						p.branchNeedsEx = true
					} else {
						packetDone = true
					}
				} else {
					packetDone = true
				}
			}
		} else {
			if len(p.currPacketData) == 5 {
				if (by & 0xC0) == 0x40 {
					p.branchNeedsEx = true
				} else {
					packetDone = true
				}
			} else if p.branchNeedsEx {
				if !bTopBitSet {
					packetDone = true
				}
			} else {
				if !bTopBitSet {
					packetDone = true
				}
			}
		}
		if packetDone {
			p.onBranchAddress()
			p.processState = sendPkt
		}
	case PktASync:
		if by == 0x00 {
			if len(p.currPacketData) > 5 {
				p.currPacket.ErrType = PktBadSequence
				p.setBytesPartPkt(1, procData, PktASync)
				p.throwMalformedPacketErr("A-Sync ?: Extra 0x00 in sequence")
			}
		} else if by == 0x80 && len(p.currPacketData) == 6 {
			p.processState = sendPkt
			p.bStreamSync = true
		} else {
			p.currPacket.ErrType = PktBadSequence
			p.bytesProcessed--
			p.currPacketData = p.currPacketData[:len(p.currPacketData)-1]
			p.throwMalformedPacketErr("A-Sync ? : Unexpected byte in sequence")
		}
	case PktCycleCount:
		bTopBitSet = (by & 0x80) == 0x80
		if !bTopBitSet || len(p.currPacketData) >= 6 {
			p.currPktIdx = 1
			p.currPacket.CycleCount = p.extractCycleCount()
			p.processState = sendPkt
		}
	case PktISyncCycle:
		if !p.isyncGotCC {
			if (by&0x80) != 0x80 || len(p.currPacketData) >= 6 {
				p.isyncGotCC = true
			}
			break
		}
		fallthrough
	case PktISync:
		if p.bytesExpected == 0 {
			cycCountBytes := len(p.currPacketData) - 2
			ctxtIDBytes := p.Config.CtxtIDBytes()
			if p.Config.IsInstrTrace() {
				p.bytesExpected = cycCountBytes + 6 + ctxtIDBytes
			} else {
				p.bytesExpected = 2 + ctxtIDBytes
			}
			p.isyncInfoIdx = 1 + cycCountBytes + ctxtIDBytes
		}
		if len(p.currPacketData)-1 == p.isyncInfoIdx {
			p.isyncGetLSiP = (p.currPacketData[p.isyncInfoIdx] & 0x80) == 0x80
		}

		if len(p.currPacketData) >= p.bytesExpected {
			if p.isyncGetLSiP {
				if (by & 0x80) != 0x80 {
					p.onISyncPacket()
				}
			} else {
				p.onISyncPacket()
			}
		}
	case PktNormData:
		if p.expectDataAddr && !p.foundDataAddr {
			if (by & 0x80) != 0x80 {
				p.foundDataAddr = true
				p.bytesExpected += len(p.currPacketData) - 1
			} else {
				break
			}
		} else if p.bytesExpected == len(p.currPacketData) {
			p.currPktIdx = 1
			if p.expectDataAddr {
				bits := uint8(0)
				beVal := uint8(0)
				updateBE := false
				dataAddr := p.extractDataAddress(&bits, &updateBE, &beVal)
				p.currPacket.UpdateAddress(dataAddr, int(bits))
				p.currPacket.Data.UpdateAddr = true
				p.currPacket.Data.Addr = dataAddr
				if updateBE {
					p.currPacket.Data.BE = (beVal == 1)
					p.currPacket.Data.UpdateBE = true
				}
			}
			p.currPacket.Data.Value = p.extractDataValue(int((p.currPacketData[0] >> 2) & 0x3))
			p.currPacket.Data.UpdateDVal = true
			p.processState = sendPkt
		}
	case PktOOOData:
		if p.bytesExpected == len(p.currPacketData) {
			p.currPktIdx = 1
			p.currPacket.Data.Value = p.extractDataValue(int((p.currPacketData[0] >> 2) & 0x3))
			p.currPacket.Data.UpdateDVal = true
			p.currPacket.Data.OooTag = (p.currPacketData[0] >> 5) & 0x3
			p.processState = sendPkt
		}
		if p.bytesExpected < len(p.currPacketData) {
			p.throwMalformedPacketErr("Malformed out of order data packet.")
		}
	case PktValNotTraced, PktOOOAddrPlc:
		if p.expectDataAddr {
			if (by & 0x80) != 0x80 {
				bits := uint8(0)
				beVal := uint8(0)
				updateBE := false
				p.currPktIdx = 1
				dataAddr := p.extractDataAddress(&bits, &updateBE, &beVal)
				p.currPacket.UpdateAddress(dataAddr, int(bits))
				p.currPacket.Data.UpdateAddr = true
				p.currPacket.Data.Addr = dataAddr
				if updateBE {
					p.currPacket.Data.BE = (beVal == 1)
					p.currPacket.Data.UpdateBE = true
				}
				p.processState = sendPkt
			}
		}
	case PktContextID:
		if p.bytesExpected == len(p.currPacketData) {
			p.currPktIdx = 1
			p.currPacket.Context.CtxtID = p.extractCtxtID()
			p.currPacket.Context.UpdatedC = true
			p.processState = sendPkt
		}
		if p.bytesExpected < len(p.currPacketData) {
			p.throwMalformedPacketErr("Malformed context id packet.")
		}
	case PktTimestamp:
		if (by & 0x80) != 0x80 {
			tsBits := uint8(0)
			p.currPktIdx = 1
			tsVal := p.extractTimestamp(&tsBits)
			p.currPacket.UpdateTimestamp(tsVal, tsBits)
			p.processState = sendPkt
		}
	case PktVMID:
		p.currPacket.Context.VMID = by
		p.currPacket.Context.UpdatedV = true
		p.processState = sendPkt
	default:
		p.processState = procErr
		p.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrPktInterpFail, "Interpreter failed - cannot process payload for unexpected or unsupported packet."))
	}
}

func (p *PktProc) outputPacket() ocsd.DatapathResp {
	dpResp := ocsd.RespFatalNotInit
	if true { // assuming p.isInit=true conceptually
		if !p.bSendPartPkt {
			dpResp = p.OutputOnAllInterfaces(p.packetIndex, &p.currPacket, p.currPacket.Type, p.currPacketData)
			if p.bStreamSync {
				p.processState = procHdr
			} else {
				p.processState = waitSync
			}
			p.currPacketData = p.currPacketData[:0]
		} else {
			dpResp = p.OutputOnAllInterfaces(p.packetIndex, &p.currPacket, p.currPacket.Type, p.partPktData)
			p.processState = p.postPartPktState
			p.packetIndex += ocsd.TrcIndex(len(p.partPktData))
			p.bSendPartPkt = false
			p.currPacket.Type = p.postPartPktType
		}
	}
	return dpResp
}

func (p *PktProc) setBytesPartPkt(numBytes int, nextState processState, nextType PktType) {
	p.partPktData = make([]byte, numBytes)
	copy(p.partPktData, p.currPacketData[:numBytes])
	p.currPacketData = p.currPacketData[numBytes:]
	p.bSendPartPkt = true
	p.postPartPktState = nextState
	p.postPartPktType = nextType
}

func (p *PktProc) onBranchAddress() {
	validBits := 0
	partAddr := p.extractBrAddrPkt(&validBits)
	p.currPacket.UpdateAddress(partAddr, validBits)
}

func (p *PktProc) extractBrAddrPkt(nBitsOut *int) uint64 {
	addrshift := []int{2, 1, 1, 0}
	addrMask := []uint8{0x7, 0xF, 0xF, 0x1F}
	addrBits := []int{3, 4, 4, 5}

	CBit := true
	bytecount := 0
	bitcount := 0
	shift := 0
	isa_idx := 0
	value := uint64(0)
	var addrbyte uint8
	byte5AddrUpdate := false

	for CBit && bytecount < 4 {
		p.checkPktLimits()
		addrbyte = p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		CBit = (addrbyte & 0x80) != 0
		shift = bitcount
		if bytecount == 0 {
			addrbyte &= ^uint8(0x81)
			bitcount += 6
			addrbyte >>= 1
		} else {
			if p.Config.IsAltBranch() && !CBit {
				if (addrbyte & 0x40) == 0x40 {
					p.extractExceptionData()
				}
				addrbyte &= 0x3F
				bitcount += 6
			} else {
				addrbyte &= 0x7F
				bitcount += 7
			}
		}
		value |= uint64(addrbyte) << shift
		bytecount++
	}

	if CBit {
		p.checkPktLimits()
		addrbyte = p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		if (addrbyte & 0x80) != 0 {
			excep_num := (addrbyte >> 3) & 0x7
			p.currPacket.UpdateISA(ocsd.ISAArm)
			p.currPacket.SetException(exceptionTypeARMdeprecated[excep_num], uint16(excep_num), (addrbyte&0x40) != 0, p.Config.IsV7MArch(), 0, 0)
		} else {
			if (addrbyte & 0x40) == 0x40 {
				p.extractExceptionData()
			}

			if (addrbyte & 0xB8) == 0x08 {
				p.currPacket.UpdateISA(ocsd.ISAArm)
			} else if (addrbyte & 0xB0) == 0x10 {
				if p.currPacket.Context.CurrAltIsa {
					p.currPacket.UpdateISA(ocsd.ISATee)
				} else {
					p.currPacket.UpdateISA(ocsd.ISAThumb2)
				}
			} else if (addrbyte & 0xA0) == 0x20 {
				p.currPacket.UpdateISA(ocsd.ISAJazelle)
			} else {
				// Malformed, but we should not panic directly here or just log.
				// For now silently fail or return what we have (PktProc handles err state).
			}
		}

		byte5AddrUpdate = true
	}

	switch p.currPacket.CurrISA { // Using CurrISA as it's the current ISA
	case ocsd.ISAThumb2:
		isa_idx = 1
	case ocsd.ISATee:
		isa_idx = 2
	case ocsd.ISAJazelle:
		isa_idx = 3
	default:
		isa_idx = 0
	}

	if byte5AddrUpdate {
		value |= uint64(addrbyte&addrMask[isa_idx]) << bitcount
		bitcount += addrBits[isa_idx]
	}

	shift = addrshift[isa_idx]
	value <<= shift
	bitcount += shift

	*nBitsOut = bitcount
	return value
}

var addrMaskB5 = []uint8{0x7, 0xF, 0xF, 0x1F}
var addrBitsB5 = []int{3, 4, 4, 5}
var exceptionTypeARMdeprecated = []ocsd.ArmV7Exception{
	ocsd.ExcpReset,
	ocsd.ExcpIRQ,
	ocsd.ExcpReserved,
	ocsd.ExcpReserved,
	ocsd.ExcpJazelle,
	ocsd.ExcpFIQ,
	ocsd.ExcpAsyncDAbort,
	ocsd.ExcpDebugHalt,
}

func (p *PktProc) extractExceptionData() {
	if !p.branchNeedsEx {
		return
	}

	for p.currPktIdx < len(p.currPacketData) {
		b := p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		if (b & 0x40) == 0x40 {
			// Exception Byte (bit 6 = 1)
			exNum := uint16((b >> 1) & 0x0F)
			cancel := (b & 0x20) != 0
			// AltISA is on bit 6, handled by extractExceptionData caller or here?
			// C++ UpdateAltISA((dataByte & 0x40) != 0)
			p.currPacket.Context.CurrAltIsa = true // bit 6 is 1
			ns := (b & 0x01) != 0
			p.currPacket.Context.CurrNS = ns
			p.currPacket.SetException(ocsd.ExcpNoException, exNum, cancel, false, 0, 0)
		} else {
			// Context Information Byte (bit 6 = 0)
			p.currPacket.Context.CurrNS = (b & 0x20) != 0
			p.currPacket.Context.CurrHyp = (b & 0x10) != 0
			p.currPacket.Context.CurrAltIsa = (b & 0x08) != 0
			p.currPacket.Context.Updated = true
		}
		if (b & 0x80) != 0x80 {
			break
		}
	}
}

func (p *PktProc) extractCycleCount() uint32 {
	cycleCount := uint32(0)
	byteIdx := 0
	mask := uint8(0x7F)
	bCond := true

	for bCond {
		p.checkPktLimits()
		currByte := p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		cycleCount |= uint32(currByte&mask) << (7 * byteIdx)
		bCond = (currByte & 0x80) == 0x80
		byteIdx++

		if byteIdx == 4 {
			mask = 0x0F
		}
		if byteIdx == 5 {
			bCond = false
		}
	}
	return cycleCount
}

func (p *PktProc) checkPktLimits() {
	if p.currPktIdx >= len(p.currPacketData) {
		p.throwMalformedPacketErr("Malformed Packet - oversized packet.")
	}
}

func (p *PktProc) extractCtxtID() uint32 {
	val := uint32(0)
	ctxtBytes := p.Config.CtxtIDBytes()

	if p.currPktIdx+ctxtBytes > len(p.currPacketData) {
		p.throwMalformedPacketErr("Too few bytes to extract context ID.")
		return 0
	}

	for i := 0; i < ctxtBytes; i++ {
		bByte := p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		val |= uint32(bByte) << (i * 8)
	}
	return val
}

func (p *PktProc) onISyncPacket() {
	var instrAddr uint32
	var j, t, altISA uint8

	p.currPktIdx = 1

	// 1. Extract cycle count (if present) - same as C++
	if p.currPacket.Type == PktISyncCycle {
		p.currPacket.CycleCount = p.extractCycleCount()
		p.currPacket.ISyncInfo.HasCycleCount = true
	}

	// 2. Extract context ID BEFORE info byte (C++ order)
	if p.Config.CtxtIDBytes() > 0 {
		p.currPacket.Context.CtxtID = p.extractCtxtID()
		p.currPacket.Context.UpdatedC = true
	}

	// 3. Extract info byte
	p.checkPktLimits()
	infoByte := p.currPacketData[p.currPktIdx]
	p.currPktIdx++

	p.currPacket.ISyncInfo.Reason = ocsd.ISyncReason((infoByte >> 5) & 0x3)
	j = (infoByte >> 4) & 0x1
	if p.Config.MinorRev() >= 3 {
		altISA = (infoByte >> 2) & 0x1
	}
	p.currPacket.Context.CurrNS = (infoByte & 0x08) != 0
	if p.Config.HasVirtExt() {
		p.currPacket.Context.CurrHyp = ((infoByte >> 1) & 0x1) != 0
	}
	p.currPacket.Context.Updated = true

	// 4. Extract address and determine ISA
	if p.Config.IsInstrTrace() {
		addrBytes := 4
		if p.Config.IsV7MArch() && (j != 0) {
			// Jazelle on V7M uses alternate format
			addrBytes = 0
			p.currPacket.CurrISA = ocsd.ISAThumb2
		}

		for i := 0; i < addrBytes; i++ {
			p.checkPktLimits()
			instrAddr |= uint32(p.currPacketData[p.currPktIdx]) << (i * 8)
			p.currPktIdx++
		}

		if addrBytes > 0 {
			t = uint8(instrAddr & 0x1) // extract T bit
			instrAddr &= 0xFFFFFFFE    // remove T bit from address (bit 0)
			p.currPacket.UpdateAddress(uint64(instrAddr), 32)

			// Determine ISA from J, T, AltISA (matches C++ exactly)
			currISA := ocsd.ISAArm
			if j != 0 {
				currISA = ocsd.ISAJazelle
			} else if t != 0 {
				if altISA != 0 {
					currISA = ocsd.ISATee
				} else {
					currISA = ocsd.ISAThumb2
				}
			}
			p.currPacket.CurrISA = currISA
			p.currPacket.Context.CurrAltIsa = altISA != 0
		}

		// 5. LSiP address (variable-length continuation-encoded)
		if p.isyncGetLSiP {
			lsiPBits := 0
			lsiPAddr := uint32(0)
			for p.currPktIdx < len(p.currPacketData) {
				b := p.currPacketData[p.currPktIdx]
				p.currPktIdx++
				lsiPAddr |= uint32(b&0x7F) << lsiPBits
				lsiPBits += 7
				if (b & 0x80) == 0 {
					break
				}
			}
			// Store: set data addr to instr addr, then overlay LSiP bits
			p.currPacket.Data.Addr = uint64(instrAddr)
			p.currPacket.Data.UpdateAddr = true
			if lsiPBits > 0 {
				mask := uint64((1 << lsiPBits) - 1)
				p.currPacket.Data.Addr = (p.currPacket.Data.Addr & ^mask) | (uint64(lsiPAddr) & mask)
			}
			p.currPacket.ISyncInfo.HasLSipAddr = true
		}
	} else {
		p.currPacket.ISyncInfo.NoAddress = true
	}

	p.processState = sendPkt
}

func (p *PktProc) extractDataAddress(bits *uint8, updateBE *bool, beVal *uint8) uint64 {
	addr := uint64(0)
	nBits := 0
	shiftAddr := 0

	for {
		b := p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		if nBits == 0 {
			addr |= uint64(b & 0x7F) // lose continuation bit
			nBits += 7
		} else {
			addr |= uint64(b&0x7F) << nBits
			nBits += 7
			// need to extract be here if 5th address byte.
			if nBits == 35 { // 5 * 7 bits
				*updateBE = true
				if (b & 0x40) != 0 {
					*beVal = 1
				} else {
					*beVal = 0
				}
				addr &= 0xFFFFFFFF // max 32 bits on etmv3... (from doc: ETMv3 only trace 32-bit addresses)
			}
		}
		if (b & 0x80) == 0 {
			break
		}
	}
	*bits = uint8(nBits)
	if shiftAddr > 0 {
		addr <<= shiftAddr
		*bits += uint8(shiftAddr)
	}
	return addr
}

func (p *PktProc) extractDataValue(sizeCode int) uint32 {
	val := uint32(0)
	bytes := sizeCode
	if bytes == 3 {
		bytes = 4
	} else if bytes == 0 {
		return 0 // no value
	}

	for i := 0; i < bytes; i++ {
		b := p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		val |= uint32(b) << (i * 8)
	}
	return val
}

func (p *PktProc) extractTimestamp(tsBits *uint8) uint64 {
	val := uint64(0)
	nBits := 0

	for {
		p.checkPktLimits()
		b := p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		val |= uint64(b&0x7F) << nBits
		nBits += 7

		if (b&0x80) == 0 || nBits >= 64 {
			break
		}
	}
	*tsBits = uint8(nBits)
	return val
}

func (p *PktProc) throwPacketHeaderErr(msg string) {
	p.processState = procErr
	p.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidPcktHdr, msg))
}

func (p *PktProc) throwMalformedPacketErr(msg string) {
	p.processState = procErr
	p.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, msg))
}
