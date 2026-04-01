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

// PktProc implements the ETMv3 packet processor.
// Ported from trc_pkt_proc_etmv3_impl.cpp
type PktProc struct {
	common.ProcBase[Packet]
	Config        *Config
	PktOutI       ocsd.PacketProcessor[Packet]
	PktRawMonI    ocsd.PacketMonitor[Packet]
	procErrReason error

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

	packetIndex ocsd.TrcIndex
}

// NewPktProc creates a new ETMv3 packet processor
func NewPktProc(cfg *Config) *PktProc {
	instID := 0
	if cfg != nil {
		instID = int(cfg.TraceID())
	}
	p := &PktProc{
		ProcBase: common.ProcBase[Packet]{
			Name: fmt.Sprintf("PKTP_ETMV3_%d", instID),
		},
	}
	p.ResetStats()
	p.resetProcessorState()
	if cfg != nil {
		_ = p.SetProtocolConfig(cfg)
	}
	return p
}

// SetPktOut attaches the downstream packet decoder.
func (p *PktProc) SetPktOut(out ocsd.PacketProcessor[Packet]) { p.PktOutI = out }

// PktOut returns the downstream packet processor.
func (p *PktProc) PktOut() ocsd.PacketProcessor[Packet] { return p.PktOutI }

// SetPktRawMonitor attaches a raw packet monitor.
func (p *PktProc) SetPktRawMonitor(mon ocsd.PacketMonitor[Packet]) { p.PktRawMonI = mon }

func (p *PktProc) outputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	if p.PktOutI != nil {
		resp, _ := p.PktOutI.PacketDataIn(ocsd.OpData, indexSOP, pkt)
		return resp
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
			resp, err = out.PacketDataIn(ocsd.OpEOT, 0, nil)
		}
		if rawMon := p.PktRawMonI; rawMon != nil {
			rawMon.RawPacketDataMon(ocsd.OpEOT, 0, nil, nil)
		}
	case ocsd.OpFlush:
		resp = p.OnFlush()
		if out := p.PktOutI; ocsd.DataRespIsCont(resp) && out != nil {
			resp, err = out.PacketDataIn(ocsd.OpFlush, 0, nil)
		}
	case ocsd.OpReset:
		if out := p.PktOutI; out != nil {
			resp, err = out.PacketDataIn(ocsd.OpReset, index, nil)
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

func (p *PktProc) resetProcessorState() {
	p.bStreamSync = false
	p.processState = waitSync
	p.bStartOfSync = false
	p.procErrReason = nil
	p.currPacket.ResetState()
	p.resetPacketState()
	p.bSendPartPkt = false
}

func (p *PktProc) resetPacketState() {
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

func (p *PktProc) SetProtocolConfig(config *Config) error {
	p.Config = config
	// Re-initialize state when config changes
	p.resetProcessorState()
	return nil // config structure handles validation properties directly
}

func (p *PktProc) OnReset() ocsd.DatapathResp {
	p.resetProcessorState()
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
		p.resetPacketState()
	}
	return resp
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
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
	if p.processState == procErr {
		err := p.procErrReason
		if err == nil {
			err = ocsd.ErrPktInterpFail
		}
		return uint32(p.bytesProcessed), resp, err
	}

	return uint32(p.bytesProcessed), resp, nil
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
	p.resetPacketState()
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
				if p.processState != procErr {
					p.processState = sendPkt
				}
			}
		}
	} else if (by & 0x81) == 0x80 {
		p.currPacket.Type = PktPHdr
		if p.currPacket.UpdateAtomFromPHdr(by, p.Config.CycleAcc()) {
			p.processState = sendPkt
		} else {
			p.throwPacketHeaderErr("Invalid P-Header.")
		}
	} else if (by & 0xF3) == 0x00 {
		switch by {
		case 0x00:
			p.currPacket.Type = PktASync
		case 0x04:
			p.currPacket.Type = PktCycleCount
		case 0x08:
			p.currPacket.Type = PktISync
			p.isyncGotCC = false
			p.isyncGetLSiP = false
		case 0x0C:
			p.currPacket.Type = PktTrigger
			p.processState = sendPkt
		}
	} else if (by & 0x03) == 0x00 {
		if (by & 0x93) == 0x00 {
			if !p.Config.DataValTrace() {
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
			if !p.Config.DataValTrace() {
				p.currPacket.ErrType = PktBadTraceMode
				p.throwPacketHeaderErr("Invalid data trace header (store failed) - not tracing data values.")
			}
			p.currPacket.Type = PktStoreFail
			p.processState = sendPkt
		} else if (by & 0xD3) == 0x50 {
			p.currPacket.Type = PktOOOAddrPlc
			if !p.Config.DataTrace() {
				p.currPacket.ErrType = PktBadTraceMode
				p.throwPacketHeaderErr("Invalid data trace header (out of order placeholder) - not tracing data.")
			}
			p.expectDataAddr = ((by & 0x20) == 0x20) && p.Config.DataAddrTrace()
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
		if !p.Config.DataTrace() {
			p.currPacket.ErrType = PktBadTraceMode
			p.throwPacketHeaderErr("Invalid data trace header (normal data) - not tracing data.")
		}
		p.currPacket.Type = PktNormData
		p.expectDataAddr = ((by & 0x20) == 0x20) && p.Config.DataAddrTrace()
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
		if !p.Config.DataTrace() {
			p.currPacket.ErrType = PktBadTraceMode
			p.throwPacketHeaderErr("Invalid data trace header (data suppressed) - not tracing data.")
		}
		p.currPacket.Type = PktDataSuppressed
		p.processState = sendPkt
	} else if (by & 0xEF) == 0x6A {
		if !p.Config.DataTrace() {
			p.currPacket.ErrType = PktBadTraceMode
			p.throwPacketHeaderErr("Invalid data trace header (value not traced) - not tracing data.")
		}
		p.currPacket.Type = PktValNotTraced
		p.expectDataAddr = ((by & 0x20) == 0x20) && p.Config.DataAddrTrace()
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
		if p.Config.AltBranch() {
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
			if p.processState != procErr {
				p.processState = sendPkt
			}
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
			if p.processState != procErr {
				p.processState = sendPkt
			}
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
			if p.Config.InstrTrace() {
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
				dataAddr, bits, updateBE, beVal := p.extractDataAddress()
				if p.processState == procErr {
					break
				}
				p.currPacket.UpdateAddress(dataAddr, int(bits))
				p.currPacket.Data.UpdateAddr = true
				p.currPacket.Data.Addr = dataAddr
				if updateBE {
					p.currPacket.Data.BE = (beVal == 1)
					p.currPacket.Data.UpdateBE = true
				}
			}
			p.currPacket.Data.Value = p.extractDataValue(int((p.currPacketData[0] >> 2) & 0x3))
			if p.processState == procErr {
				break
			}
			p.currPacket.Data.UpdateDVal = true
			p.processState = sendPkt
		}
	case PktOOOData:
		if p.bytesExpected == len(p.currPacketData) {
			p.currPktIdx = 1
			p.currPacket.Data.Value = p.extractDataValue(int((p.currPacketData[0] >> 2) & 0x3))
			if p.processState == procErr {
				break
			}
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
				p.currPktIdx = 1
				dataAddr, bits, updateBE, beVal := p.extractDataAddress()
				if p.processState == procErr {
					break
				}
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
			if p.processState == procErr {
				break
			}
			p.currPacket.Context.UpdatedC = true
			p.processState = sendPkt
		}
		if p.bytesExpected < len(p.currPacketData) {
			p.throwMalformedPacketErr("Malformed context id packet.")
		}
	case PktTimestamp:
		if (by & 0x80) != 0x80 {
			p.currPktIdx = 1
			tsVal, tsBits := p.extractTimestamp()
			if p.processState == procErr {
				break
			}
			p.currPacket.UpdateTimestamp(tsVal, tsBits)
			p.processState = sendPkt
		}
	case PktVMID:
		p.currPacket.Context.VMID = by
		p.currPacket.Context.UpdatedV = true
		p.processState = sendPkt
	default:
		p.processState = procErr
		p.procErrReason = fmt.Errorf("%w: interpreter failed: unsupported packet payload", ocsd.ErrPktInterpFail)
	}
}

func (p *PktProc) outputPacket() ocsd.DatapathResp {
	var dpResp ocsd.DatapathResp
	if true { // assuming p.isInit=true conceptually
		if !p.bSendPartPkt {
			dpResp = p.outputOnAllInterfaces(p.packetIndex, &p.currPacket, p.currPacket.Type, p.currPacketData)
			if p.bStreamSync {
				p.processState = procHdr
			} else {
				p.processState = waitSync
			}
			p.currPacketData = p.currPacketData[:0]
		} else {
			dpResp = p.outputOnAllInterfaces(p.packetIndex, &p.currPacket, p.currPacket.Type, p.partPktData)
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
	partAddr, validBits := p.extractBrAddrPkt()
	p.currPacket.UpdateAddress(partAddr, validBits)
}

func (p *PktProc) extractBrAddrPkt() (value uint64, nBitsOut int) {
	addrshift := []int{2, 1, 1, 0}
	addrMask := []uint8{0x7, 0xF, 0xF, 0x1F}
	addrBits := []int{3, 4, 4, 5}

	CBit := true
	bytecount := 0
	bitcount := 0
	shift := 0
	isa_idx := 0
	var addrbyte uint8
	byte5AddrUpdate := false

	for CBit && bytecount < 4 {
		if !p.checkPktLimits() {
			return 0, 0
		}
		addrbyte = p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		CBit = (addrbyte & 0x80) != 0
		shift = bitcount
		if bytecount == 0 {
			addrbyte &= ^uint8(0x81)
			bitcount += 6
			addrbyte >>= 1
		} else {
			if p.Config.AltBranch() && !CBit {
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
		if !p.checkPktLimits() {
			return 0, 0
		}
		addrbyte = p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		if (addrbyte & 0x80) != 0 {
			excep_num := (addrbyte >> 3) & 0x7
			p.currPacket.UpdateISA(ocsd.ISAArm)
			p.currPacket.SetException(exceptionTypeARMdeprecated[excep_num], uint16(excep_num))
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
				// Legacy streams may encode address+exception combinations that do not
				// map cleanly onto these ISA patterns. Preserve existing behaviour.
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

	return value, bitcount
}

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

var exceptionTypesStd = []ocsd.ArmV7Exception{
	ocsd.ExcpNoException,
	ocsd.ExcpDebugHalt,
	ocsd.ExcpSMC,
	ocsd.ExcpHyp,
	ocsd.ExcpAsyncDAbort,
	ocsd.ExcpJazelle,
	ocsd.ExcpReserved,
	ocsd.ExcpReserved,
	ocsd.ExcpReset,
	ocsd.ExcpUndef,
	ocsd.ExcpSVC,
	ocsd.ExcpPrefAbort,
	ocsd.ExcpSyncDataAbort,
	ocsd.ExcpGeneric,
	ocsd.ExcpIRQ,
	ocsd.ExcpFIQ,
}

var exceptionTypesCM = []ocsd.ArmV7Exception{
	ocsd.ExcpNoException,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMIRQn,
	ocsd.ExcpCMUsageFault,
	ocsd.ExcpCMNMI,
	ocsd.ExcpSVC,
	ocsd.ExcpCMDebugMonitor,
	ocsd.ExcpCMMemManage,
	ocsd.ExcpCMPendSV,
	ocsd.ExcpCMSysTick,
	ocsd.ExcpReserved,
	ocsd.ExcpReset,
	ocsd.ExcpReserved,
	ocsd.ExcpCMHardFault,
	ocsd.ExcpReserved,
	ocsd.ExcpCMBusFault,
	ocsd.ExcpReserved,
	ocsd.ExcpReserved,
}

func (p *PktProc) extractExceptionData() {
	if !p.branchNeedsEx {
		return
	}

	if !p.checkPktLimits() {
		return
	}

	dataByte := p.currPacketData[p.currPktIdx]
	p.currPktIdx++

	p.currPacket.Context.CurrNS = (dataByte & 0x1) != 0
	exceptionNum := uint16((dataByte >> 1) & 0xF)
	cancelPrevInstr := (dataByte & 0x20) != 0
	p.currPacket.Context.CurrAltIsa = (dataByte & 0x40) != 0
	p.currPacket.Context.Updated = true

	resume := 0
	irqN := 0
	byte2 := false

	if (dataByte & 0x80) != 0 {
		if !p.checkPktLimits() {
			return
		}
		dataByte = p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		if (dataByte & 0x40) != 0 {
			byte2 = true
		} else {
			if p.Config.V7MArch() {
				exceptionNum |= uint16(dataByte&0x1F) << 4
			}
			p.currPacket.Context.CurrHyp = (dataByte & 0x20) != 0
			p.currPacket.Context.Updated = true

			if (dataByte & 0x80) != 0 {
				if !p.checkPktLimits() {
					return
				}
				dataByte = p.currPacketData[p.currPktIdx]
				p.currPktIdx++
				byte2 = true
			}
		}

		if byte2 {
			resume = int(dataByte & 0xF)
		}
	}

	excepType := ocsd.ExcpReserved
	if p.Config.V7MArch() {
		exceptionNum &= 0x1FF
		if int(exceptionNum) < len(exceptionTypesCM) {
			excepType = exceptionTypesCM[exceptionNum]
		} else {
			excepType = ocsd.ExcpCMIRQn
		}

		if excepType == ocsd.ExcpCMIRQn {
			if exceptionNum > 0x018 {
				irqN = int(exceptionNum - 0x10)
			} else if exceptionNum == 0x008 {
				irqN = 0
			} else {
				irqN = int(exceptionNum)
			}
		}
	} else {
		exceptionNum &= 0xF
		excepType = exceptionTypesStd[exceptionNum]
	}

	p.currPacket.SetExceptionWithCancel(excepType, exceptionNum, cancelPrevInstr)
	_ = resume
	_ = irqN
}

func (p *PktProc) extractCycleCount() uint32 {
	cycleCount := uint32(0)
	byteIdx := 0
	mask := uint8(0x7F)
	bCond := true

	for bCond {
		if !p.checkPktLimits() {
			return 0
		}
		currByte := p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		if byteIdx == 4 {
			if (currByte & 0x80) != 0 {
				p.throwMalformedPacketErr("Malformed cycle count: overlong continuation")
				return 0
			}
			if (currByte & 0x70) != 0 {
				p.throwMalformedPacketErr("Malformed cycle count: overflow in terminal byte")
				return 0
			}
		}

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

func (p *PktProc) checkPktLimits() bool {
	if p.currPktIdx >= len(p.currPacketData) {
		p.throwMalformedPacketErr("Malformed Packet - oversized packet.")
		return false
	}
	return true
}

func (p *PktProc) extractCtxtID() uint32 {
	val := uint32(0)
	ctxtBytes := p.Config.CtxtIDBytes()

	if p.currPktIdx+ctxtBytes > len(p.currPacketData) {
		p.throwMalformedPacketErr("Too few bytes to extract context ID.")
		return 0
	}

	for i := 0; i < int(ctxtBytes); i++ {
		bByte := p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		val |= uint32(bByte) << (i * 8)
	}
	return val
}

func (p *PktProc) onISyncPacket() {
	var instrAddr uint32
	var lsiPAddr uint32
	var lsiPBits int
	var j, t, altISA uint8

	p.currPktIdx = 1

	// 1. Extract cycle count (if present) - same as C++
	if p.isyncGotCC {
		p.currPacket.CycleCount = p.extractCycleCount()
		if p.processState == procErr {
			return
		}
		p.currPacket.ISyncInfo.HasCycleCount = true
	}

	// 2. Extract context ID BEFORE info byte (C++ order)
	if p.Config.CtxtIDBytes() > 0 {
		p.currPacket.Context.CtxtID = p.extractCtxtID()
		if p.processState == procErr {
			return
		}
		p.currPacket.Context.UpdatedC = true
	}

	// 3. Extract info byte
	if !p.checkPktLimits() {
		return
	}
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
	if p.Config.InstrTrace() {
		for i := range 4 {
			if !p.checkPktLimits() {
				return
			}
			instrAddr |= uint32(p.currPacketData[p.currPktIdx]) << (i * 8)
			p.currPktIdx++
		}

		t = uint8(instrAddr & 0x1)
		instrAddr &= 0xFFFFFFFE
		p.currPacket.UpdateAddress(uint64(instrAddr), 32)

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
		p.currPacket.UpdateISA(currISA)

		// 5. LSiP address
		if p.isyncGetLSiP {
			partAddr, bits := p.extractBrAddrPkt()
			lsiPAddr = uint32(partAddr)
			lsiPBits = bits
			if p.processState == procErr {
				return
			}
			p.currPacket.Data.Addr = uint64(instrAddr)
			p.currPacket.Data.UpdateAddr = true
			if lsiPBits > 0 {
				mask := uint64((uint64(1) << uint(lsiPBits)) - 1)
				p.currPacket.Data.Addr = (p.currPacket.Data.Addr & ^mask) | (uint64(lsiPAddr) & mask)
			}
			p.currPacket.ISyncInfo.HasLSipAddr = true
		}
	} else {
		p.currPacket.ISyncInfo.NoAddress = true
	}

	p.processState = sendPkt
}

func (p *PktProc) extractDataAddress() (addr uint64, bits uint8, updateBE bool, beVal uint8) {
	nBits := 0
	nBytes := 0

	for {
		if !p.checkPktLimits() {
			return 0, 0, false, 0
		}
		b := p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		nBytes++

		if nBits > 57 {
			p.throwMalformedPacketErr("Malformed data address: shift exceeds 64-bit accumulator")
			return 0, 0, false, 0
		}

		if nBits == 0 {
			addr |= uint64(b & 0x7F) // lose continuation bit
			nBits += 7
		} else {
			addr |= uint64(b&0x7F) << nBits
			nBits += 7
			// need to extract be here if 5th address byte.
			if nBits == 35 { // 5 * 7 bits
				updateBE = true
				if (b & 0x40) != 0 {
					beVal = 1
				} else {
					beVal = 0
				}
				addr &= 0xFFFFFFFF // max 32 bits on etmv3... (from doc: ETMv3 only trace 32-bit addresses)
			}
		}
		if (b & 0x80) == 0 {
			break
		}
		if nBytes >= 5 {
			p.throwMalformedPacketErr("Malformed data address: continuation exceeds maximum encoded length")
			return 0, 0, false, 0
		}
	}
	return addr, uint8(nBits), updateBE, beVal
}

func (p *PktProc) extractDataValue(sizeCode int) uint32 {
	val := uint32(0)
	bytes := sizeCode
	switch bytes {
	case 3:
		bytes = 4
	case 0:
		return 0 // no value
	}

	for i := 0; i < bytes; i++ {
		if !p.checkPktLimits() {
			return 0
		}
		b := p.currPacketData[p.currPktIdx]
		p.currPktIdx++
		val |= uint32(b) << (i * 8)
	}
	return val
}

func (p *PktProc) extractTimestamp() (val uint64, tsBits uint8) {
	tsMaxBytes := 7
	if p.Config.TSPkt64() {
		tsMaxBytes = 9
	}
	tsCurrBytes := 0
	bCont := true
	mask := uint8(0x7F)
	lastMask := uint8(0x3F)
	if p.Config.TSPkt64() {
		lastMask = 0xFF
	}
	tsIterBits := uint8(7)
	tsLastIterBits := uint8(6)
	if p.Config.TSPkt64() {
		tsLastIterBits = 8
	}
	nBits := uint8(0)

	for tsCurrBytes < tsMaxBytes && bCont {
		if !p.checkPktLimits() {
			return 0, 0
		}
		currByte := p.currPacketData[p.currPktIdx]
		p.currPktIdx++

		val |= uint64(currByte&mask) << (7 * tsCurrBytes)
		tsCurrBytes++
		nBits += tsIterBits
		bCont = (currByte & 0x80) == 0x80

		if tsCurrBytes == tsMaxBytes-1 {
			mask = lastMask
			tsIterBits = tsLastIterBits
		}
	}
	return val, nBits
}

func (p *PktProc) throwPacketHeaderErr(msg string) {
	p.processState = procErr
	p.procErrReason = fmt.Errorf("%w: %s", ocsd.ErrInvalidPcktHdr, msg)
}

func (p *PktProc) throwMalformedPacketErr(msg string) {
	p.processState = procErr
	p.procErrReason = fmt.Errorf("%w: %s", ocsd.ErrBadPacketSeq, msg)
}
