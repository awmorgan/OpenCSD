package ptm

import (
	"fmt"
	"strings"
)

const (
	asyncReqZeros         = 5
	asyncPad0Limit        = 11
	maxVAValidBits        = 32
	vaMask         uint64 = 0xFFFFFFFF
)

type pktType int

const (
	ptmPktNotSync pktType = iota
	ptmPktIncompleteEOT
	ptmPktNoError
	ptmPktBranchAddress
	ptmPktAsync
	ptmPktISync
	ptmPktTrigger
	ptmPktWPUpdate
	ptmPktIgnore
	ptmPktContextID
	ptmPktVMID
	ptmPktAtom
	ptmPktTimestamp
	ptmPktExceptionRet
	ptmPktBranchOrBypassEOT
	ptmPktTpiuPadEOB
	ptmPktBadSequence
	ptmPktReserved
)

type isa int

const (
	isaARM isa = iota
	isaThumb2
	isaAArch64
	isaTEE
	isaJazelle
	isaCustom
	isaUnknown
)

type iSyncReason int

const (
	iSyncPeriodic iSyncReason = iota
	iSyncTraceEnable
	iSyncRestartOverflow
	iSyncDebugExit
)

type ptmException struct {
	present bool
	typeID  int
	number  uint16
}

type ptmContext struct {
	currAltISA bool
	currNS     bool
	currHyp    bool
	updated    bool
	updatedC   bool
	updatedV   bool
	ctxtID     uint32
	vmid       uint8
}

type ptmAddr struct {
	val       uint32
	pktBits   uint8
	validBits uint8
}

type ptmAtom struct {
	enBits uint32
	num    uint8
}

type ptmPacket struct {
	typeID     pktType
	errType    pktType
	currISA    isa
	prevISA    isa
	addr       ptmAddr
	context    ptmContext
	atom       ptmAtom
	iSync      iSyncReason
	cycleCount uint32
	ccValid    bool
	timestamp  uint64
	tsUpdate   uint8
	exception  ptmException
}

func (p *ptmPacket) resetState() {
	p.typeID = ptmPktNotSync
	p.context = ptmContext{}
	p.addr = ptmAddr{}
	p.currISA = isaUnknown
	p.prevISA = isaUnknown
	p.timestamp = 0
	p.clear()
}

func (p *ptmPacket) clear() {
	p.errType = ptmPktNoError
	p.cycleCount = 0
	p.ccValid = false
	p.context.updated = false
	p.context.updatedC = false
	p.context.updatedV = false
	p.tsUpdate = 0
	p.atom.enBits = 0
	p.exception.present = false
	p.prevISA = p.currISA
}

func (p *ptmPacket) setType(t pktType) { p.typeID = t }

func (p *ptmPacket) setErrType(t pktType) {
	p.errType = p.typeID
	p.typeID = t
}

func (p *ptmPacket) updateNS(ns int) {
	p.context.currNS = ns != 0
	p.context.updated = true
}

func (p *ptmPacket) updateAltISA(alt int) {
	p.context.currAltISA = alt != 0
	p.context.updated = true
}

func (p *ptmPacket) updateHyp(hyp int) {
	p.context.currHyp = hyp != 0
	p.context.updated = true
}

func (p *ptmPacket) updateISA(next isa) {
	p.prevISA = p.currISA
	p.currISA = next
}

func (p *ptmPacket) updateContextID(id uint32) {
	p.context.ctxtID = id
	p.context.updatedC = true
}

func (p *ptmPacket) updateVMID(id uint8) {
	p.context.vmid = id
	p.context.updatedV = true
}

func (p *ptmPacket) setException(typeID int, number uint16) {
	p.exception.present = true
	p.exception.typeID = typeID
	p.exception.number = number
}

func (p *ptmPacket) setISyncReason(reason iSyncReason) { p.iSync = reason }

func (p *ptmPacket) setCycleCount(val uint32) {
	p.cycleCount = val
	p.ccValid = true
}

func (p *ptmPacket) updateAddress(part uint32, updateBits int) {
	validMask := uint32(vaMask >> (maxVAValidBits - updateBits))
	p.addr.pktBits = uint8(updateBits)
	p.addr.val &^= validMask
	p.addr.val |= part & validMask
	if updateBits > int(p.addr.validBits) {
		p.addr.validBits = uint8(updateBits)
	}
}

func (p *ptmPacket) updateTimestamp(ts uint64, updateBits uint8) {
	validMask := ^uint64(0) >> (64 - updateBits)
	p.timestamp &^= validMask
	p.timestamp |= ts & validMask
	p.tsUpdate = updateBits
}

func (p *ptmPacket) setAtomFromPHdr(pHdr byte) {
	atomFmtID := pHdr & 0xF0
	if atomFmtID == 0x80 {
		if (pHdr & 0x08) == 0x08 {
			p.atom.num = 2
		} else {
			p.atom.num = 1
		}
	} else if atomFmtID == 0x90 {
		p.atom.num = 3
	} else {
		if (pHdr & 0xE0) == 0xA0 {
			p.atom.num = 4
		} else {
			p.atom.num = 5
		}
	}

	atomMask := byte(0x2)
	p.atom.enBits = 0
	for i := 0; i < int(p.atom.num); i++ {
		p.atom.enBits <<= 1
		if (atomMask & pHdr) == 0 {
			p.atom.enBits |= 0x1
		}
		atomMask <<= 1
	}
}

func (p *ptmPacket) setCycleAccAtomFromPHdr(pHdr byte) {
	p.atom.num = 1
	if (pHdr & 0x2) != 0 {
		p.atom.enBits = 0x0
	} else {
		p.atom.enBits = 0x1
	}
}

func (p *ptmPacket) toString() string {
	name, desc := packetTypeName(p.typeID)
	var b strings.Builder
	b.WriteString(name)
	b.WriteString(" : ")
	b.WriteString(desc)
	b.WriteString("; ")

	switch p.typeID {
	case ptmPktBadSequence:
		name, _ = packetTypeName(p.errType)
		b.WriteString("[")
		b.WriteString(name)
		b.WriteString("]; ")
	case ptmPktAtom:
		b.WriteString(p.atomString())
	case ptmPktContextID:
		b.WriteString(fmt.Sprintf("CtxtID=0x%08X; ", p.context.ctxtID))
	case ptmPktVMID:
		b.WriteString(fmt.Sprintf("VMID=0x%02X; ", p.context.vmid))
	case ptmPktWPUpdate, ptmPktBranchAddress:
		b.WriteString(p.branchAddressString())
	case ptmPktISync:
		b.WriteString(p.iSyncString())
	case ptmPktTimestamp:
		b.WriteString(p.timestampString())
	}

	return b.String()
}

func (p *ptmPacket) atomString() string {
	var b strings.Builder
	bitpattern := p.atom.enBits
	if p.ccValid {
		if (bitpattern & 0x1) != 0 {
			b.WriteString("E")
		} else {
			b.WriteString("N")
		}
		b.WriteString("; ")
		b.WriteString(p.cycleCountString())
		return b.String()
	}

	for i := 0; i < int(p.atom.num); i++ {
		if (bitpattern & 0x1) != 0 {
			b.WriteString("E")
		} else {
			b.WriteString("N")
		}
		bitpattern >>= 1
	}
	b.WriteString("; ")
	return b.String()
}

func (p *ptmPacket) branchAddressString() string {
	var b strings.Builder
	addrStr := getValStr(32, int(p.addr.validBits), uint64(p.addr.val), true, int(p.addr.pktBits))
	b.WriteString("Addr=")
	b.WriteString(addrStr)
	b.WriteString("; ")

	if p.currISA != p.prevISA {
		b.WriteString(p.isaString())
	}

	if p.context.updated {
		if p.context.currNS {
			b.WriteString("NS; ")
		} else {
			b.WriteString("S; ")
		}
		if p.context.currHyp {
			b.WriteString("Hyp; ")
		}
	}

	if p.exception.present {
		b.WriteString(p.exceptionString())
	}

	if p.ccValid {
		b.WriteString(p.cycleCountString())
	}
	return b.String()
}

func (p *ptmPacket) exceptionString() string {
	excepNames := []string{
		"No Exception", "Debug Halt", "SMC", "Hyp",
		"Async Data Abort", "Jazelle", "Reserved", "Reserved",
		"PE Reset", "Undefined Instr", "SVC", "Prefetch Abort",
		"Data Fault", "Generic", "IRQ", "FIQ",
	}
	var name string
	if int(p.exception.number) < len(excepNames) {
		name = excepNames[p.exception.number]
	} else {
		name = "Unknown"
	}
	return fmt.Sprintf("Excep=%s [%02X]; ", name, p.exception.number)
}

func (p *ptmPacket) isaString() string {
	var isaStr string
	switch p.currISA {
	case isaARM:
		isaStr = "ARM(32)"
	case isaThumb2:
		isaStr = "Thumb2"
	case isaAArch64:
		isaStr = "AArch64"
	case isaTEE:
		isaStr = "ThumbEE"
	case isaJazelle:
		isaStr = "Jazelle"
	default:
		isaStr = "Unknown"
	}
	return fmt.Sprintf("ISA=%s; ", isaStr)
}

func (p *ptmPacket) iSyncString() string {
	reason := []string{"Periodic", "Trace Enable", "Restart Overflow", "Debug Exit"}
	var b strings.Builder
	b.WriteString("(")
	b.WriteString(reason[int(p.iSync)])
	b.WriteString("); ")
	b.WriteString(fmt.Sprintf("Addr=0x%08x; ", p.addr.val))
	if p.context.currNS {
		b.WriteString("NS; ")
	} else {
		b.WriteString("S; ")
	}
	if p.context.currHyp {
		b.WriteString("Hyp; ")
	} else {
		b.WriteString(" ")
	}
	if p.context.updatedC {
		b.WriteString(fmt.Sprintf("CtxtID=0x%08X; ", p.context.ctxtID))
	}
	b.WriteString(p.isaString())
	if p.ccValid {
		b.WriteString(p.cycleCountString())
	}
	return b.String()
}

func (p *ptmPacket) timestampString() string {
	valStr := getValStr(64, 64, p.timestamp, true, int(p.tsUpdate))
	var b strings.Builder
	b.WriteString("TS=")
	b.WriteString(valStr)
	b.WriteString(fmt.Sprintf("(%d); ", p.timestamp))
	if p.ccValid {
		b.WriteString(p.cycleCountString())
	}
	return b.String()
}

func (p *ptmPacket) cycleCountString() string {
	return fmt.Sprintf("Cycles=%d; ", p.cycleCount)
}

func packetTypeName(t pktType) (string, string) {
	switch t {
	case ptmPktNotSync:
		return "NOTSYNC", "PTM Not Synchronised"
	case ptmPktIncompleteEOT:
		return "INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"
	case ptmPktNoError:
		return "NO_ERROR", "Error type not set"
	case ptmPktBadSequence:
		return "BAD_SEQUENCE", "Invalid sequence in packet"
	case ptmPktReserved:
		return "RESERVED", "Reserved Packet Header"
	case ptmPktBranchAddress:
		return "BRANCH_ADDRESS", "Branch address packet"
	case ptmPktAsync:
		return "ASYNC", "Alignment Synchronisation Packet"
	case ptmPktISync:
		return "ISYNC", "Instruction Synchronisation packet"
	case ptmPktTrigger:
		return "TRIGGER", "Trigger Event packet"
	case ptmPktWPUpdate:
		return "WP_UPDATE", "Waypoint update packet"
	case ptmPktIgnore:
		return "IGNORE", "Ignore packet"
	case ptmPktContextID:
		return "CTXTID", "Context ID packet"
	case ptmPktVMID:
		return "VMID", "VM ID packet"
	case ptmPktAtom:
		return "ATOM", "Atom packet"
	case ptmPktTimestamp:
		return "TIMESTAMP", "Timestamp packet"
	case ptmPktExceptionRet:
		return "ERET", "Exception return packet"
	default:
		return "UNKNOWN", "Unknown packet type"
	}
}

type pktProcessor struct {
	data           []byte
	pos            int
	processState   int
	currPacketData []byte
	currPktIndex   int
	packet         ptmPacket
	async0         int
	ctxtIDBytes    int
	cycleAcc       bool
	tsPkt64        bool
	numPktBytesReq int
	needCycleCount bool
	gotCycleCount  bool
	gotCCBytes     int
	gotCtxtIDBytes int
	gotTSBytes     bool
	tsByteMax      int
	gotAddrBytes   bool
	numAddrBytes   int
	gotExcepBytes  bool
	numExcepBytes  int
	addrPktISA     isa
	excepAltISA    int
}

const (
	stateWaitSync = iota
	stateProcHdr
	stateProcData
	stateSendPkt
)

func newPktProcessor(data []byte) *pktProcessor {
	p := &pktProcessor{
		data:         data,
		processState: stateWaitSync,
		ctxtIDBytes:  0,
		cycleAcc:     false,
		tsPkt64:      false,
	}
	p.packet.resetState()
	return p
}

func (p *pktProcessor) readByte() (byte, bool) {
	if p.pos >= len(p.data) {
		return 0, false
	}
	b := p.data[p.pos]
	p.pos++
	p.currPacketData = append(p.currPacketData, b)
	return b, true
}

func (p *pktProcessor) findAsyncInStream() bool {
	zeroCount := 0
	start := 0
	for i := p.pos; i < len(p.data); i++ {
		b := p.data[i]
		if b == 0x00 {
			if zeroCount == 0 {
				start = i
			}
			zeroCount++
			continue
		}
		if b == 0x80 && zeroCount >= asyncReqZeros {
			p.currPktIndex = start
			p.currPacketData = append(p.currPacketData[:0], p.data[start:i+1]...)
			p.packet.setType(ptmPktAsync)
			p.async0 = zeroCount
			p.pos = i + 1
			p.processState = stateSendPkt
			return true
		}
		zeroCount = 0
	}
	p.pos = len(p.data)
	return false
}

func (p *pktProcessor) headerToType(b byte) pktType {
	if (b & 0x01) == 0x01 {
		return ptmPktBranchAddress
	}
	if (b & 0x81) == 0x80 {
		return ptmPktAtom
	}
	switch b {
	case 0x00:
		return ptmPktAsync
	case 0x08:
		return ptmPktISync
	case 0x72:
		return ptmPktWPUpdate
	case 0x0C:
		return ptmPktTrigger
	case 0x6E:
		return ptmPktContextID
	case 0x3C:
		return ptmPktVMID
	case 0x42, 0x46:
		return ptmPktTimestamp
	case 0x76:
		return ptmPktExceptionRet
	case 0x66:
		return ptmPktIgnore
	default:
		return ptmPktReserved
	}
}

func (p *pktProcessor) extractCtxtID(idx int) (uint32, error) {
	var ctxtID uint32
	shift := 0
	for i := 0; i < p.ctxtIDBytes; i++ {
		if idx+i >= len(p.currPacketData) {
			return 0, fmt.Errorf("insufficient packet bytes for context id")
		}
		ctxtID |= uint32(p.currPacketData[idx+i]) << shift
		shift += 8
	}
	return ctxtID, nil
}

func (p *pktProcessor) extractCycleCount(offset int) (uint32, error) {
	cycleCount := uint32(0)
	bCont := true
	byIdx := 0
	shift := 4
	for bCont {
		if offset+byIdx >= len(p.currPacketData) {
			return 0, fmt.Errorf("insufficient packet bytes for cycle count")
		}
		currByte := p.currPacketData[offset+byIdx]
		if byIdx == 0 {
			bCont = (currByte & 0x40) != 0
			cycleCount = uint32((currByte >> 2) & 0xF)
		} else {
			bCont = (currByte & 0x80) != 0
			if byIdx == 4 {
				bCont = false
			}
			cycleCount |= uint32(currByte&0x7F) << shift
			shift += 7
		}
		byIdx++
	}
	return cycleCount, nil
}

func (p *pktProcessor) extractAddress(offset int) (uint32, uint8, error) {
	addrVal := uint32(0)
	mask := byte(0x7E)
	numBits := uint8(0x7)
	shift := 0
	nextShift := 0
	totalBits := uint8(0)

	for i := 0; i < p.numAddrBytes; i++ {
		if i == 4 {
			mask = 0x0F
			numBits = 4
			if p.addrPktISA == isaJazelle {
				mask = 0x1F
				numBits = 5
			} else if p.addrPktISA == isaARM {
				mask = 0x07
				numBits = 3
			}
		} else if i > 0 {
			mask = 0x7F
			numBits = 7
			if i == p.numAddrBytes-1 {
				mask = 0x3F
				numBits = 6
			}
		}

		idx := i + offset
		if idx >= len(p.currPacketData) {
			return 0, 0, fmt.Errorf("insufficient packet bytes for address")
		}
		shift = nextShift
		addrVal |= uint32(p.currPacketData[idx]&mask) << shift
		totalBits += numBits

		if i == 0 {
			if p.addrPktISA == isaJazelle {
				addrVal >>= 1
				nextShift = 6
				totalBits--
			} else {
				nextShift = 7
			}
		} else {
			nextShift += 7
		}
	}

	if p.addrPktISA == isaARM {
		addrVal <<= 1
		totalBits++
	}
	return addrVal, totalBits, nil
}

func (p *pktProcessor) pktASync() error {
	if len(p.currPacketData) == 1 {
		p.async0 = 1
	}
	res := p.findAsync()
	switch res {
	case asyncOK, asyncExtra0:
		p.processState = stateSendPkt
	case asyncThrow0, asyncNotAsync:
		p.packet.setErrType(ptmPktBadSequence)
		p.processState = stateSendPkt
	case asyncIncomplete:
		// wait for more data
	}
	return nil
}

func (p *pktProcessor) pktISync() error {
	if len(p.currPacketData) == 1 {
		p.gotCtxtIDBytes = 0
		p.numPktBytesReq = 6 + p.ctxtIDBytes
	}

	bGotBytes := false
	validByte := true
	for validByte && !bGotBytes {
		currByte, ok := p.readByte()
		if !ok {
			validByte = false
			break
		}
		pktIndex := len(p.currPacketData) - 1
		if pktIndex == 5 {
			altISA := (currByte >> 2) & 0x1
			reason := (currByte >> 5) & 0x3
			p.packet.setISyncReason(iSyncReason(reason))
			p.packet.updateNS(int((currByte >> 3) & 0x1))
			p.packet.updateAltISA(int((currByte >> 2) & 0x1))
			p.packet.updateHyp(int((currByte >> 1) & 0x1))
			isaVal := isaARM
			if (p.currPacketData[1] & 0x1) != 0 {
				if altISA == 1 {
					isaVal = isaTEE
				} else {
					isaVal = isaThumb2
				}
			}
			p.packet.updateISA(isaVal)
			p.needCycleCount = reason != 0 && p.cycleAcc
			p.gotCycleCount = false
			p.numPktBytesReq += boolToInt(p.needCycleCount)
			p.gotCCBytes = 0
		} else if pktIndex > 5 {
			if p.needCycleCount && !p.gotCycleCount {
				if pktIndex == 6 {
					p.gotCycleCount = (currByte & 0x40) == 0
				} else {
					p.gotCycleCount = (currByte&0x80) == 0 || pktIndex == 10
				}
				p.gotCCBytes++
				if !p.gotCycleCount {
					p.numPktBytesReq++
				}
			} else if p.ctxtIDBytes > p.gotCtxtIDBytes {
				p.gotCtxtIDBytes++
			}
		}

		bGotBytes = len(p.currPacketData) == p.numPktBytesReq
	}

	if bGotBytes {
		address := uint32(p.currPacketData[1]) & 0xFE
		address |= uint32(p.currPacketData[2]) << 8
		address |= uint32(p.currPacketData[3]) << 16
		address |= uint32(p.currPacketData[4]) << 24
		p.packet.updateAddress(address, 32)

		optIdx := 6
		if p.needCycleCount {
			cc, err := p.extractCycleCount(optIdx)
			if err != nil {
				return err
			}
			p.packet.setCycleCount(cc)
			optIdx += p.gotCCBytes
		}
		if p.ctxtIDBytes > 0 {
			ctxtID, err := p.extractCtxtID(optIdx)
			if err != nil {
				return err
			}
			p.packet.updateContextID(ctxtID)
		}
		p.processState = stateSendPkt
	}
	return nil
}

func (p *pktProcessor) pktAtom() error {
	pHdr := p.currPacketData[0]
	if !p.cycleAcc {
		p.packet.setAtomFromPHdr(pHdr)
		p.processState = stateSendPkt
		return nil
	}

	bGotAll := false
	byteAvail := true
	if (pHdr & 0x40) == 0 {
		bGotAll = true
	} else {
		for byteAvail && !bGotAll {
			currByte, ok := p.readByte()
			if !ok {
				byteAvail = false
				break
			}
			if (currByte&0x80) == 0 || len(p.currPacketData) == 5 {
				bGotAll = true
			}
		}
	}

	if bGotAll {
		cc, err := p.extractCycleCount(0)
		if err != nil {
			return err
		}
		p.packet.setCycleCount(cc)
		p.packet.setCycleAccAtomFromPHdr(pHdr)
		p.processState = stateSendPkt
	}
	return nil
}

func (p *pktProcessor) pktBranchAddr() error {
	currByte := p.currPacketData[0]
	bDone := false
	bBytesAvail := true

	if len(p.currPacketData) == 1 {
		p.gotAddrBytes = false
		p.numAddrBytes = 1
		p.needCycleCount = p.cycleAcc
		p.gotCCBytes = 0
		p.gotExcepBytes = false
		p.numExcepBytes = 0
		p.addrPktISA = isaUnknown

		if (currByte & 0x80) == 0 {
			p.gotAddrBytes = true
			if !p.needCycleCount {
				bDone = true
			}
			p.gotExcepBytes = true
		}
	}

	for !bDone && bBytesAvail {
		currByte, ok := p.readByte()
		if !ok {
			bBytesAvail = false
			break
		}
		byteIdx := len(p.currPacketData) - 1
		if !p.gotAddrBytes {
			if byteIdx < 4 {
				if (currByte & 0x80) == 0x00 {
					if (currByte & 0x40) == 0x00 {
						p.gotExcepBytes = true
					}
					p.gotAddrBytes = true
					bDone = p.gotExcepBytes && !p.needCycleCount
				}
			} else {
				if (currByte & 0x40) == 0x00 {
					p.gotExcepBytes = true
				}
				p.gotAddrBytes = true
				bDone = p.gotExcepBytes && !p.needCycleCount

				p.addrPktISA = isaARM
				if (currByte & 0x20) == 0x20 {
					p.addrPktISA = isaJazelle
				} else if (currByte & 0x30) == 0x10 {
					p.addrPktISA = isaThumb2
				}
			}
			p.numAddrBytes++
		} else if !p.gotExcepBytes {
			if p.numExcepBytes == 0 {
				if (currByte & 0x80) == 0x00 {
					p.gotExcepBytes = true
				}
				if (currByte & 0x40) == 0x40 {
					p.excepAltISA = 1
				} else {
					p.excepAltISA = 0
				}
			} else {
				p.gotExcepBytes = true
			}
			p.numExcepBytes++
			if p.gotExcepBytes && !p.needCycleCount {
				bDone = true
			}
		} else if p.needCycleCount {
			if p.gotCCBytes == 0 {
				bDone = (currByte & 0x40) == 0x00
			} else {
				bDone = (currByte&0x80) == 0x00 || p.gotCCBytes == 4
			}
			p.gotCCBytes++
		}
	}

	if bDone {
		if p.addrPktISA == isaUnknown {
			p.addrPktISA = p.packet.currISA
		}
		if p.gotExcepBytes {
			if p.addrPktISA == isaTEE && p.excepAltISA == 0 {
				p.addrPktISA = isaThumb2
			} else if p.addrPktISA == isaThumb2 && p.excepAltISA == 1 {
				p.addrPktISA = isaTEE
			}
		}
		p.packet.updateISA(p.addrPktISA)

		addrVal, totalBits, err := p.extractAddress(0)
		if err != nil {
			return err
		}
		p.packet.updateAddress(addrVal, int(totalBits))

		if p.numExcepBytes > 0 {
			e1 := p.currPacketData[p.numAddrBytes]
			enum := (uint16(e1) >> 1) & 0xF
			p.packet.updateNS(int(e1 & 0x1))
			if p.numExcepBytes > 1 {
				e2 := p.currPacketData[p.numAddrBytes+1]
				p.packet.updateHyp(int((e2 >> 5) & 0x1))
				enum |= uint16(e2&0x1F) << 4
			}
			p.packet.setException(int(enum), enum)
		}

		if p.needCycleCount {
			countIdx := p.numAddrBytes + p.numExcepBytes
			cc, err := p.extractCycleCount(countIdx)
			if err != nil {
				return err
			}
			p.packet.setCycleCount(cc)
		}
		p.processState = stateSendPkt
	}
	return nil
}

func (p *pktProcessor) pktReserved() error {
	p.processState = stateSendPkt
	return nil
}

type asyncResult int

const (
	asyncOK asyncResult = iota
	asyncNotAsync
	asyncExtra0
	asyncThrow0
	asyncIncomplete
)

func (p *pktProcessor) findAsync() asyncResult {
	bFound := false
	bByteAvail := true
	res := asyncNotAsync
	for !bFound && bByteAvail {
		currByte, ok := p.readByte()
		if !ok {
			bByteAvail = false
			res = asyncIncomplete
			break
		}
		if currByte == 0x00 {
			p.async0++
			if p.async0 >= (asyncPad0Limit + asyncReqZeros) {
				bFound = true
				res = asyncThrow0
			}
		} else {
			if currByte == 0x80 {
				if p.async0 == 5 {
					res = asyncOK
				} else if p.async0 > 5 {
					res = asyncExtra0
				}
			}
			bFound = true
		}
	}
	return res
}

func getValStr(totalBits int, validBits int, value uint64, asHex bool, updateBits int) string {
	if totalBits < 4 || totalBits > 64 {
		return ""
	}
	if asHex {
		numHexChars := totalBits / 4
		if totalBits%4 > 0 {
			numHexChars++
		}
		validChars := validBits / 4
		if validBits%4 > 0 {
			validChars++
		}
		var b strings.Builder
		b.WriteString("0x")
		if validChars < numHexChars {
			b.WriteString(strings.Repeat("?", numHexChars-validChars))
		}
		format := fmt.Sprintf("%%0%dX", validChars)
		if validBits > 32 {
			b.WriteString(fmt.Sprintf(format, value))
		} else {
			b.WriteString(fmt.Sprintf(format, uint32(value)))
		}
		if validBits < totalBits {
			b.WriteString(fmt.Sprintf(" (%d:0)", validBits-1))
		}
		if updateBits > 0 {
			updateMask := ^uint64(0) >> (64 - updateBits)
			b.WriteString(fmt.Sprintf(" ~[0x%X]", value&updateMask))
		}
		return b.String()
	}

	valStr := ""
	if validBits < totalBits {
		valStr += "??"
	}
	if validBits > 32 {
		valStr += fmt.Sprintf("%d", value)
	} else {
		valStr += fmt.Sprintf("%d", uint32(value))
	}
	if validBits < totalBits {
		valStr += fmt.Sprintf(" (%d:0)", validBits-1)
	}
	return valStr
}

func formatRawBytes(bytes []byte) string {
	var b strings.Builder
	for _, v := range bytes {
		b.WriteString(fmt.Sprintf("0x%02x ", v))
	}
	return b.String()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ParsePtmPackets(data []byte) ([]string, error) {
	p := newPktProcessor(data)
	var out []string

	for {
		if p.processState == stateWaitSync {
			if !p.findAsyncInStream() {
				break
			}
		}

		switch p.processState {
		case stateProcHdr:
			p.currPktIndex = p.pos
			p.currPacketData = p.currPacketData[:0]
			p.packet.clear()
			currByte, ok := p.readByte()
			if !ok {
				return out, nil
			}
			p.packet.setType(p.headerToType(currByte))
			p.processState = stateProcData
		case stateProcData:
			var err error
			switch p.packet.typeID {
			case ptmPktAsync:
				err = p.pktASync()
			case ptmPktISync:
				err = p.pktISync()
			case ptmPktAtom:
				err = p.pktAtom()
			case ptmPktBranchAddress:
				err = p.pktBranchAddr()
			default:
				err = p.pktReserved()
			}
			if err != nil {
				return out, err
			}
			if p.pos >= len(p.data) && p.processState != stateSendPkt {
				return out, nil
			}
		case stateSendPkt:
			line := fmt.Sprintf("Idx:%d; ID:0; [%s];\t%s", p.currPktIndex, formatRawBytes(p.currPacketData), p.packet.toString())
			out = append(out, line)
			p.currPacketData = p.currPacketData[:0]
			p.processState = stateProcHdr
		default:
			p.processState = stateProcHdr
		}

		if p.pos >= len(p.data) && p.processState == stateProcHdr {
			break
		}
		if p.processState == stateWaitSync {
			break
		}
		if p.processState == stateSendPkt && p.pos >= len(p.data) {
			continue
		}
	}

	return out, nil
}
