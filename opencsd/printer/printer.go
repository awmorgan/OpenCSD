package printer

import (
	"fmt"
	"strings"

	"opencsd/common"
	"opencsd/ptm"
)

// FormatRawPacketLine formats a PTM packet line to match the C++ .ppl output.
func FormatRawPacketLine(offset uint64, traceID uint8, pkt ptm.Packet) string {
	hexStr := formatHexBytes(pkt.Data)
	pktType := ptmPacketTypeName(pkt.Type)
	desc := ptmPacketDescription(pkt)
	return fmt.Sprintf("Idx:%d; ID:%x; [%s];\t%s : %s", offset, traceID, hexStr, pktType, desc)
}

// FormatGenericElementLine formats a generic trace element line to match the C++ .ppl output.
func FormatGenericElementLine(offset uint64, traceID uint8, elem common.GenericTraceElement) string {
	return fmt.Sprintf("Idx:%d; ID:%x; %s", offset, traceID, formatGenericElement(elem))
}

// FormatGenericElement formats a generic trace element to match the C++ .ppl output.
func FormatGenericElement(elem common.GenericTraceElement) string {
	return formatGenericElement(elem)
}

func formatHexBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return strings.Join(parts, " ") + " "
}

func ptmPacketTypeName(pktType ptm.PacketType) string {
	switch pktType {
	case ptm.PacketTypeASYNC:
		return "ASYNC"
	case ptm.PacketTypeISYNC:
		return "ISYNC"
	case ptm.PacketTypeATOM:
		return "ATOM"
	case ptm.PacketTypeBranchAddr:
		return "BRANCH_ADDRESS"
	case ptm.PacketTypeTimestamp:
		return "TIMESTAMP"
	case ptm.PacketTypeContextID:
		return "CTXTID"
	case ptm.PacketTypeVMID:
		return "VMID"
	case ptm.PacketTypeExceptionReturn:
		return "ERET"
	case ptm.PacketTypeWaypoint:
		return "WP_UPDATE"
	case ptm.PacketTypeNoSync:
		return "NOTSYNC"
	default:
		return "UNKNOWN"
	}
}

func ptmPacketDescription(pkt ptm.Packet) string {
	switch pkt.Type {
	case ptm.PacketTypeASYNC:
		return "Alignment Synchronisation Packet; "
	case ptm.PacketTypeISYNC:
		return formatISyncDesc(pkt)
	case ptm.PacketTypeATOM:
		desc := fmt.Sprintf("Atom packet; %s; ", atomPattern(pkt.AtomBits, pkt.AtomCount))
		if pkt.CCValid {
			desc += fmt.Sprintf("Cycles=%d; ", pkt.CycleCount)
		}
		return desc
	case ptm.PacketTypeBranchAddr:
		return formatBranchAddrDesc(pkt)
	case ptm.PacketTypeTimestamp:
		return formatTimestampDesc(pkt)
	case ptm.PacketTypeContextID:
		return fmt.Sprintf("Context ID packet; CtxtID=0x%08x; ", pkt.ContextID)
	case ptm.PacketTypeVMID:
		return fmt.Sprintf("VMID packet; VMID=0x%02x; ", pkt.VMID)
	case ptm.PacketTypeExceptionReturn:
		return "Exception return packet; "
	case ptm.PacketTypeWaypoint:
		return formatWaypointUpdateDesc(pkt)
	case ptm.PacketTypeNoSync:
		return "PTM Not Synchronised; "
	default:
		return "Unknown packet type; "
	}
}

func formatWaypointUpdateDesc(pkt ptm.Packet) string {
	desc := "Waypoint update packet; "
	addrStr := formatValStr(32, int(pkt.AddrValidBits), pkt.Address, int(pkt.AddrBits))
	desc += fmt.Sprintf("Addr=%s; ", addrStr)
	if pkt.ISAValid && pkt.ISAChanged {
		desc += fmt.Sprintf("ISA=%s; ", isaPacketString(pkt.ISA))
	}
	if pkt.CCValid {
		desc += fmt.Sprintf("Cycles=%d; ", pkt.CycleCount)
	}
	return desc
}

func formatISyncDesc(pkt ptm.Packet) string {
	reason := "Periodic"
	switch pkt.ISyncReason {
	case ptm.ISyncTraceEnable:
		reason = "Trace Enable"
	case ptm.ISyncAfterOverflow:
		reason = "Restart Overflow"
	case ptm.ISyncDebugExit:
		reason = "Debug Exit"
	}

	security := "S; "
	if !pkt.SecureState {
		security = "NS; "
	}

	hyp := " "
	if pkt.Hypervisor {
		hyp = "Hyp; "
	}

	ctxt := ""
	if pkt.ContextID != 0 {
		ctxt = fmt.Sprintf("CtxtID=%08x; ", pkt.ContextID)
	}

	isa := fmt.Sprintf("ISA=%s; ", isaPacketString(pkt.ISA))

	desc := fmt.Sprintf("Instruction Synchronisation packet; (%s); Addr=0x%08x; %s%s%s", reason, uint32(pkt.Address), security, hyp, ctxt) + isa
	if pkt.CCValid {
		desc += fmt.Sprintf("Cycles=%d; ", pkt.CycleCount)
	}
	return desc
}

func formatBranchAddrDesc(pkt ptm.Packet) string {
	desc := "Branch address packet; "
	validBits := int(pkt.AddrBits)
	if pkt.AddrValidBits > 0 {
		validBits = int(pkt.AddrValidBits)
	}
	addrStr := formatValStr(32, validBits, pkt.Address, int(pkt.AddrBits))
	desc += fmt.Sprintf("Addr=%s; ", addrStr)

	if pkt.ISAValid && pkt.ISAChanged {
		desc += fmt.Sprintf("ISA=%s; ", isaPacketString(pkt.ISA))
	}

	if pkt.SecureValid {
		if pkt.SecureState {
			desc += "S; "
		} else {
			desc += "NS; "
		}
		if pkt.Hypervisor {
			desc += "Hyp; "
		}
	}

	if pkt.ExceptionNum != 0 {
		desc += fmt.Sprintf("Excep=%s [%02x]; ", ptmExceptionName(pkt.ExceptionNum), pkt.ExceptionNum)
	}
	if pkt.CCValid {
		desc += fmt.Sprintf("Cycles=%d; ", pkt.CycleCount)
	}

	return desc
}

func formatTimestampDesc(pkt ptm.Packet) string {
	tsStr := formatValStr(64, 64, pkt.Timestamp, int(pkt.TSUpdateBits))
	desc := fmt.Sprintf("Timestamp packet; TS=%s(%d); ", tsStr, pkt.Timestamp)
	if pkt.CCValid {
		desc += fmt.Sprintf("Cycles=%d; ", pkt.CycleCount)
	}
	return desc
}

func atomPattern(bits uint8, count uint8) string {
	if count == 0 {
		return ""
	}
	var sb strings.Builder
	for i := uint8(0); i < count; i++ {
		if (bits & (1 << i)) != 0 {
			sb.WriteByte('E')
		} else {
			sb.WriteByte('N')
		}
	}
	return sb.String()
}

func formatGenericElement(elem common.GenericTraceElement) string {
	name := genericElemName(elem.Type)
	details := genericElemDetails(elem)
	ccStr := ""
	if elem.HasCycleCount {
		ccStr = fmt.Sprintf(" [CC=%d]; ", elem.CycleCount)
	}
	return fmt.Sprintf("%s(%s%s)", name, details, ccStr)
}

func genericElemName(t common.ElemType) string {
	switch t {
	case common.ElemTypeNoSync:
		return "OCSD_GEN_TRC_ELEM_NO_SYNC"
	case common.ElemTypeTraceOn:
		return "OCSD_GEN_TRC_ELEM_TRACE_ON"
	case common.ElemTypeEOTrace:
		return "OCSD_GEN_TRC_ELEM_EO_TRACE"
	case common.ElemTypePeContext:
		return "OCSD_GEN_TRC_ELEM_PE_CONTEXT"
	case common.ElemTypeAddrRange:
		return "OCSD_GEN_TRC_ELEM_INSTR_RANGE"
	case common.ElemTypeAddrNacc:
		return "OCSD_GEN_TRC_ELEM_ADDR_NACC"
	case common.ElemTypeException:
		return "OCSD_GEN_TRC_ELEM_EXCEPTION"
	case common.ElemTypeExceptionReturn:
		return "OCSD_GEN_TRC_ELEM_EXCEPTION_RET"
	case common.ElemTypeTimestamp:
		return "OCSD_GEN_TRC_ELEM_TIMESTAMP"
	default:
		return "OCSD_GEN_TRC_ELEM_UNKNOWN"
	}
}

func genericElemDetails(elem common.GenericTraceElement) string {
	switch elem.Type {
	case common.ElemTypeNoSync:
		reason := "init-decoder"
		return fmt.Sprintf(" [%s]", reason)
	case common.ElemTypeTraceOn:
		reason := traceOnReason(elem.TraceOnReason)
		return fmt.Sprintf(" [%s]", reason)
	case common.ElemTypeEOTrace:
		return " [end-of-trace]"
	case common.ElemTypePeContext:
		return formatPEContext(elem.Context)
	case common.ElemTypeAddrRange:
		return formatAddrRange(elem.AddrRange)
	case common.ElemTypeAddrNacc:
		return formatAddrNacc(elem)
	case common.ElemTypeException:
		return formatException(elem.Exception)
	case common.ElemTypeExceptionReturn:
		return ""
	case common.ElemTypeTimestamp:
		return fmt.Sprintf(" [ TS=0x%012x]; ", elem.Timestamp)
	default:
		return ""
	}
}

func traceOnReason(reason string) string {
	lower := strings.ToLower(reason)
	switch lower {
	case "trace enable", "begin or filter":
		return "begin or filter"
	case "overflow":
		return "overflow"
	case "debug restart":
		return "debug restart"
	default:
		if reason != "" {
			return reason
		}
		return "begin or filter"
	}
}

func formatPEContext(ctx common.PEContext) string {
	isa := isaElemString(ctx.ISA)
	security := "S; "
	if ctx.SecurityState == common.SecurityStateNonSecure {
		security = "N; "
	}
	bits := "32-bit; "
	if ctx.Bits64 {
		bits = "64-bit; "
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("(ISA=%s) %s%s", isa, security, bits))
	if ctx.VMID != 0 {
		sb.WriteString(fmt.Sprintf("VMID=0x%x; ", ctx.VMID))
	}
	if ctx.ContextID != 0 {
		sb.WriteString(fmt.Sprintf("CTXTID=0x%x; ", ctx.ContextID))
	}
	return sb.String()
}

func formatAddrRange(ar common.AddrRange) string {
	isa := isaElemString(ar.ISA)
	lastExec := "E "
	if ar.NumInstr > 0 && !ar.LastInstrExec {
		lastExec = "N "
	}

	instrType := instrTypeString(ar.LastInstrType)
	subType := instrSubTypeString(ar)
	cond := ""
	if ar.LastInstrCond {
		cond = " <cond>"
	}

	return fmt.Sprintf("exec range=0x%x:[0x%x] num_i(%d) last_sz(%d) (ISA=%s) %s%s%s%s", ar.StartAddr, ar.EndAddr, ar.NumInstr, ar.LastInstrSz, isa, lastExec, instrType, subType, cond)
}

func formatAddrNacc(elem common.GenericTraceElement) string {
	// Format: " 0xc02f5b3a; Memspace [0x19:Any S] "
	// Memory space encoding (ocsd_mem_space_acc_t):
	//   OCSD_MEM_SPACE_S = 0x19 (Any Secure)
	//   OCSD_MEM_SPACE_N = 0x6  (Any Non Secure)
	memSpaceCode := 0x6 // Any Non Secure
	memSpaceStr := "Any NS"
	if elem.NaccMemSpace == common.SecurityStateSecure {
		memSpaceCode = 0x19
		memSpaceStr = "Any S"
	}
	return fmt.Sprintf(" 0x%x; Memspace [0x%x:%s] ", elem.NaccAddr, memSpaceCode, memSpaceStr)
}

func formatException(ex common.ExceptionInfo) string {
	var sb strings.Builder
	if ex.PrefRetAddr != 0 {
		sb.WriteString(fmt.Sprintf("pref ret addr:0x%x; ", ex.PrefRetAddr))
	}
	sb.WriteString(fmt.Sprintf("excep num (0x%02x) ", ex.Number))
	return sb.String()
}

func isaPacketString(isa common.ISA) string {
	switch isa {
	case common.ISAARM:
		return "ARM(32)"
	case common.ISAThumb2, common.ISAThumb:
		return "Thumb2"
	case common.ISAA64:
		return "AArch64"
	case common.ISATEE:
		return "ThumbEE"
	default:
		return "Unknown"
	}
}

func isaElemString(isa common.ISA) string {
	switch isa {
	case common.ISAARM:
		return "A32"
	case common.ISAThumb2, common.ISAThumb:
		return "T32"
	case common.ISAA64:
		return "A64"
	case common.ISATEE:
		return "TEE"
	default:
		return "Unk"
	}
}

func instrTypeString(t common.InstrType) string {
	switch t {
	case common.InstrTypeBranch:
		return "BR  "
	case common.InstrTypeBranchIndirect:
		return "iBR "
	case common.InstrTypeISB:
		return "ISB "
	case common.InstrTypeDSBDMB:
		return "DSB.DMB"
	default:
		return "--- "
	}
}

func instrSubTypeString(ar common.AddrRange) string {
	// b+link is shown for both direct and indirect branches with link
	if ar.LastInstrLink {
		return "b+link "
	}
	if ar.LastInstrType == common.InstrTypeBranchIndirect && ar.LastInstrReturn {
		return "V7:impl ret"
	}
	return ""
}

func formatValStr(totalBits int, validBits int, value uint64, updateBits int) string {
	if totalBits < 4 {
		totalBits = 4
	}
	if totalBits > 64 {
		totalBits = 64
	}

	if validBits < 0 {
		validBits = 0
	}
	if validBits > totalBits {
		validBits = totalBits
	}

	numHexChars := totalBits / 4
	if totalBits%4 != 0 {
		numHexChars++
	}

	validChars := validBits / 4
	if validBits%4 != 0 {
		validChars++
	}

	var sb strings.Builder
	sb.WriteString("0x")
	if validChars < numHexChars {
		for i := 0; i < numHexChars-validChars; i++ {
			sb.WriteString("?")
		}
	}

	if validChars > 0 {
		fmtStr := fmt.Sprintf("%%0%dX", validChars)
		sb.WriteString(fmt.Sprintf(fmtStr, value))
	}

	if validBits < totalBits {
		sb.WriteString(fmt.Sprintf(" (%d:0)", validBits-1))
	}

	if updateBits > 0 {
		updateMask := uint64(0)
		if updateBits >= 64 {
			updateMask = ^uint64(0)
		} else {
			updateMask = (uint64(1) << updateBits) - 1
		}
		sb.WriteString(fmt.Sprintf(" ~[0x%X]", value&updateMask))
	}

	return sb.String()
}

func ptmExceptionName(exNum uint16) string {
	if exNum < 16 {
		return []string{
			"No Exception",
			"Debug Halt",
			"SMC",
			"Hyp",
			"Async Data Abort",
			"Jazelle",
			"Reserved",
			"Reserved",
			"PE Reset",
			"Undefined Instr",
			"SVC",
			"Prefetch Abort",
			"Data Fault",
			"Generic",
			"IRQ",
			"FIQ",
		}[exNum]
	}
	return "Unknown"
}
