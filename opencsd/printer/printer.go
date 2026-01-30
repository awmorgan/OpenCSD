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
		return fmt.Sprintf("Atom packet; %s; ", atomPattern(pkt.AtomBits, pkt.AtomCount))
	case ptm.PacketTypeBranchAddr:
		return formatBranchAddrDesc(pkt)
	case ptm.PacketTypeTimestamp:
		return fmt.Sprintf("Timestamp packet; TS=0x%x; ", pkt.Timestamp)
	case ptm.PacketTypeContextID:
		return fmt.Sprintf("Context ID packet; CtxtID=0x%08x; ", pkt.ContextID)
	case ptm.PacketTypeVMID:
		return fmt.Sprintf("VMID packet; VMID=0x%02x; ", pkt.VMID)
	case ptm.PacketTypeExceptionReturn:
		return "Exception return packet; "
	default:
		return "Unknown packet type; "
	}
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
		ctxt = fmt.Sprintf("CtxtID=0x%08x; ", pkt.ContextID)
	}

	isa := fmt.Sprintf("ISA=%s; ", isaPacketString(pkt.ISA))

	return fmt.Sprintf("Instruction Synchronisation packet; (%s); Addr=0x%08x; %s%s%s", reason, uint32(pkt.Address), security, hyp, ctxt) + isa
}

func formatBranchAddrDesc(pkt ptm.Packet) string {
	// NOTE: Address and exception details require full PTM address decode.
	desc := "Branch address packet; "
	if pkt.Address != 0 {
		desc += fmt.Sprintf("Addr=0x%08x; ", uint32(pkt.Address))
	}
	if pkt.ExceptionNum != 0 {
		desc += fmt.Sprintf("Excep=0x%02x; ", pkt.ExceptionNum)
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
	return fmt.Sprintf("%s(%s)", name, details)
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
	switch reason {
	case "trace enable":
		return "begin or filter"
	case "debug restart":
		return "debug restart"
	case "overflow":
		return "overflow"
	case "begin or filter":
		return "begin or filter"
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
	lastSz := ar.LastInstrSz
	if lastSz == 0 {
		lastSz = 4
	}
	lastExec := "E "
	if ar.LastInstrSz != 0 && !ar.LastInstrExec && ar.NumInstr > 0 {
		lastExec = "N "
	}
	instrType := instrTypeString(ar.LastInstrType)
	cond := ""
	if ar.LastInstrCond {
		cond = " <cond>"
	}
	return fmt.Sprintf("exec range=0x%x:[0x%x] num_i(%d) last_sz(%d) (ISA=%s) %s%s%s", ar.StartAddr, ar.EndAddr, ar.NumInstr, lastSz, isa, lastExec, instrType, cond)
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
		return "BR "
	case common.InstrTypeBranchIndirect:
		return "iBR "
	default:
		return "--- "
	}
}
