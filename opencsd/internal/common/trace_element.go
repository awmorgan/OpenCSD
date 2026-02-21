package common

import (
	"fmt"
	"strings"

	"opencsd/internal/ocsd"
)

// GenElemType represents the generic trace element type.
type GenElemType uint32

const (
	GenElemUnknown         GenElemType = 0
	GenElemNoSync          GenElemType = 1
	GenElemTraceOn         GenElemType = 2
	GenElemEOTrace         GenElemType = 3
	GenElemPeContext       GenElemType = 4
	GenElemInstrRange      GenElemType = 5
	GenElemIRangeNopath    GenElemType = 6
	GenElemAddrNacc        GenElemType = 7
	GenElemAddrUnknown     GenElemType = 8
	GenElemException       GenElemType = 9
	GenElemExceptionRet    GenElemType = 10
	GenElemTimestamp       GenElemType = 11
	GenElemCycleCount      GenElemType = 12
	GenElemEvent           GenElemType = 13
	GenElemSWTrace         GenElemType = 14
	GenElemSyncMarker      GenElemType = 15
	GenElemMemTrans        GenElemType = 16
	GenElemInstrumentation GenElemType = 17
	GenElemITMTrace        GenElemType = 18
	GenElemCustom          GenElemType = 19
)

type TraceOnReason uint32

const (
	TraceOnNormal   TraceOnReason = 0
	TraceOnOverflow TraceOnReason = 1
	TraceOnExDebug  TraceOnReason = 2
)

type EventType uint16

const (
	EventUnknown  EventType = 0
	EventTrigger  EventType = 1
	EventNumbered EventType = 2
)

type TraceEvent struct {
	EvType   EventType
	EvNumber uint16
}

type UnsyncInfo uint32

const (
	UnsyncUnknown      UnsyncInfo = 0
	UnsyncInitDecoder  UnsyncInfo = 1
	UnsyncResetDecoder UnsyncInfo = 2
	UnsyncOverflow     UnsyncInfo = 3
	UnsyncDiscard      UnsyncInfo = 4
	UnsyncBadPacket    UnsyncInfo = 5
	UnsyncBadImage     UnsyncInfo = 6
	UnsyncEOT          UnsyncInfo = 7
)

type TraceSyncMarker uint32

const (
	ElemMarkerTS TraceSyncMarker = 0
)

type TraceMarkerPayload struct {
	Type  TraceSyncMarker
	Value uint32
}

type TraceMemtrans uint32

const (
	MemTransTraceInit TraceMemtrans = 0
	MemTransStart     TraceMemtrans = 1
	MemTransCommit    TraceMemtrans = 2
	MemTransFail      TraceMemtrans = 3
)

type TraceSWIte struct {
	EL    uint8
	Value uint64
}

type SWTItmType uint32

const (
	SWITPayload  SWTItmType = 0
	DWTPayload   SWTItmType = 1
	TSSync       SWTItmType = 2
	TSDelay      SWTItmType = 3
	TSPKTDelay   SWTItmType = 4
	TSPKTTSDelay SWTItmType = 5
	TSGlobal     SWTItmType = 6
)

type SWTItmInfo struct {
	PktType      SWTItmType
	PayloadSrcID uint8
	PayloadSize  uint8
	Value        uint32
	Overflow     uint8
}

// TraceElement corresponds to OcsdTraceElement
type TraceElement struct {
	ElemType     GenElemType
	ISA          ocsd.ISA
	StAddr       ocsd.VAddr
	EnAddr       ocsd.VAddr
	Context      ocsd.PEContext
	Timestamp    uint64
	CycleCount   uint32
	LastIType    ocsd.InstrType
	LastISubtype ocsd.InstrSubtype

	FlagBits uint32

	Payload struct {
		ExceptionNum  uint32
		TraceEvent    TraceEvent
		TraceOnReason TraceOnReason
		SWTraceInfo   ocsd.SWTInfo
		NumInstrRange uint32
		UnsyncEOTInfo UnsyncInfo
		SyncMarker    TraceMarkerPayload
		MemTrans      TraceMemtrans
		SWIte         TraceSWIte
		SWTItm        SWTItmInfo
	}

	PtrExtendedData []byte
}

func (e *TraceElement) LastInstrExec() bool { return (e.FlagBits & (1 << 0)) != 0 }
func (e *TraceElement) SetLastInstrExec(v bool) {
	if v {
		e.FlagBits |= (1 << 0)
	} else {
		e.FlagBits &^= (1 << 0)
	}
}

func (e *TraceElement) LastInstrSz() uint8 { return uint8((e.FlagBits >> 1) & 0x7) }
func (e *TraceElement) SetLastInstrSz(v uint8) {
	e.FlagBits = (e.FlagBits &^ (0x7 << 1)) | ((uint32(v) & 0x7) << 1)
}

func (e *TraceElement) HasCC() bool { return (e.FlagBits & (1 << 4)) != 0 }
func (e *TraceElement) SetHasCC(v bool) {
	if v {
		e.FlagBits |= (1 << 4)
	} else {
		e.FlagBits &^= (1 << 4)
	}
}

func (e *TraceElement) CPUFreqChange() bool { return (e.FlagBits & (1 << 5)) != 0 }
func (e *TraceElement) SetCPUFreqChange(v bool) {
	if v {
		e.FlagBits |= (1 << 5)
	} else {
		e.FlagBits &^= (1 << 5)
	}
}

func (e *TraceElement) ExcepRetAddr() bool { return (e.FlagBits & (1 << 6)) != 0 }
func (e *TraceElement) SetExcepRetAddr(v bool) {
	if v {
		e.FlagBits |= (1 << 6)
	} else {
		e.FlagBits &^= (1 << 6)
	}
}

func (e *TraceElement) ExcepDataMarker() bool { return (e.FlagBits & (1 << 7)) != 0 }
func (e *TraceElement) SetExcepDataMarker(v bool) {
	if v {
		e.FlagBits |= (1 << 7)
	} else {
		e.FlagBits &^= (1 << 7)
	}
}

func (e *TraceElement) ExtendedData() bool { return (e.FlagBits & (1 << 8)) != 0 }
func (e *TraceElement) SetExtendedData(v bool) {
	if v {
		e.FlagBits |= (1 << 8)
	} else {
		e.FlagBits &^= (1 << 8)
	}
}

func (e *TraceElement) HasTS() bool { return (e.FlagBits & (1 << 9)) != 0 }
func (e *TraceElement) SetHasTS(v bool) {
	if v {
		e.FlagBits |= (1 << 9)
	} else {
		e.FlagBits &^= (1 << 9)
	}
}

func (e *TraceElement) LastInstrCond() bool { return (e.FlagBits & (1 << 10)) != 0 }
func (e *TraceElement) SetLastInstrCond(v bool) {
	if v {
		e.FlagBits |= (1 << 10)
	} else {
		e.FlagBits &^= (1 << 10)
	}
}

func (e *TraceElement) ExcepRetAddrBrTgt() bool { return (e.FlagBits & (1 << 11)) != 0 }
func (e *TraceElement) SetExcepRetAddrBrTgt(v bool) {
	if v {
		e.FlagBits |= (1 << 11)
	} else {
		e.FlagBits &^= (1 << 11)
	}
}

func (e *TraceElement) ExcepMTailChain() bool { return (e.FlagBits & (1 << 12)) != 0 }
func (e *TraceElement) SetExcepMTailChain(v bool) {
	if v {
		e.FlagBits |= (1 << 12)
	} else {
		e.FlagBits &^= (1 << 12)
	}
}

// Construct with default state
func NewTraceElement() *TraceElement {
	te := &TraceElement{}
	te.Init()
	return te
}

func NewTraceElementWithType(typ GenElemType) *TraceElement {
	te := &TraceElement{}
	te.Init()
	te.ElemType = typ
	return te
}

func (e *TraceElement) Init() {
	e.StAddr = ^ocsd.VAddr(0) // -1
	e.EnAddr = ^ocsd.VAddr(0) // -1
	e.ISA = ocsd.ISAUnknown

	e.CycleCount = 0
	e.Timestamp = 0

	e.Context.SetCtxtIDValid(false)
	e.Context.SetVMIDValid(false)
	e.Context.SetELValid(false)

	e.LastIType = ocsd.InstrOther
	e.LastISubtype = ocsd.SInstrNone

	e.clearPerPktData()
}

func (e *TraceElement) clearPerPktData() {
	e.FlagBits = 0
	e.Payload = struct {
		ExceptionNum  uint32
		TraceEvent    TraceEvent
		TraceOnReason TraceOnReason
		SWTraceInfo   ocsd.SWTInfo
		NumInstrRange uint32
		UnsyncEOTInfo UnsyncInfo
		SyncMarker    TraceMarkerPayload
		MemTrans      TraceMemtrans
		SWIte         TraceSWIte
		SWTItm        SWTItmInfo
	}{}
	e.PtrExtendedData = nil
}

// set elements API
func (e *TraceElement) SetType(typ GenElemType) {
	e.ElemType = typ
	e.clearPerPktData()
}

func (e *TraceElement) UpdateType(typ GenElemType) {
	e.ElemType = typ
}

func (e *TraceElement) SetContext(newCtx ocsd.PEContext) {
	e.Context = newCtx
}

func (e *TraceElement) SetISA(isa ocsd.ISA) {
	e.ISA = isa
	if e.ISA > ocsd.ISAUnknown {
		e.ISA = ocsd.ISAUnknown
	}
}

func (e *TraceElement) SetCycleCount(cycleCount uint32) {
	e.CycleCount = cycleCount
	e.SetHasCC(true)
}

func (e *TraceElement) SetEvent(evType EventType, number uint16) {
	e.Payload.TraceEvent.EvType = evType
	if evType == EventNumbered {
		e.Payload.TraceEvent.EvNumber = number
	} else {
		e.Payload.TraceEvent.EvNumber = 0
	}
}

func (e *TraceElement) SetTS(ts uint64, freqChange bool) {
	e.Timestamp = ts
	e.SetCPUFreqChange(freqChange)
	e.SetHasTS(true)
}

func (e *TraceElement) SetExcepMarker() {
	e.SetExcepDataMarker(true)
}

func (e *TraceElement) SetExceptionNum(excepNum uint32) {
	e.Payload.ExceptionNum = excepNum
}

func (e *TraceElement) SetTraceOnReason(reason TraceOnReason) {
	e.Payload.TraceOnReason = reason
}

func (e *TraceElement) SetUnSyncEOTReason(reason UnsyncInfo) {
	e.Payload.UnsyncEOTInfo = reason
}

func (e *TraceElement) SetTransactionType(trans TraceMemtrans) {
	e.Payload.MemTrans = trans
}

func (e *TraceElement) SetAddrRange(stAddr, enAddr ocsd.VAddr, numInstr uint32) {
	e.StAddr = stAddr
	e.EnAddr = enAddr
	e.Payload.NumInstrRange = numInstr
}

func (e *TraceElement) SetLastInstrInfo(exec bool, lastIType ocsd.InstrType, lastISubtype ocsd.InstrSubtype, size uint8) {
	e.SetLastInstrExec(exec)
	e.SetLastInstrSz(size & 0x7)
	e.LastIType = lastIType
	e.LastISubtype = lastISubtype
}

func (e *TraceElement) SetAddrStart(stAddr ocsd.VAddr) {
	e.StAddr = stAddr
}

func (e *TraceElement) SetSWTInfo(swtInfo ocsd.SWTInfo) {
	e.Payload.SWTraceInfo = swtInfo
}

func (e *TraceElement) SetExtendedDataPtr(data []byte) {
	e.SetExtendedData(true)
	e.PtrExtendedData = data
}

func (e *TraceElement) SetITEInfo(swInstrumentation TraceSWIte) {
	e.Payload.SWIte = swInstrumentation
}

func (e *TraceElement) SetSWTITMInfo(itmInfo SWTItmInfo) {
	e.Payload.SWTItm = itmInfo
}

func (e *TraceElement) SetSyncMarker(marker TraceMarkerPayload) {
	e.Payload.SyncMarker = marker
}

func (e *TraceElement) CopyPersistentData(src *TraceElement) {
	e.ISA = src.ISA
	e.Context = src.Context
}

var sElemDescs = map[GenElemType]string{
	GenElemUnknown:         "OCSD_GEN_TRC_ELEM_UNKNOWN",
	GenElemNoSync:          "OCSD_GEN_TRC_ELEM_NO_SYNC",
	GenElemTraceOn:         "OCSD_GEN_TRC_ELEM_TRACE_ON",
	GenElemEOTrace:         "OCSD_GEN_TRC_ELEM_EO_TRACE",
	GenElemPeContext:       "OCSD_GEN_TRC_ELEM_PE_CONTEXT",
	GenElemInstrRange:      "OCSD_GEN_TRC_ELEM_INSTR_RANGE",
	GenElemIRangeNopath:    "OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH",
	GenElemAddrNacc:        "OCSD_GEN_TRC_ELEM_ADDR_NACC",
	GenElemAddrUnknown:     "OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN",
	GenElemException:       "OCSD_GEN_TRC_ELEM_EXCEPTION",
	GenElemExceptionRet:    "OCSD_GEN_TRC_ELEM_EXCEPTION_RET",
	GenElemTimestamp:       "OCSD_GEN_TRC_ELEM_TIMESTAMP",
	GenElemCycleCount:      "OCSD_GEN_TRC_ELEM_CYCLE_COUNT",
	GenElemEvent:           "OCSD_GEN_TRC_ELEM_EVENT",
	GenElemSWTrace:         "OCSD_GEN_TRC_ELEM_SWTRACE",
	GenElemSyncMarker:      "OCSD_GEN_TRC_ELEM_SYNC_MARKER",
	GenElemMemTrans:        "OCSD_GEN_TRC_ELEM_MEMTRANS",
	GenElemInstrumentation: "OCSD_GEN_TRC_ELEM_INSTRUMENTATION",
	GenElemITMTrace:        "OCSD_GEN_TRC_ELEM_ITMTRACE",
	GenElemCustom:          "OCSD_GEN_TRC_ELEM_CUSTOM",
}

var instrTypeStr = map[ocsd.InstrType]string{
	ocsd.InstrOther:      "--- ",
	ocsd.InstrBr:         "BR  ",
	ocsd.InstrBrIndirect: "iBR ",
	ocsd.InstrIsb:        "ISB ",
	ocsd.InstrDsbDmb:     "DSB.DMB",
	ocsd.InstrWfiWfe:     "WFI.WFE",
	ocsd.InstrTstart:     "TSTART",
}

var instrSubtypeStr = map[ocsd.InstrSubtype]string{
	ocsd.SInstrNone:         "--- ",
	ocsd.SInstrBrLink:       "b+link ",
	ocsd.SInstrV8Ret:        "A64:ret ",
	ocsd.SInstrV8Eret:       "A64:eret ",
	ocsd.SInstrV7ImpliedRet: "V7:impl ret",
}

var traceOnStr = map[TraceOnReason]string{
	TraceOnNormal:   "begin or filter",
	TraceOnOverflow: "overflow",
	TraceOnExDebug:  "debug restart",
}

var isaStr = map[ocsd.ISA]string{
	ocsd.ISAArm:     "A32",
	ocsd.ISAThumb2:  "T32",
	ocsd.ISAAArch64: "A64",
	ocsd.ISATee:     "TEE",
	ocsd.ISAJazelle: "Jaz",
	ocsd.ISACustom:  "Cst",
	ocsd.ISAUnknown: "Unk",
}

var unsyncStr = map[UnsyncInfo]string{
	UnsyncUnknown:      "undefined",
	UnsyncInitDecoder:  "init-decoder",
	UnsyncResetDecoder: "reset-decoder",
	UnsyncOverflow:     "overflow",
	UnsyncDiscard:      "discard",
	UnsyncBadPacket:    "bad-packet",
	UnsyncBadImage:     "bad-program-image",
	UnsyncEOT:          "end-of-trace",
}

var transTypeStr = map[TraceMemtrans]string{
	MemTransTraceInit: "Init",
	MemTransStart:     "Start",
	MemTransCommit:    "Commit",
	MemTransFail:      "Fail",
}

var markerTypeStr = map[TraceSyncMarker]string{
	ElemMarkerTS: "Timestamp marker",
}

// String implements OcsdTraceElement::toString
func (e *TraceElement) String() string {
	var sb strings.Builder

	desc, ok := sElemDescs[e.ElemType]
	if !ok {
		return "OCSD_GEN_TRC_ELEM??: index out of range."
	}
	sb.WriteString(desc)
	sb.WriteString("(")

	switch e.ElemType {
	case GenElemInstrRange:
		sb.WriteString(fmt.Sprintf("exec range=0x%x:[0x%x] ", e.StAddr, e.EnAddr))
		sb.WriteString(fmt.Sprintf("num_i(%d) ", e.Payload.NumInstrRange))
		sb.WriteString(fmt.Sprintf("last_sz(%d) ", e.LastInstrSz()))
		sb.WriteString(fmt.Sprintf("(ISA=%s) ", isaStr[e.ISA]))
		if e.LastInstrExec() {
			sb.WriteString("E ")
		} else {
			sb.WriteString("N ")
		}
		if s, ok := instrTypeStr[e.LastIType]; ok {
			sb.WriteString(s)
		}
		if e.LastISubtype != ocsd.SInstrNone {
			if s, ok := instrSubtypeStr[e.LastISubtype]; ok {
				sb.WriteString(s)
			}
		}
		if e.LastInstrCond() {
			sb.WriteString(" <cond>")
		}

	case GenElemAddrNacc:
		var strEx string
		switch ocsd.MemSpaceAcc(e.Payload.ExceptionNum) {
		case ocsd.MemSpaceEL1S:
			strEx = "EL1S"
		case ocsd.MemSpaceEL1N:
			strEx = "EL1N"
		case ocsd.MemSpaceEL2:
			strEx = "EL2"
		case ocsd.MemSpaceEL3:
			strEx = "EL3"
		case ocsd.MemSpaceEL2S:
			strEx = "EL2S"
		case ocsd.MemSpaceEL1R:
			strEx = "EL1R"
		case ocsd.MemSpaceEL2R:
			strEx = "EL2R"
		case ocsd.MemSpaceRoot:
			strEx = "Root"
		case ocsd.MemSpaceS:
			strEx = "S"
		case ocsd.MemSpaceN:
			strEx = "N"
		case ocsd.MemSpaceR:
			strEx = "R"
		case ocsd.MemSpaceAny:
			strEx = "Any"
		case ocsd.MemSpaceNone:
			strEx = "None"
		}
		sb.WriteString(fmt.Sprintf(" 0x%x; Memspace [0x%x:%s] ", e.StAddr, e.Payload.ExceptionNum, strEx))

	case GenElemIRangeNopath:
		sb.WriteString(fmt.Sprintf("first 0x%x:[next 0x%x] ", e.StAddr, e.EnAddr))
		sb.WriteString(fmt.Sprintf("num_i(%d) ", e.Payload.NumInstrRange))

	case GenElemException:
		if e.ExcepRetAddr() {
			sb.WriteString(fmt.Sprintf("pref ret addr:0x%x", e.EnAddr))
			if e.ExcepRetAddrBrTgt() {
				sb.WriteString(" [addr also prev br tgt]")
			}
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("excep num (0x%02x) ", e.Payload.ExceptionNum))

	case GenElemPeContext:
		sb.WriteString(fmt.Sprintf("(ISA=%s) ", isaStr[e.ISA]))
		if e.Context.ExceptionLevel > ocsd.ELUnknown && e.Context.ELValid() {
			sb.WriteString(fmt.Sprintf("EL%d", e.Context.ExceptionLevel))
		}
		switch e.Context.SecurityLevel {
		case ocsd.SecSecure:
			sb.WriteString("S; ")
		case ocsd.SecNonsecure:
			sb.WriteString("N; ")
		case ocsd.SecRoot:
			sb.WriteString("Root; ")
		case ocsd.SecRealm:
			sb.WriteString("Realm; ")
		}
		if e.Context.Bits64() {
			sb.WriteString("64-bit; ")
		} else {
			sb.WriteString("32-bit; ")
		}
		if e.Context.VMIDValid() {
			sb.WriteString(fmt.Sprintf("VMID=0x%x; ", e.Context.VMID))
		}
		if e.Context.CtxtIDValid() {
			sb.WriteString(fmt.Sprintf("CTXTID=0x%x; ", e.Context.ContextID))
		}

	case GenElemTraceOn:
		if s, ok := traceOnStr[e.Payload.TraceOnReason]; ok {
			sb.WriteString(fmt.Sprintf(" [%s]", s))
		}

	case GenElemTimestamp:
		sb.WriteString(fmt.Sprintf(" [ TS=0x%012x]; ", e.Timestamp))

	case GenElemSWTrace:
		e.printSWInfoPkt(&sb)

	case GenElemITMTrace:
		e.printSWInfoPktItm(&sb)

	case GenElemEvent:
		if e.Payload.TraceEvent.EvType == EventTrigger {
			sb.WriteString(" Trigger; ")
		} else if e.Payload.TraceEvent.EvType == EventNumbered {
			sb.WriteString(fmt.Sprintf(" Numbered:%d; ", e.Payload.TraceEvent.EvNumber))
		}

	case GenElemEOTrace, GenElemNoSync:
		if e.Payload.UnsyncEOTInfo <= UnsyncEOT {
			sb.WriteString(fmt.Sprintf(" [%s]", unsyncStr[e.Payload.UnsyncEOTInfo]))
		}

	case GenElemSyncMarker:
		typ := e.Payload.SyncMarker.Type
		if s, ok := markerTypeStr[typ]; ok {
			sb.WriteString(fmt.Sprintf(" [%s(0x%08x)]", s, e.Payload.SyncMarker.Value))
		}

	case GenElemMemTrans:
		if s, ok := transTypeStr[e.Payload.MemTrans]; ok {
			sb.WriteString(s)
		}

	case GenElemInstrumentation:
		sb.WriteString(fmt.Sprintf("EL%d; 0x%016x", e.Payload.SWIte.EL, e.Payload.SWIte.Value))
	}

	if e.HasCC() {
		sb.WriteString(fmt.Sprintf(" [CC=%d]; ", e.CycleCount))
	}

	sb.WriteString(")")
	return sb.String()
}

func (e *TraceElement) printSWInfoPkt(sb *strings.Builder) {
	info := e.Payload.SWTraceInfo
	if !info.GlobalErr() {
		if info.IDValid() {
			sb.WriteString(fmt.Sprintf(" (Ma:0x%02x; Ch:0x%02x) ", info.MasterID, info.ChannelID))
		} else {
			sb.WriteString("(Ma:0x??; Ch:0x??) ")
		}

		if info.PayloadPktBitsize() > 0 && len(e.PtrExtendedData) > 0 {
			sb.WriteString("0x")
			switch info.PayloadPktBitsize() {
			case 4:
				sb.WriteString(fmt.Sprintf("%x", e.PtrExtendedData[0]&0xF))
			case 8:
				sb.WriteString(fmt.Sprintf("%02x", e.PtrExtendedData[0]))
			case 16:
				if len(e.PtrExtendedData) >= 2 {
					val := uint16(e.PtrExtendedData[0]) | (uint16(e.PtrExtendedData[1]) << 8)
					sb.WriteString(fmt.Sprintf("%04x", val))
				}
			case 32:
				if len(e.PtrExtendedData) >= 4 {
					val := uint32(e.PtrExtendedData[0]) | (uint32(e.PtrExtendedData[1]) << 8) | (uint32(e.PtrExtendedData[2]) << 16) | (uint32(e.PtrExtendedData[3]) << 24)
					sb.WriteString(fmt.Sprintf("%08x", val))
				}
			case 64:
				if len(e.PtrExtendedData) >= 8 {
					val := uint64(e.PtrExtendedData[0]) | (uint64(e.PtrExtendedData[1]) << 8) | (uint64(e.PtrExtendedData[2]) << 16) | (uint64(e.PtrExtendedData[3]) << 24) |
						(uint64(e.PtrExtendedData[4]) << 32) | (uint64(e.PtrExtendedData[5]) << 40) | (uint64(e.PtrExtendedData[6]) << 48) | (uint64(e.PtrExtendedData[7]) << 56)
					sb.WriteString(fmt.Sprintf("%016x", val))
				}
			default:
				sb.WriteString("{Data Error : unsupported bit width.}")
			}
			sb.WriteString("; ")
		}

		if info.MarkerPacket() {
			sb.WriteString("+Mrk ")
		}
		if info.TriggerEvent() {
			sb.WriteString("Trig ")
		}
		if info.HasTimestamp() {
			sb.WriteString(fmt.Sprintf(" [ TS=0x%012x]; ", e.Timestamp))
		}
		if info.Frequency() {
			sb.WriteString("Freq")
		}
		if info.MasterErr() {
			sb.WriteString("{Master Error.}")
		}
	} else {
		sb.WriteString("{Global Error.}")
	}
}

func (e *TraceElement) printSWInfoPktItm(sb *strings.Builder) {
	itm := e.Payload.SWTItm

	if itm.Overflow != 0 {
		sb.WriteString("ITM_OVERFLOW; ")
	}

	var tsLocalDesc string

	switch itm.PktType {
	case SWITPayload:
		width := int(itm.PayloadSize) * 2
		sb.WriteString(fmt.Sprintf("ITM_SWIT (ch: 0x%x; Data: 0x%0*x) ", itm.PayloadSrcID, width, itm.Value))
	case DWTPayload:
		width := int(itm.PayloadSize) * 2
		sb.WriteString(fmt.Sprintf("ITM_DWT (desc: 0x%x; Data: 0x%0*x) ", itm.PayloadSrcID, width, itm.Value))
	case TSGlobal:
		sb.WriteString(fmt.Sprintf("ITM_TS_GLOBAL ( TS: 0x%016x) ", e.Timestamp))
	case TSSync:
		tsLocalDesc = "TS Sync"
	case TSDelay:
		tsLocalDesc = "TS Delay"
	case TSPKTDelay:
		tsLocalDesc = "Packet Delay"
	case TSPKTTSDelay:
		tsLocalDesc = "TS and Packet Delay"
	}

	if tsLocalDesc != "" {
		sb.WriteString(fmt.Sprintf("ITM_TS_LOCAL ( TS delta: 0x%08x, { %s}; ", itm.Value, tsLocalDesc))
		sb.WriteString(fmt.Sprintf("TS cumulative: 0x%x) ", e.Timestamp))
	}
}
