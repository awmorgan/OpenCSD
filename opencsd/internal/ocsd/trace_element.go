package ocsd

import (
	"fmt"
	"strings"
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
	Index            TrcIndex
	TraceID          uint8
	ElemType         GenElemType
	ISA              ISA
	StartAddr        VAddr
	EndAddr          VAddr
	Context          PEContext
	Timestamp        uint64
	CycleCount       uint32
	LastInstrType    InstrType
	LastInstrSubtype InstrSubtype

	LastInstrExecuted     bool
	LastInstrSize         uint8
	HasCC                 bool
	CPUFreqChange         bool
	ExceptionRetAddr      bool
	ExceptionDataMarker   bool
	ExtendedData          bool
	HasTS                 bool
	LastInstrCond         bool
	ExceptionRetAddrBrTgt bool
	ExceptionMTailChain   bool

	Payload struct {
		ExceptionNum  uint32
		TraceEvent    TraceEvent
		TraceOnReason TraceOnReason
		SWTraceInfo   SWTInfo
		NumInstrRange uint32
		UnsyncEOTInfo UnsyncInfo
		SyncMarker    TraceMarkerPayload
		MemTrans      TraceMemtrans
		SWIte         TraceSWIte
		SWTItm        SWTItmInfo
	}

	PtrExtendedData []byte
}

func (e *TraceElement) clearPerPktData() {
	e.LastInstrExecuted = false
	e.LastInstrSize = 0
	e.HasCC = false
	e.CPUFreqChange = false
	e.ExceptionRetAddr = false
	e.ExceptionDataMarker = false
	e.ExtendedData = false
	e.HasTS = false
	e.LastInstrCond = false
	e.ExceptionRetAddrBrTgt = false
	e.ExceptionMTailChain = false

	e.Payload = struct {
		ExceptionNum  uint32
		TraceEvent    TraceEvent
		TraceOnReason TraceOnReason
		SWTraceInfo   SWTInfo
		NumInstrRange uint32
		UnsyncEOTInfo UnsyncInfo
		SyncMarker    TraceMarkerPayload
		MemTrans      TraceMemtrans
		SWIte         TraceSWIte
		SWTItm        SWTItmInfo
	}{}
	e.PtrExtendedData = nil
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
	e.StartAddr = ^VAddr(0) // -1
	e.EndAddr = ^VAddr(0)   // -1
	e.ISA = ISAUnknown

	e.CycleCount = 0
	e.Timestamp = 0

	e.Context.SetCtxtIDValid(false)
	e.Context.SetVMIDValid(false)
	e.Context.SetELValid(false)

	e.LastInstrType = InstrOther
	e.LastInstrSubtype = SInstrNone

	e.clearPerPktData()
}

// set elements API
func (e *TraceElement) SetType(typ GenElemType) {
	e.ElemType = typ
	e.clearPerPktData()
}

func (e *TraceElement) UpdateType(typ GenElemType) {
	e.ElemType = typ
}

func (e *TraceElement) SetContext(newCtx PEContext) {
	e.Context = newCtx
}

func (e *TraceElement) SetISA(isa ISA) {
	e.ISA = min(isa, ISAUnknown)
}

func (e *TraceElement) SetCycleCount(cycleCount uint32) {
	e.CycleCount = cycleCount
	e.HasCC = true
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
	e.CPUFreqChange = freqChange
	e.HasTS = true
}

func (e *TraceElement) SetExcepMarker() {
	e.ExceptionDataMarker = true
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

func (e *TraceElement) SetAddrRange(stAddr, enAddr VAddr, numInstr uint32) {
	e.StartAddr = stAddr
	e.EndAddr = enAddr
	e.Payload.NumInstrRange = numInstr
}

func (e *TraceElement) SetLastInstrInfo(exec bool, lastIType InstrType, lastISubtype InstrSubtype, size uint8) {
	e.LastInstrExecuted = exec
	e.LastInstrSize = size & 0x7
	e.LastInstrType = lastIType
	e.LastInstrSubtype = lastISubtype
}

func (e *TraceElement) SetAddrStart(stAddr VAddr) {
	e.StartAddr = stAddr
}

func (e *TraceElement) SetSWTInfo(swtInfo SWTInfo) {
	e.Payload.SWTraceInfo = swtInfo
}

func (e *TraceElement) SetExtendedDataPtr(data []byte) {
	e.ExtendedData = true
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

var elemDescs = map[GenElemType]string{
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

var instrTypeNames = map[InstrType]string{
	InstrOther:      "--- ",
	InstrBr:         "BR  ",
	InstrBrIndirect: "iBR ",
	InstrIsb:        "ISB ",
	InstrDsbDmb:     "DSB.DMB",
	InstrWfiWfe:     "WFI.WFE",
	InstrTstart:     "TSTART",
}

var instrSubtypeNames = map[InstrSubtype]string{
	SInstrNone:         "--- ",
	SInstrBrLink:       "b+link ",
	SInstrV8Ret:        "A64:ret ",
	SInstrV8Eret:       "A64:eret ",
	SInstrV7ImpliedRet: "V7:impl ret",
}

var traceOnNames = map[TraceOnReason]string{
	TraceOnNormal:   "begin or filter",
	TraceOnOverflow: "overflow",
	TraceOnExDebug:  "debug restart",
}

var isaNames = map[ISA]string{
	ISAArm:     "A32",
	ISAThumb2:  "T32",
	ISAAArch64: "A64",
	ISATee:     "TEE",
	ISAJazelle: "Jaz",
	ISACustom:  "Cst",
	ISAUnknown: "Unk",
}

var unsyncNames = map[UnsyncInfo]string{
	UnsyncUnknown:      "undefined",
	UnsyncInitDecoder:  "init-decoder",
	UnsyncResetDecoder: "reset-decoder",
	UnsyncOverflow:     "overflow",
	UnsyncDiscard:      "discard",
	UnsyncBadPacket:    "bad-packet",
	UnsyncBadImage:     "bad-program-image",
	UnsyncEOT:          "end-of-trace",
}

var transTypeNames = map[TraceMemtrans]string{
	MemTransTraceInit: "Init",
	MemTransStart:     "Start",
	MemTransCommit:    "Commit",
	MemTransFail:      "Fail",
}

var markerTypeNames = map[TraceSyncMarker]string{
	ElemMarkerTS: "Timestamp marker",
}

func traceElemMemSpaceString(memSpace MemSpaceAcc) string {
	switch memSpace {
	case MemSpaceNone:
		return "None"
	case MemSpaceEL1S:
		return "EL1S"
	case MemSpaceEL1N:
		return "EL1N"
	case MemSpaceEL2:
		return "EL2N"
	case MemSpaceEL3:
		return "EL3"
	case MemSpaceEL2S:
		return "EL2S"
	case MemSpaceEL1R:
		return "EL1R"
	case MemSpaceEL2R:
		return "EL2R"
	case MemSpaceRoot:
		return "Root"
	case MemSpaceS:
		return "Any S"
	case MemSpaceN:
		return "Any NS"
	case MemSpaceR:
		return "Any R"
	case MemSpaceAny:
		return "Any"
	default:
		var parts []string
		msBits := uint8(memSpace)
		if msBits&uint8(MemSpaceEL1S) != 0 {
			parts = append(parts, "EL1S")
		}
		if msBits&uint8(MemSpaceEL1N) != 0 {
			parts = append(parts, "EL1N")
		}
		if msBits&uint8(MemSpaceEL2) != 0 {
			parts = append(parts, "EL2N")
		}
		if msBits&uint8(MemSpaceEL3) != 0 {
			parts = append(parts, "EL3")
		}
		if msBits&uint8(MemSpaceEL2S) != 0 {
			parts = append(parts, "EL2S")
		}
		if msBits&uint8(MemSpaceEL1R) != 0 {
			parts = append(parts, "EL1R")
		}
		if msBits&uint8(MemSpaceEL2R) != 0 {
			parts = append(parts, "EL2R")
		}
		if msBits&uint8(MemSpaceRoot) != 0 {
			parts = append(parts, "Root")
		}
		return strings.Join(parts, ",")
	}
}

// String implements OcsdTraceElement::toString
func (e *TraceElement) String() string {
	var sb strings.Builder

	desc, ok := elemDescs[e.ElemType]
	if !ok {
		return "OCSD_GEN_TRC_ELEM??: index out of range."
	}
	sb.WriteString(desc)
	sb.WriteString("(")

	switch e.ElemType {
	case GenElemInstrRange:
		fmt.Fprintf(&sb, "exec range=0x%x:[0x%x] ", e.StartAddr, e.EndAddr)
		fmt.Fprintf(&sb, "num_i(%d) ", e.Payload.NumInstrRange)
		fmt.Fprintf(&sb, "last_sz(%d) ", e.LastInstrSize)
		fmt.Fprintf(&sb, "(ISA=%s) ", isaNames[e.ISA])
		if e.LastInstrExecuted {
			sb.WriteString("E ")
		} else {
			sb.WriteString("N ")
		}
		if s, ok := instrTypeNames[e.LastInstrType]; ok {
			sb.WriteString(s)
		}
		if e.LastInstrSubtype != SInstrNone {
			if s, ok := instrSubtypeNames[e.LastInstrSubtype]; ok {
				sb.WriteString(s)
			}
		}
		if e.LastInstrCond {
			sb.WriteString(" <cond>")
		}

	case GenElemAddrNacc:
		strEx := traceElemMemSpaceString(MemSpaceAcc(e.Payload.ExceptionNum))
		fmt.Fprintf(&sb, " 0x%x; Memspace [0x%x:%s] ", e.StartAddr, e.Payload.ExceptionNum, strEx)

	case GenElemIRangeNopath:
		fmt.Fprintf(&sb, "first 0x%x:[next 0x%x] ", e.StartAddr, e.EndAddr)
		fmt.Fprintf(&sb, "num_i(%d) ", e.Payload.NumInstrRange)

	case GenElemException:
		if e.ExceptionRetAddr {
			fmt.Fprintf(&sb, "pref ret addr:0x%x", e.EndAddr)
			if e.ExceptionRetAddrBrTgt {
				sb.WriteString(" [addr also prev br tgt]")
			}
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "excep num (0x%02x) ", e.Payload.ExceptionNum)

	case GenElemPeContext:
		fmt.Fprintf(&sb, "(ISA=%s) ", isaNames[e.ISA])
		if e.Context.ExceptionLevel > ELUnknown && e.Context.ELValid() {
			fmt.Fprintf(&sb, "EL%d", e.Context.ExceptionLevel)
		}
		switch e.Context.SecurityLevel {
		case SecSecure:
			sb.WriteString("S; ")
		case SecNonsecure:
			sb.WriteString("N; ")
		case SecRoot:
			sb.WriteString("Root; ")
		case SecRealm:
			sb.WriteString("Realm; ")
		}
		if e.Context.Bits64() {
			sb.WriteString("64-bit; ")
		} else {
			sb.WriteString("32-bit; ")
		}
		if e.Context.VMIDValid() {
			fmt.Fprintf(&sb, "VMID=0x%x; ", e.Context.VMID)
		}
		if e.Context.CtxtIDValid() {
			fmt.Fprintf(&sb, "CTXTID=0x%x; ", e.Context.ContextID)
		}

	case GenElemTraceOn:
		if s, ok := traceOnNames[e.Payload.TraceOnReason]; ok {
			fmt.Fprintf(&sb, " [%s]", s)
		}

	case GenElemTimestamp:
		fmt.Fprintf(&sb, " [ TS=0x%012x]; ", e.Timestamp)

	case GenElemSWTrace:
		e.printSWInfoPkt(&sb)

	case GenElemITMTrace:
		e.printSWInfoPktItm(&sb)

	case GenElemEvent:
		switch e.Payload.TraceEvent.EvType {
		case EventTrigger:
			sb.WriteString(" Trigger; ")
		case EventNumbered:
			fmt.Fprintf(&sb, " Numbered:%d; ", e.Payload.TraceEvent.EvNumber)
		}

	case GenElemEOTrace, GenElemNoSync:
		if e.Payload.UnsyncEOTInfo <= UnsyncEOT {
			fmt.Fprintf(&sb, " [%s]", unsyncNames[e.Payload.UnsyncEOTInfo])
		}

	case GenElemSyncMarker:
		typ := e.Payload.SyncMarker.Type
		if s, ok := markerTypeNames[typ]; ok {
			fmt.Fprintf(&sb, " [%s(0x%08x)]", s, e.Payload.SyncMarker.Value)
		}

	case GenElemMemTrans:
		if s, ok := transTypeNames[e.Payload.MemTrans]; ok {
			sb.WriteString(s)
		}

	case GenElemInstrumentation:
		fmt.Fprintf(&sb, "EL%d; 0x%016x", e.Payload.SWIte.EL, e.Payload.SWIte.Value)
	}

	if e.HasCC {
		fmt.Fprintf(&sb, " [CC=%d]; ", e.CycleCount)
	}

	sb.WriteString(")")
	return sb.String()
}

func (e *TraceElement) printSWInfoPkt(sb *strings.Builder) {
	info := e.Payload.SWTraceInfo
	if !info.GlobalErr() {
		if info.IDValid() {
			fmt.Fprintf(sb, " (Ma:0x%02x; Ch:0x%02x) ", info.MasterID, info.ChannelID)
		} else {
			sb.WriteString("(Ma:0x??; Ch:0x??) ")
		}

		if info.PayloadPktBitsize() > 0 && len(e.PtrExtendedData) > 0 {
			sb.WriteString("0x")
			switch info.PayloadPktBitsize() {
			case 4:
				fmt.Fprintf(sb, "%x", e.PtrExtendedData[0]&0xF)
			case 8:
				fmt.Fprintf(sb, "%02x", e.PtrExtendedData[0])
			case 16:
				if len(e.PtrExtendedData) >= 2 {
					val := uint16(e.PtrExtendedData[0]) | (uint16(e.PtrExtendedData[1]) << 8)
					fmt.Fprintf(sb, "%04x", val)
				}
			case 32:
				if len(e.PtrExtendedData) >= 4 {
					val := uint32(e.PtrExtendedData[0]) | (uint32(e.PtrExtendedData[1]) << 8) | (uint32(e.PtrExtendedData[2]) << 16) | (uint32(e.PtrExtendedData[3]) << 24)
					fmt.Fprintf(sb, "%08x", val)
				}
			case 64:
				if len(e.PtrExtendedData) >= 8 {
					val := uint64(e.PtrExtendedData[0]) | (uint64(e.PtrExtendedData[1]) << 8) | (uint64(e.PtrExtendedData[2]) << 16) | (uint64(e.PtrExtendedData[3]) << 24) |
						(uint64(e.PtrExtendedData[4]) << 32) | (uint64(e.PtrExtendedData[5]) << 40) | (uint64(e.PtrExtendedData[6]) << 48) | (uint64(e.PtrExtendedData[7]) << 56)
					fmt.Fprintf(sb, "%016x", val)
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
			fmt.Fprintf(sb, " [ TS=0x%012x]; ", e.Timestamp)
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
		fmt.Fprintf(sb, "ITM_SWIT (ch: 0x%x; Data: 0x%0*x) ", itm.PayloadSrcID, width, itm.Value)
	case DWTPayload:
		width := int(itm.PayloadSize) * 2
		fmt.Fprintf(sb, "ITM_DWT (desc: 0x%x; Data: 0x%0*x) ", itm.PayloadSrcID, width, itm.Value)
	case TSGlobal:
		fmt.Fprintf(sb, "ITM_TS_GLOBAL ( TS: 0x%016x) ", e.Timestamp)
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
		fmt.Fprintf(sb, "ITM_TS_LOCAL ( TS delta: 0x%08x, { %s}; ", itm.Value, tsLocalDesc)
		fmt.Fprintf(sb, "TS cumulative: 0x%016x) ", e.Timestamp)
	}
}
