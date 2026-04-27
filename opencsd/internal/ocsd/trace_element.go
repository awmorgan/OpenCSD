package ocsd

import (
	"encoding/binary"
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
	e.PtrExtendedData = nil

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
}

// Construct with default state
func NewTraceElement() *TraceElement {
	te := &TraceElement{}
	te.Init()
	return te
}

func NewTraceElementWithType(typ GenElemType) *TraceElement {
	te := NewTraceElement()
	te.ElemType = typ
	return te
}

func (e *TraceElement) Init() {
	e.StartAddr = ^VAddr(0) // -1
	e.EndAddr = ^VAddr(0)   // -1
	e.ISA = ISAUnknown

	e.CycleCount = 0
	e.Timestamp = 0

	e.Context.CtxtIDValid = false
	e.Context.VMIDValid = false
	e.Context.ELValid = false

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
	return memSpace.String()
}

// String implements OcsdTraceElement::toString
func (e *TraceElement) String() string {
	desc, ok := elemDescs[e.ElemType]
	if !ok {
		return "OCSD_GEN_TRC_ELEM??: index out of range."
	}

	var sb strings.Builder
	sb.WriteString(desc)
	sb.WriteByte('(')
	e.writeElementPayload(&sb)
	if e.HasCC {
		fmt.Fprintf(&sb, " [CC=%d]; ", e.CycleCount)
	}
	sb.WriteByte(')')
	return sb.String()
}

func (e *TraceElement) writeElementPayload(sb *strings.Builder) {
	switch e.ElemType {
	case GenElemInstrRange:
		e.writeInstrRange(sb)
	case GenElemAddrNacc:
		space := MemSpaceAcc(e.Payload.ExceptionNum)
		fmt.Fprintf(sb, " 0x%x; Memspace [0x%x:%s] ", e.StartAddr, e.Payload.ExceptionNum, traceElemMemSpaceString(space))
	case GenElemIRangeNopath:
		fmt.Fprintf(sb, "first 0x%x:[next 0x%x] num_i(%d) ", e.StartAddr, e.EndAddr, e.Payload.NumInstrRange)
	case GenElemException:
		e.writeException(sb)
	case GenElemPeContext:
		e.writePEContext(sb)
	case GenElemTraceOn:
		if s, ok := traceOnNames[e.Payload.TraceOnReason]; ok {
			fmt.Fprintf(sb, " [%s]", s)
		}
	case GenElemTimestamp:
		fmt.Fprintf(sb, " [ TS=0x%012x]; ", e.Timestamp)
	case GenElemSWTrace:
		e.printSWInfoPkt(sb)
	case GenElemITMTrace:
		e.printSWInfoPktItm(sb)
	case GenElemEvent:
		e.writeEvent(sb)
	case GenElemEOTrace, GenElemNoSync:
		if s, ok := unsyncNames[e.Payload.UnsyncEOTInfo]; ok {
			fmt.Fprintf(sb, " [%s]", s)
		}
	case GenElemSyncMarker:
		marker := e.Payload.SyncMarker
		if s, ok := markerTypeNames[marker.Type]; ok {
			fmt.Fprintf(sb, " [%s(0x%08x)]", s, marker.Value)
		}
	case GenElemMemTrans:
		if s, ok := transTypeNames[e.Payload.MemTrans]; ok {
			sb.WriteString(s)
		}
	case GenElemInstrumentation:
		fmt.Fprintf(sb, "EL%d; 0x%016x", e.Payload.SWIte.EL, e.Payload.SWIte.Value)
	}
}

func (e *TraceElement) writeInstrRange(sb *strings.Builder) {
	fmt.Fprintf(sb, "exec range=0x%x:[0x%x] ", e.StartAddr, e.EndAddr)
	fmt.Fprintf(sb, "num_i(%d) last_sz(%d) ", e.Payload.NumInstrRange, e.LastInstrSize)
	fmt.Fprintf(sb, "(ISA=%s) ", isaName(e.ISA))
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
}

func (e *TraceElement) writeException(sb *strings.Builder) {
	if e.ExceptionRetAddr {
		fmt.Fprintf(sb, "pref ret addr:0x%x", e.EndAddr)
		if e.ExceptionRetAddrBrTgt {
			sb.WriteString(" [addr also prev br tgt]")
		}
		sb.WriteString("; ")
	}
	fmt.Fprintf(sb, "excep num (0x%02x) ", e.Payload.ExceptionNum)
}

func (e *TraceElement) writePEContext(sb *strings.Builder) {
	fmt.Fprintf(sb, "(ISA=%s) ", isaName(e.ISA))
	if e.Context.ExceptionLevel > ELUnknown && e.Context.ELValid {
		fmt.Fprintf(sb, "EL%d", e.Context.ExceptionLevel)
	}
	sb.WriteString(securityLevelName(e.Context.SecurityLevel))
	if e.Context.Bits64 {
		sb.WriteString("64-bit; ")
	} else {
		sb.WriteString("32-bit; ")
	}
	if e.Context.VMIDValid {
		fmt.Fprintf(sb, "VMID=0x%x; ", e.Context.VMID)
	}
	if e.Context.CtxtIDValid {
		fmt.Fprintf(sb, "CTXTID=0x%x; ", e.Context.ContextID)
	}
}

func (e *TraceElement) writeEvent(sb *strings.Builder) {
	switch e.Payload.TraceEvent.EvType {
	case EventTrigger:
		sb.WriteString(" Trigger; ")
	case EventNumbered:
		fmt.Fprintf(sb, " Numbered:%d; ", e.Payload.TraceEvent.EvNumber)
	}
}

func isaName(isa ISA) string {
	if s, ok := isaNames[isa]; ok {
		return s
	}
	return isaNames[ISAUnknown]
}

func securityLevelName(level SecLevel) string {
	switch level {
	case SecSecure:
		return "S; "
	case SecNonsecure:
		return "N; "
	case SecRoot:
		return "Root; "
	case SecRealm:
		return "Realm; "
	default:
		return ""
	}
}

func (e *TraceElement) printSWInfoPkt(sb *strings.Builder) {
	info := e.Payload.SWTraceInfo
	if info.GlobalErr {
		sb.WriteString("{Global Error.}")
		return
	}

	writeSWTID(sb, info)
	e.writeSWTPayload(sb, info.PayloadPktBitsize)
	writeSWTFlags(sb, info, e.Timestamp)
}

func writeSWTID(sb *strings.Builder, info SWTInfo) {
	if info.IDValid {
		fmt.Fprintf(sb, " (Ma:0x%02x; Ch:0x%02x) ", info.MasterID, info.ChannelID)
		return
	}
	sb.WriteString("(Ma:0x??; Ch:0x??) ")
}

func (e *TraceElement) writeSWTPayload(sb *strings.Builder, bitSize uint8) {
	if bitSize == 0 || len(e.PtrExtendedData) == 0 {
		return
	}

	sb.WriteString("0x")
	switch bitSize {
	case 4:
		fmt.Fprintf(sb, "%x", e.PtrExtendedData[0]&0xF)
	case 8:
		fmt.Fprintf(sb, "%02x", e.PtrExtendedData[0])
	case 16:
		if len(e.PtrExtendedData) >= 2 {
			fmt.Fprintf(sb, "%04x", binary.LittleEndian.Uint16(e.PtrExtendedData))
		}
	case 32:
		if len(e.PtrExtendedData) >= 4 {
			fmt.Fprintf(sb, "%08x", binary.LittleEndian.Uint32(e.PtrExtendedData))
		}
	case 64:
		if len(e.PtrExtendedData) >= 8 {
			fmt.Fprintf(sb, "%016x", binary.LittleEndian.Uint64(e.PtrExtendedData))
		}
	default:
		sb.WriteString("{Data Error : unsupported bit width.}")
	}
	sb.WriteString("; ")
}

func writeSWTFlags(sb *strings.Builder, info SWTInfo, timestamp uint64) {
	if info.MarkerPacket {
		sb.WriteString("+Mrk ")
	}
	if info.TriggerEvent {
		sb.WriteString("Trig ")
	}
	if info.HasTimestamp {
		fmt.Fprintf(sb, " [ TS=0x%012x]; ", timestamp)
	}
	if info.Frequency {
		sb.WriteString("Freq")
	}
	if info.MasterErr {
		sb.WriteString("{Master Error.}")
	}
}

var itmLocalTimestampNames = map[SWTItmType]string{
	TSSync:       "TS Sync",
	TSDelay:      "TS Delay",
	TSPKTDelay:   "Packet Delay",
	TSPKTTSDelay: "TS and Packet Delay",
}

func (e *TraceElement) printSWInfoPktItm(sb *strings.Builder) {
	itm := e.Payload.SWTItm

	if itm.Overflow != 0 {
		sb.WriteString("ITM_OVERFLOW; ")
	}

	switch itm.PktType {
	case SWITPayload:
		fmt.Fprintf(sb, "ITM_SWIT (ch: 0x%x; Data: 0x%0*x) ", itm.PayloadSrcID, int(itm.PayloadSize)*2, itm.Value)
	case DWTPayload:
		fmt.Fprintf(sb, "ITM_DWT (desc: 0x%x; Data: 0x%0*x) ", itm.PayloadSrcID, int(itm.PayloadSize)*2, itm.Value)
	case TSGlobal:
		fmt.Fprintf(sb, "ITM_TS_GLOBAL ( TS: 0x%016x) ", e.Timestamp)
	}

	if desc := itmLocalTimestampNames[itm.PktType]; desc != "" {
		fmt.Fprintf(sb, "ITM_TS_LOCAL ( TS delta: 0x%08x, { %s}; ", itm.Value, desc)
		fmt.Fprintf(sb, "TS cumulative: 0x%016x) ", e.Timestamp)
	}
}
