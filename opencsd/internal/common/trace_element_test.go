package common

import (
	"fmt"
	"opencsd/internal/ocsd"
	"testing"
)

func TestTraceElement_InitAndDefaults(t *testing.T) {
	elem := ocsd.NewTraceElement()

	if elem.ElemType != ocsd.GenElemUnknown {
		t.Errorf("Expected element type %v, got %v", ocsd.GenElemUnknown, elem.ElemType)
	}

	if elem.StartAddr != ^ocsd.VAddr(0) || elem.EndAddr != ^ocsd.VAddr(0) {
		t.Errorf("Expected addresses to be initialized to -1")
	}

	if elem.ISA != ocsd.ISAUnknown {
		t.Errorf("Expected unknown ISA, got %v", elem.ISA)
	}

	elem2 := ocsd.NewTraceElementWithType(ocsd.GenElemTraceOn)
	if elem2.ElemType != ocsd.GenElemTraceOn {
		t.Errorf("Expected type GenElemTraceOn, got %v", elem2.ElemType)
	}
}

func TestTraceElement_Setters(t *testing.T) {
	elem := ocsd.NewTraceElement()

	// Test cycle count
	elem.SetCycleCount(42)
	if elem.CycleCount != 42 || !elem.HasCC {
		t.Errorf("SetCycleCount failed")
	}

	// Test TS
	elem.SetTS(12345678, true)
	if elem.Timestamp != 12345678 || !elem.HasTS || !elem.CPUFreqChange {
		t.Errorf("SetTS failed")
	}

	// Test Event
	elem.SetEvent(ocsd.EventNumbered, 5)
	if elem.Payload.TraceEvent.EvType != ocsd.EventNumbered || elem.Payload.TraceEvent.EvNumber != 5 {
		t.Errorf("SetEvent failed")
	}

	// Test Instr Info
	elem.SetLastInstrInfo(true, ocsd.InstrBr, ocsd.SInstrBrLink, 4)
	if !elem.LastInstrExecuted || elem.LastInstrSize != 4 || elem.LastInstrType != ocsd.InstrBr || elem.LastInstrSubtype != ocsd.SInstrBrLink {
		t.Errorf("SetLastInstrInfo failed")
	}

	// Test Memory Trans
	elem.SetTransactionType(ocsd.MemTransCommit)
	if elem.Payload.MemTrans != ocsd.MemTransCommit {
		t.Errorf("SetTransactionType failed")
	}

	// Test Extended Data
	elem.SetExtendedDataPtr([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if !elem.ExtendedData || len(elem.PtrExtendedData) != 4 {
		t.Errorf("SetExtendedDataPtr failed")
	}

	// Test context
	var ctx ocsd.PEContext
	ctx.SecurityLevel = ocsd.SecSecure
	ctx.ExceptionLevel = ocsd.EL3
	ctx.SetELValid(true)
	elem.SetContext(ctx)
	if elem.Context.SecurityLevel != ocsd.SecSecure || !elem.Context.ELValid() {
		t.Errorf("SetContext failed")
	}

	// Test Addr Range
	elem.SetAddrRange(0x1000, 0x2000, 10)
	if elem.StartAddr != 0x1000 || elem.EndAddr != 0x2000 || elem.Payload.NumInstrRange != 10 {
		t.Errorf("SetAddrRange failed")
	}

	elem.SetAddrStart(0x3000)
	if elem.StartAddr != 0x3000 {
		t.Errorf("SetAddrStart failed")
	}

	elem.LastInstrCond = true
	if !elem.LastInstrCond {
		t.Errorf("SetLastInstrCond failed")
	}

	elem.SetExcepMarker()
	if !elem.ExceptionDataMarker {
		t.Errorf("SetExcepMarker failed")
	}

	elem.SetExceptionNum(0xA)
	if elem.Payload.ExceptionNum != 0xA {
		t.Errorf("SetExceptionNum failed")
	}

	elem.SetTraceOnReason(ocsd.TraceOnOverflow)
	if elem.Payload.TraceOnReason != ocsd.TraceOnOverflow {
		t.Errorf("SetTraceOnReason failed")
	}

	elem.SetUnSyncEOTReason(ocsd.UnsyncBadPacket)
	if elem.Payload.UnsyncEOTInfo != ocsd.UnsyncBadPacket {
		t.Errorf("SetUnSyncEOTReason failed")
	}

	elem.SetSWTInfo(ocsd.SWTInfo{})
	elem.SetITEInfo(ocsd.TraceSWIte{EL: 1, Value: 123})
	elem.SetSWTITMInfo(ocsd.SWTItmInfo{PktType: ocsd.TSGlobal})
	elem.SetSyncMarker(ocsd.TraceMarkerPayload{Type: ocsd.ElemMarkerTS, Value: 1})
}

func TestTraceElement_Strings(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*ocsd.TraceElement)
		expected string
	}{
		{
			name: "Unknown",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemUnknown)
			},
			expected: "OCSD_GEN_TRC_ELEM_UNKNOWN()",
		},
		{
			name: "NoSync",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemNoSync)
				e.SetUnSyncEOTReason(ocsd.UnsyncInitDecoder)
			},
			expected: "OCSD_GEN_TRC_ELEM_NO_SYNC( [init-decoder])",
		},
		{
			name: "TraceOn",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemTraceOn)
				e.SetTraceOnReason(ocsd.TraceOnNormal)
			},
			expected: "OCSD_GEN_TRC_ELEM_TRACE_ON( [begin or filter])",
		},
		{
			name: "PeContext",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemPeContext)
				e.SetISA(ocsd.ISAArm)
				var ctx ocsd.PEContext
				ctx.ExceptionLevel = ocsd.EL2
				ctx.SetELValid(true)
				ctx.SecurityLevel = ocsd.SecNonsecure
				ctx.SetBits64(false)
				ctx.VMID = 0xAA
				ctx.SetVMIDValid(true)
				ctx.ContextID = 0xBB
				ctx.SetCtxtIDValid(true)
				e.SetContext(ctx)
			},
			expected: "OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=A32) EL2N; 32-bit; VMID=0xaa; CTXTID=0xbb; )",
		},
		{
			name: "InstrRange",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemInstrRange)
				e.SetAddrRange(0x8000, 0x8010, 4)
				e.SetISA(ocsd.ISAThumb2)
				e.SetLastInstrInfo(true, ocsd.InstrBr, ocsd.SInstrBrLink, 4)
				e.LastInstrCond = true
				e.SetCycleCount(100)
			},
			expected: "OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range=0x8000:[0x8010] num_i(4) last_sz(4) (ISA=T32) E BR  b+link  <cond> [CC=100]; )",
		},
		{
			name: "Nopath",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemIRangeNopath)
				e.SetAddrRange(0x1000, 0x2000, 50)
			},
			expected: "OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH(first 0x1000:[next 0x2000] num_i(50) )",
		},
		{
			name: "Exception",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemException)
				e.SetExceptionNum(0x11)
				e.EndAddr = 0x4000
				e.ExceptionRetAddr = true
				e.ExceptionRetAddrBrTgt = true
			},
			expected: "OCSD_GEN_TRC_ELEM_EXCEPTION(pref ret addr:0x4000 [addr also prev br tgt]; excep num (0x11) )",
		},
		{
			name: "Timestamp",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemTimestamp)
				e.SetTS(0x123456789ABC, false)
			},
			expected: "OCSD_GEN_TRC_ELEM_TIMESTAMP( [ TS=0x123456789abc]; )",
		},
		{
			name: "Event",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemEvent)
				e.SetEvent(ocsd.EventNumbered, 42)
			},
			expected: "OCSD_GEN_TRC_ELEM_EVENT( Numbered:42; )",
		},
		{
			name: "Event Trigger",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemEvent)
				e.SetEvent(ocsd.EventTrigger, 0)
			},
			expected: "OCSD_GEN_TRC_ELEM_EVENT( Trigger; )",
		},
		{
			name: "MemTrans",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemMemTrans)
				e.SetTransactionType(ocsd.MemTransStart)
			},
			expected: "OCSD_GEN_TRC_ELEM_MEMTRANS(Start)",
		},
		{
			name: "Instrumentation",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemInstrumentation)
				e.SetITEInfo(ocsd.TraceSWIte{EL: 1, Value: 0xDEADBEEF})
			},
			expected: "OCSD_GEN_TRC_ELEM_INSTRUMENTATION(EL1; 0x00000000deadbeef)",
		},
		{
			name: "SyncMarker",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemSyncMarker)
				e.SetSyncMarker(ocsd.TraceMarkerPayload{Type: ocsd.ElemMarkerTS, Value: 0x1234})
			},
			expected: "OCSD_GEN_TRC_ELEM_SYNC_MARKER( [Timestamp marker(0x00001234)])",
		},
		{
			name: "AddrNacc",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0x5555
				e.SetExceptionNum(uint32(ocsd.MemSpaceEL2))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0x5555; Memspace [0x4:EL2N] )",
		},
		{
			name: "AddrNacc Various",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0x123
				e.SetExceptionNum(uint32(ocsd.MemSpaceEL1S))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0x123; Memspace [0x1:EL1S] )",
		},
		{
			name: "CycleCount",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemCycleCount)
				e.SetCycleCount(999)
			},
			expected: "OCSD_GEN_TRC_ELEM_CYCLE_COUNT( [CC=999]; )",
		},
		{
			name: "Custom",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemCustom)
			},
			expected: "OCSD_GEN_TRC_ELEM_CUSTOM()",
		},
		{
			name: "InstrRange No Exec",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemInstrRange)
				e.SetAddrRange(0x100, 0x110, 4)
				e.SetISA(ocsd.ISAArm)
				e.SetLastInstrInfo(false, ocsd.InstrDsbDmb, ocsd.SInstrNone, 4)
			},
			expected: "OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range=0x100:[0x110] num_i(4) last_sz(4) (ISA=A32) N DSB.DMB)",
		},
		{
			name: "PeContext various",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemPeContext)
				e.SetISA(ocsd.ISAUnknown)
				var ctx ocsd.PEContext
				ctx.ExceptionLevel = ocsd.ELUnknown
				ctx.SetELValid(false)
				ctx.SecurityLevel = ocsd.SecRoot
				ctx.SetBits64(true)
				e.SetContext(ctx)
			},
			expected: "OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=Unk) Root; 64-bit; )",
		},
		{
			name: "ExceptionRet",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemExceptionRet)
			},
			expected: "OCSD_GEN_TRC_ELEM_EXCEPTION_RET()",
		},
		{
			name: "PeContext bounds",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemPeContext)
				e.SetISA(ocsd.ISA(99)) // Invalid ISA goes to Unknown
			},
			expected: "OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=Unk) S; 32-bit; )",
		},
		{
			name: "AddrNacc EL3",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceEL3))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x8:EL3] )",
		},
		{
			name: "AddrNacc EL2S",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceEL2S))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x10:EL2S] )",
		},
		{
			name: "AddrNacc EL1R",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceEL1R))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x20:EL1R] )",
		},
		{
			name: "AddrNacc EL2R",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceEL2R))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x40:EL2R] )",
		},
		{
			name: "AddrNacc Root",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceRoot))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x80:Root] )",
		},
		{
			name: "AddrNacc S N R Any None",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceS))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x19:Any S] )",
		},
		{
			name: "AddrNacc N",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceN))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x6:Any NS] )",
		},
		{
			name: "AddrNacc R",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceR))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x60:Any R] )",
		},
		{
			name: "AddrNacc Any",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceAny))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0xff:Any] )",
		},
		{
			name: "AddrNacc None",
			setup: func(e *ocsd.TraceElement) {
				e.SetType(ocsd.GenElemAddrNacc)
				e.StartAddr = 0xAA
				e.SetExceptionNum(uint32(ocsd.MemSpaceNone))
			},
			expected: "OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xaa; Memspace [0x0:None] )",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			elem := ocsd.NewTraceElement()
			tc.setup(elem)
			got := elem.String()
			if got != tc.expected {
				t.Errorf("\nexpected: %q\ngot:      %q", tc.expected, got)
			}
		})
	}
}

func TestTraceElement_SWTraceStrings(t *testing.T) {
	e := ocsd.NewTraceElementWithType(ocsd.GenElemSWTrace)
	var info ocsd.SWTInfo
	info.MasterID = 0x1
	info.ChannelID = 0x2
	info.SetIDValid(true)
	info.SetPayloadPktBitsize(32)
	e.SetSWTInfo(info)
	e.SetExtendedDataPtr([]byte{0xEF, 0xBE, 0xAD, 0xDE})

	expected := "OCSD_GEN_TRC_ELEM_SWTRACE( (Ma:0x01; Ch:0x02) 0xdeadbeef; )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	// 4 bits
	info.SetPayloadPktBitsize(4)
	e.SetSWTInfo(info)
	expected = "OCSD_GEN_TRC_ELEM_SWTRACE( (Ma:0x01; Ch:0x02) 0xf; )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got) // f because it masks 0xEF & 0xF = 0xF
	}

	// 16 bits
	info.SetPayloadPktBitsize(16)
	e.SetSWTInfo(info)
	expected = "OCSD_GEN_TRC_ELEM_SWTRACE( (Ma:0x01; Ch:0x02) 0xbeef; )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	// 64 bits
	info.SetPayloadPktBitsize(64)
	e.SetSWTInfo(info)
	e.SetExtendedDataPtr([]byte{0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x11, 0x22, 0x33})
	expected = "OCSD_GEN_TRC_ELEM_SWTRACE( (Ma:0x01; Ch:0x02) 0x33221100deadbeef; )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	// Unsupported bits
	info.SetPayloadPktBitsize(42)
	e.SetSWTInfo(info)
	expected = "OCSD_GEN_TRC_ELEM_SWTRACE( (Ma:0x01; Ch:0x02) 0x{Data Error : unsupported bit width.}; )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	info.SetGlobalErr(true)
	e.SetSWTInfo(info)
	expected = "OCSD_GEN_TRC_ELEM_SWTRACE({Global Error.})"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	info.SetGlobalErr(false)
	info.SetMasterErr(true)
	info.SetPayloadPktBitsize(8)
	info.SetIDValid(false)
	info.SetMarkerPacket(true)
	info.SetTriggerEvent(true)
	info.SetHasTimestamp(true)
	info.SetFrequency(true)
	e.SetTS(0x998877, false)
	e.SetSWTInfo(info)
	expected = "OCSD_GEN_TRC_ELEM_SWTRACE((Ma:0x??; Ch:0x??) 0xef; +Mrk Trig  [ TS=0x000000998877]; Freq{Master Error.})"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}
}

func TestTraceElement_ITMTraceStrings(t *testing.T) {
	e := ocsd.NewTraceElementWithType(ocsd.GenElemITMTrace)
	itm := ocsd.SWTItmInfo{
		PktType:      ocsd.SWITPayload,
		PayloadSrcID: 0x8,
		PayloadSize:  2,
		Value:        0x1234,
	}
	e.SetSWTITMInfo(itm)

	expected := "OCSD_GEN_TRC_ELEM_ITMTRACE(ITM_SWIT (ch: 0x8; Data: 0x1234) )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	itm.PktType = ocsd.TSGlobal
	e.SetTS(0xABCDEF, false)
	e.SetSWTITMInfo(itm)
	expected = "OCSD_GEN_TRC_ELEM_ITMTRACE(ITM_TS_GLOBAL ( TS: 0x0000000000abcdef) )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	itm.PktType = ocsd.DWTPayload
	itm.Overflow = 1
	e.SetSWTITMInfo(itm)
	expected = "OCSD_GEN_TRC_ELEM_ITMTRACE(ITM_OVERFLOW; ITM_DWT (desc: 0x8; Data: 0x1234) )"
	if got := e.String(); got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}

	itm.Overflow = 0

	tsTypes := []struct {
		typ  ocsd.SWTItmType
		name string
	}{
		{ocsd.TSSync, "TS Sync"},
		{ocsd.TSDelay, "TS Delay"},
		{ocsd.TSPKTDelay, "Packet Delay"},
		{ocsd.TSPKTTSDelay, "TS and Packet Delay"},
	}

	for _, tt := range tsTypes {
		itm.PktType = tt.typ
		itm.Value = 0xAA
		e.SetSWTITMInfo(itm)
		e.SetTS(0xBB, false)
		exp := fmt.Sprintf("OCSD_GEN_TRC_ELEM_ITMTRACE(ITM_TS_LOCAL ( TS delta: 0x000000aa, { %s}; TS cumulative: 0x00000000000000bb) )", tt.name)
		if got := e.String(); got != exp {
			t.Errorf("Expected %q, got %q", exp, got)
		}
	}
}

func TestTraceElement_CopyPersistentInfo(t *testing.T) {
	e1 := ocsd.NewTraceElement()
	e1.SetISA(ocsd.ISAAArch64)

	var ctx ocsd.PEContext
	ctx.SecurityLevel = ocsd.SecSecure
	e1.SetContext(ctx)

	e2 := ocsd.NewTraceElement()
	e2.CopyPersistentData(e1)

	if e2.ISA != ocsd.ISAAArch64 || e2.Context.SecurityLevel != ocsd.SecSecure {
		t.Errorf("CopyPersistentData failed")
	}
}

func TestTraceElement_Flags(t *testing.T) {
	e := ocsd.NewTraceElement()
	e.ExceptionRetAddrBrTgt = true
	if !e.ExceptionRetAddrBrTgt {
		t.Errorf("ExceptionRetAddrBrTgt failed")
	}
	e.ExceptionMTailChain = true
	if !e.ExceptionMTailChain {
		t.Errorf("ExceptionMTailChain failed")
	}

	e.UpdateType(ocsd.GenElemEvent)
	if e.ElemType != ocsd.GenElemEvent {
		t.Errorf("UpdateType failed")
	}
}
