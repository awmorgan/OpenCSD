package common

import (
	"opencsd/internal/ocsd"
)

// Aliases for types moved to internal/ocsd
type GenElemType = ocsd.GenElemType

const (
	GenElemUnknown         = ocsd.GenElemUnknown
	GenElemNoSync          = ocsd.GenElemNoSync
	GenElemTraceOn         = ocsd.GenElemTraceOn
	GenElemEOTrace         = ocsd.GenElemEOTrace
	GenElemPeContext       = ocsd.GenElemPeContext
	GenElemInstrRange      = ocsd.GenElemInstrRange
	GenElemIRangeNopath    = ocsd.GenElemIRangeNopath
	GenElemAddrNacc        = ocsd.GenElemAddrNacc
	GenElemAddrUnknown     = ocsd.GenElemAddrUnknown
	GenElemException       = ocsd.GenElemException
	GenElemExceptionRet    = ocsd.GenElemExceptionRet
	GenElemTimestamp       = ocsd.GenElemTimestamp
	GenElemCycleCount      = ocsd.GenElemCycleCount
	GenElemEvent           = ocsd.GenElemEvent
	GenElemSWTrace         = ocsd.GenElemSWTrace
	GenElemSyncMarker      = ocsd.GenElemSyncMarker
	GenElemMemTrans        = ocsd.GenElemMemTrans
	GenElemInstrumentation = ocsd.GenElemInstrumentation
	GenElemITMTrace        = ocsd.GenElemITMTrace
	GenElemCustom          = ocsd.GenElemCustom
)

type TraceOnReason = ocsd.TraceOnReason

const (
	TraceOnNormal   = ocsd.TraceOnNormal
	TraceOnOverflow = ocsd.TraceOnOverflow
	TraceOnExDebug  = ocsd.TraceOnExDebug
)

type EventType = ocsd.EventType

const (
	EventUnknown  = ocsd.EventUnknown
	EventTrigger  = ocsd.EventTrigger
	EventNumbered = ocsd.EventNumbered
)

type TraceEvent = ocsd.TraceEvent
type UnsyncInfo = ocsd.UnsyncInfo

const (
	UnsyncUnknown      = ocsd.UnsyncUnknown
	UnsyncInitDecoder  = ocsd.UnsyncInitDecoder
	UnsyncResetDecoder = ocsd.UnsyncResetDecoder
	UnsyncOverflow     = ocsd.UnsyncOverflow
	UnsyncDiscard      = ocsd.UnsyncDiscard
	UnsyncBadPacket    = ocsd.UnsyncBadPacket
	UnsyncBadImage     = ocsd.UnsyncBadImage
	UnsyncEOT          = ocsd.UnsyncEOT
)

type TraceSyncMarker = ocsd.TraceSyncMarker

const (
	ElemMarkerTS = ocsd.ElemMarkerTS
)

type TraceMarkerPayload = ocsd.TraceMarkerPayload
type TraceMemtrans = ocsd.TraceMemtrans

const (
	MemTransTraceInit = ocsd.MemTransTraceInit
	MemTransStart     = ocsd.MemTransStart
	MemTransCommit    = ocsd.MemTransCommit
	MemTransFail      = ocsd.MemTransFail
)

type TraceSWIte = ocsd.TraceSWIte
type SWTItmType = ocsd.SWTItmType

const (
	SWITPayload  = ocsd.SWITPayload
	DWTPayload   = ocsd.DWTPayload
	TSSync       = ocsd.TSSync
	TSDelay      = ocsd.TSDelay
	TSPKTDelay   = ocsd.TSPKTDelay
	TSPKTTSDelay = ocsd.TSPKTTSDelay
	TSGlobal     = ocsd.TSGlobal
)

type SWTItmInfo = ocsd.SWTItmInfo
type TraceElement = ocsd.TraceElement

// NewTraceElement constructs with default state
func NewTraceElement() *TraceElement {
	return ocsd.NewTraceElement()
}

func NewTraceElementWithType(typ GenElemType) *TraceElement {
	return ocsd.NewTraceElementWithType(typ)
}
