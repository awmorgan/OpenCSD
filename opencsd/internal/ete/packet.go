package ete

import "opencsd/internal/etmv4"

type PktType = etmv4.PktType

type TraceInfo = etmv4.TraceInfo
type Context = etmv4.Context
type ExceptionInfo = etmv4.ExceptionInfo
type TracePacket = etmv4.TracePacket

const (
	PktNotSync       = etmv4.PktNotSync
	PktIncompleteEOT = etmv4.PktIncompleteEOT
	PktNoErrType     = etmv4.PktNoErrType

	PktTraceInfo = etmv4.PktTraceInfo
	PktTimestamp = etmv4.PktTimestamp
	PktTraceOn   = etmv4.PktTraceOn
	PktFuncRet   = etmv4.PktFuncRet
	PktExcept    = etmv4.PktExcept

	PktQ = etmv4.PktQ

	ETE_PktITE         = etmv4.ETE_PktITE
	ETE_PktTransSt     = etmv4.ETE_PktTransSt
	ETE_PktTransCommit = etmv4.ETE_PktTransCommit
	ETE_PktTSMarker    = etmv4.ETE_PktTSMarker

	ETE_PktSrcAddrMatch   = etmv4.ETE_PktSrcAddrMatch
	ETE_PktSrcAddrS_IS0   = etmv4.ETE_PktSrcAddrS_IS0
	ETE_PktSrcAddrS_IS1   = etmv4.ETE_PktSrcAddrS_IS1
	ETE_PktSrcAddrL_32IS0 = etmv4.ETE_PktSrcAddrL_32IS0
	ETE_PktSrcAddrL_32IS1 = etmv4.ETE_PktSrcAddrL_32IS1
	ETE_PktSrcAddrL_64IS0 = etmv4.ETE_PktSrcAddrL_64IS0
	ETE_PktSrcAddrL_64IS1 = etmv4.ETE_PktSrcAddrL_64IS1

	ETE_PktPeReset   = etmv4.ETE_PktPeReset
	ETE_PktTransFail = etmv4.ETE_PktTransFail
)
