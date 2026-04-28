package etmv4

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"opencsd/internal/ocsd"
)

// PktType is the ETMv4/ETE trace packet type.
// Equivalent to ocsd_etmv4_i_pkt_type.
type PktType int

const (
	/* state of decode markers */
	PktNotSync       PktType = 0x200 /*!< no sync found yet. */
	PktIncompleteEOT PktType = 0x201 /*!< flushing incomplete/empty packet at end of trace.*/
	PktNoErrType     PktType = 0x202 /*!< error type not set for packet. */

	/* markers for unknown/bad packets */
	PktBadSequence  PktType = 0x300 /*!< invalid sequence for packet type. */
	PktBadTraceMode PktType = 0x301 /*!< invalid packet type for this trace mode. */
	PktReserved     PktType = 0x302 /*!< packet type reserved. */
	PktReservedCfg  PktType = 0x303 /*!< packet type reserved for current configuration */

	/* I stream packet types. */
	/* extension header. */
	PktExtension PktType = 0x00 /*!< b00000000  */

	/* sync */
	PktTraceInfo PktType = 0x01 /*!< b00000001 */
	// timestamp
	PktTimestamp PktType = 0x02 /*!< b0000001x */
	PktTraceOn   PktType = 0x04 /*!< b00000100 */
	PktFuncRet   PktType = 0x05 /*!< b00000101 (V8M only) */
	// Exceptions
	PktExcept    PktType = 0x06 /*!< b00000110 */
	PktExceptRtn PktType = 0x07 /*!< b00000111 (ETE invalid) */

	/* unused encoding              0x08         b00001000 */
	ETE_PktITE         PktType = 0x09 /*!  b00001001 (ETE only) */
	ETE_PktTransSt     PktType = 0x0A /*!  b00001010 (ETE only) */
	ETE_PktTransCommit PktType = 0x0B /*!  b00001011 (ETE only) */

	/* cycle count packets */
	PktCcntF2 PktType = 0x0C /*!< b0000110x */
	PktCcntF1 PktType = 0x0E /*!< b0000111x */
	PktCcntF3 PktType = 0x10 /*!< b0001xxxx */

	// data synchronisation markers
	PktNumDsMkr   PktType = 0x20 /*!< b00100xxx */
	PktUnnumDsMkr PktType = 0x28 /*!< b00101000 to b00101100 0x2C */

	// commit packets
	PktCommit PktType = 0x2D /*!< b00101101 */

	// cancel packets
	PktCancelF1        PktType = 0x2E /*!< b00101110 */
	PktCancelF1Mispred PktType = 0x2F /*!< b00101111 */

	// mispredict packets
	PktMispredict PktType = 0x30 /*!< b001100xx */
	PktCancelF2   PktType = 0x34 /*!< b001101xx */
	PktCancelF3   PktType = 0x38 /*!< b00111xxx */

	// condition codes
	PktCondIF2   PktType = 0x40 /*!< b0100000x */
	PktCondFlush PktType = 0x43 /*!< b01000011 */
	PktCondResF4 PktType = 0x44 /*!< b0100010x */
	PktCondResF2 PktType = 0x48 /*!< b0100100x */
	PktCondResF3 PktType = 0x50 /*!< b0101xxxx */
	PktCondResF1 PktType = 0x68 /*!< b011010xx */
	PktCondIF1   PktType = 0x6C /*!< b01101100 */
	PktCondIF3   PktType = 0x6D /*!< b01101101 */

	PktIgnore PktType = 0x70 /*!< b01110000 */
	PktEvent  PktType = 0x71 /*!< b01110001 */

	// address / context
	PktCtxtF1 PktType = 0x60 /*!< b0110xxxx */
	PktCtxtF2 PktType = 0x61 /*!< b0110xxxx */
	PktCtxtF3 PktType = 0x62 /*!< b0110xxxx */
	PktCtxtF4 PktType = 0x63 /*!< b0110xxxx */

	PktCtxt PktType = 0x80 /*!< b1000xxxx */

	PktAddrCtxtL_32IS0 PktType = 0x82 /*!< b10000010  */
	PktAddrCtxtL_32IS1 PktType = 0x83 /*!< b10000011  */
	PktAddrCtxtL_64IS0 PktType = 0x85 /*!< b10000101  */
	PktAddrCtxtL_64IS1 PktType = 0x86 /*!< b10000110  */

	ETE_PktTSMarker PktType = 0x88 /*!< b10001000 (ETE 1.1) */

	PktAddrMatch PktType = 0x90 /*!< exact address match packet */

	PktAddrS_IS0 PktType = 0x95 /*!< Short addr IS0 */
	PktAddrS_IS1 PktType = 0x96 /*!< Short addr IS1 */

	PktAddrL_32IS0 PktType = 0x9A /*!< long address instruction format 5 */
	PktAddrL_32IS1 PktType = 0x9B /*!< long address instruction format 6 */
	PktAddrL_64IS0 PktType = 0x9D /*!< long address instruction format 7 */
	PktAddrL_64IS1 PktType = 0x9E /*!< long address instruction format 8 */

	PktQ PktType = 0xA0 /*!< b1010xxxx */

	ETE_PktSrcAddrMatch   PktType = 0xB0
	ETE_PktSrcAddrS_IS0   PktType = 0xB4
	ETE_PktSrcAddrS_IS1   PktType = 0xB5
	ETE_PktSrcAddrL_32IS0 PktType = 0xB6
	ETE_PktSrcAddrL_32IS1 PktType = 0xB7
	ETE_PktSrcAddrL_64IS0 PktType = 0xB8
	ETE_PktSrcAddrL_64IS1 PktType = 0xB9

	// atoms
	PktAtomF6 PktType = 0xC0 /*!< b11000000 - b11010100 0xC0 - 0xD4, b11100000 - b11110100 0xE0 - 0xF4 */
	PktAtomF5 PktType = 0xD5 /*!< b11010101 - b11010111 0xD5 - 0xD7, b11110101 0xF5 */
	PktAtomF2 PktType = 0xD8 /*!< b110110xx to 0xDB */
	PktAtomF4 PktType = 0xDC /*!< b110111xx to 0xDF */
	PktAtomF1 PktType = 0xF6 /*!< b1111011x to 0xF7 */
	PktAtomF3 PktType = 0xF8 /*!< b11111xxx to 0xFF */

	// extension packets - follow 0x00 header
	PktAsync    PktType = 0x100 /*!< b00000000 */
	PktDiscard  PktType = 0x103 /*!< b00000011 */
	PktOverflow PktType = 0x105 /*!< b00000101 */

	// ETE extended types
	ETE_PktPeReset   PktType = 0x400 // base type is exception packet.
	ETE_PktTransFail PktType = 0x401 // base type is exception packet.
)

var (
	// Compatibility packet type aliases used by newer ETE call sites.
	PktTypeITE          = ETE_PktITE
	PktTypeTRANS_ST     = ETE_PktTransSt
	PktTypeTRANS_COMMIT = ETE_PktTransCommit
	PktTypeTRANS_FAIL   = ETE_PktTransFail
	PktTypeTS_MARKER    = ETE_PktTSMarker
	PktTypePE_RESET     = ETE_PktPeReset
)

// Info for TINFO packet.
type TraceInfo struct {
	Val          uint16
	CCEnabled    bool  // 1 if cycle count enabled
	CondEnabled  uint8 // conditional trace enabled type.
	P0Load       bool  // 1 if tracing with P0 load elements (for data trace)
	P0Store      bool  // 1 if tracing with P0 store elements (for data trace)
	InTransState bool  // Is in transaction state (ETE)

	// internal decoder info for processing TINFO packets
	InitialTInfo     bool // 1 if this tinfo is the initial one used to start decode
	SpecFieldPresent bool // 1 if this tinfo had a spec depth field
}

// Trace context.
type Context struct {
	EL       uint8 // exception level.
	SF       bool  // sixty four bit
	NS       bool  // none secure
	Updated  bool  // updated this context packet (otherwise same as last time)
	UpdatedC bool  // updated CtxtID
	UpdatedV bool  // updated VMID
	NSE      bool  // PE FEAT_RME: root / realm indicator

	CtxtID uint32 // Current ctxtID
	VMID   uint32 // current VMID
}

// Exception information.
type ExceptionInfo struct {
	ExceptionType uint16 // exception number
	AddrInterp    uint8  // address value interpretation
	MFaultPending bool   // M class fault pending.
	MType         bool   // 1 if M class exception.
}

type CondInstr struct {
	CondCKey    uint32
	NumCElem    uint8
	CondKeySet  bool
	F3FinalElem bool
	F2CondIncr  bool
}

type CondResult struct {
	CondRKey0  uint32
	CondRKey1  uint32
	Res0       uint8
	Res1       uint8
	CI0        bool
	CI1        bool
	KeyRes0Set bool
	KeyRes1Set bool
	F2KeyIncr  uint8
	F2F4Token  uint8
	F3Tokens   uint16
}

type QPkt struct {
	QCount       uint32
	AddrPresent  bool
	AddrMatch    bool
	CountPresent bool
	QType        uint8
}

type ITEPkt struct {
	EL    uint8
	Value uint64
}

type Valid struct {
	Context            bool
	VAddrValid         bool
	Timestamp          bool
	CycleCount         bool
	CCExactMatch       bool
	CCThreshold        bool
	TInfo              bool
	TraceOnReason      bool
	ExactMatchIdxValid bool
	CommitElem         bool
	CancelElem         bool
	CondInstr          bool
	CondResult         bool
	SpecDepthValid     bool
}

// Trace packet element.
type TracePacket struct {
	Index ocsd.TrcIndex

	Type      PktType
	Err       error
	ErrHdrVal uint8

	// intra-packet data - valid across packets.
	VAddr               ocsd.VAddr
	VAddrISA            uint8
	VAddrValidBits      uint8
	VAddrPktBits        uint8
	VAddrStack          [3]ocsd.VAddr
	VAddrValidBitsStack [3]uint8
	VAddrPktBitsStack   [3]uint8
	VAddrISAStack       [3]uint8
	Context             Context

	Timestamp     uint64
	TSBitsChanged uint8

	CCThreshold uint32

	// single packet data - only valid for specific packet types on packet instance.
	Atom       ocsd.PktAtom
	CycleCount uint32

	CurrSpecDepth uint32
	P0Key         uint32

	CommitElements uint32
	CancelElements uint32

	TraceInfo TraceInfo

	ExceptionInfo ExceptionInfo

	AddrExactMatchIdx uint8
	DsmVal            uint8
	EventVal          uint8

	CondInstr  CondInstr
	CondResult CondResult
	QPkt       QPkt
	ITEPkt     ITEPkt

	Valid Valid

	ProtocolVersion uint8
}

var errIncompleteEOT = errors.New("incomplete packet flushed at end of trace")
var errReservedCfg = errors.New("packet type reserved for current configuration")
var errReservedHeader = errors.New("packet header reserved encoding")

// EffectiveType returns the packet type used for reporting/printing.
// Only incomplete-EOT overrides the packet type for raw packet output.
func (p *TracePacket) EffectiveType() PktType {
	if p == nil {
		return PktNoErrType
	}
	if p.Err == nil {
		return p.Type
	}
	if errors.Is(p.Err, errIncompleteEOT) {
		return PktIncompleteEOT
	}
	if errors.Is(p.Err, errReservedCfg) {
		return PktReservedCfg
	}
	if errors.Is(p.Err, errReservedHeader) || errors.Is(p.Err, ocsd.ErrInvalidPcktHdr) {
		return PktReserved
	}
	if errors.Is(p.Err, ocsd.ErrBadPacketSeq) {
		return PktBadSequence
	}
	return p.Type
}

// PktTypeName returns the canonical packet type string used by packet printers.
func PktTypeName(t PktType) string {
	return t.String()
}

// ensure PktType meets Stringer requirements
var _ fmt.Stringer = PktType(0)

func (t PktType) String() string {
	switch t {
	case PktNotSync:
		return "I_NOT_SYNC"
	case PktIncompleteEOT:
		return "I_INCOMPLETE_EOT"
	case PktNoErrType:
		return "I_NO_ERR_TYPE"
	case PktBadSequence:
		return "I_BAD_SEQUENCE"
	case PktBadTraceMode:
		return "I_BAD_TRACEMODE"
	case PktReserved:
		return "I_RESERVED"
	case PktReservedCfg:
		return "I_RESERVED_CFG"
	case PktExtension:
		return "I_EXTENSION"
	case PktTraceInfo:
		return "I_TRACE_INFO"
	case PktTimestamp:
		return "I_TIMESTAMP"
	case PktTraceOn:
		return "I_TRACE_ON"
	case PktFuncRet:
		return "I_FUNC_RET"
	case PktExcept:
		return "I_EXCEPT"
	case PktExceptRtn:
		return "I_EXCEPT_RTN"
	case ETE_PktITE:
		return "I_ITE"
	case ETE_PktTransSt:
		return "I_TRANS_ST"
	case ETE_PktTransCommit:
		return "I_TRANS_COMMIT"
	case PktCcntF2:
		return "I_CCNT_F2"
	case PktCcntF1:
		return "I_CCNT_F1"
	case PktCcntF3:
		return "I_CCNT_F3"
	case PktNumDsMkr:
		return "I_NUM_DS_MKR"
	case PktUnnumDsMkr:
		return "I_UNNUM_DS_MKR"
	case PktCommit:
		return "I_COMMIT"
	case PktCancelF1:
		return "I_CANCEL_F1"
	case PktCancelF1Mispred:
		return "I_CANCEL_F1_MISPRED"
	case PktMispredict:
		return "I_MISPREDICT"
	case PktCancelF2:
		return "I_CANCEL_F2"
	case PktCancelF3:
		return "I_CANCEL_F3"
	case PktCtxt:
		return "I_CTXT"
	case PktAddrCtxtL_32IS0:
		return "I_ADDR_CTXT_L_32IS0"
	case PktAddrCtxtL_32IS1:
		return "I_ADDR_CTXT_L_32IS1"
	case PktAddrCtxtL_64IS0:
		return "I_ADDR_CTXT_L_64IS0"
	case PktAddrCtxtL_64IS1:
		return "I_ADDR_CTXT_L_64IS1"

	case ETE_PktTSMarker:
		return "I_TS_MARKER"

	case PktAddrMatch:
		return "I_ADDR_MATCH"

	case PktAddrS_IS0:
		return "I_ADDR_S_IS0"
	case PktAddrS_IS1:
		return "I_ADDR_S_IS1"

	case PktAddrL_32IS0:
		return "I_ADDR_L_32IS0"
	case PktAddrL_32IS1:
		return "I_ADDR_L_32IS1"
	case PktAddrL_64IS0:
		return "I_ADDR_L_64IS0"
	case PktAddrL_64IS1:
		return "I_ADDR_L_64IS1"
	case PktQ:
		return "I_Q"
	case PktCondIF2:
		return "I_COND_I_F2"
	case PktCondFlush:
		return "I_COND_FLUSH"
	case PktCondResF4:
		return "I_COND_RES_F4"
	case PktCondResF2:
		return "I_COND_RES_F2"
	case PktCondResF3:
		return "I_COND_RES_F3"
	case PktCondResF1:
		return "I_COND_RES_F1"
	case PktCondIF1:
		return "I_COND_I_F1"
	case PktCondIF3:
		return "I_COND_I_F3"
	case PktIgnore:
		return "I_IGNORE"
	case PktEvent:
		return "I_EVENT"
	case ETE_PktSrcAddrMatch:
		return "I_SRC_ADDR_MATCH"
	case ETE_PktSrcAddrS_IS0:
		return "I_SRC_ADDR_S_IS0"
	case ETE_PktSrcAddrS_IS1:
		return "I_SRC_ADDR_S_IS1"
	case ETE_PktSrcAddrL_32IS0:
		return "I_SCR_ADDR_L_32IS0" // C++ typo: SCR not SRC; golden files match C++ output
	case ETE_PktSrcAddrL_32IS1:
		return "I_SRC_ADDR_L_32IS1"
	case ETE_PktSrcAddrL_64IS0:
		return "I_SRC_ADDR_L_64IS0"
	case ETE_PktSrcAddrL_64IS1:
		return "I_SRC_ADDR_L_64IS1"
	case PktAtomF6:
		return "I_ATOM_F6"
	case PktAtomF5:
		return "I_ATOM_F5"
	case PktAtomF2:
		return "I_ATOM_F2"
	case PktAtomF4:
		return "I_ATOM_F4"
	case PktAtomF1:
		return "I_ATOM_F1"
	case PktAtomF3:
		return "I_ATOM_F3"
	case PktAsync:
		return "I_ASYNC"
	case PktDiscard:
		return "I_DISCARD"
	case PktOverflow:
		return "I_OVERFLOW"
	case ETE_PktPeReset:
		return "I_PE_RESET"
	case ETE_PktTransFail:
		return "I_TRANS_FAIL"
	}
	return "I_UNKNOWN"
}

func (t PktType) Description() string {
	switch t {
	case PktNotSync:
		return "I Stream not synchronised"
	case PktIncompleteEOT:
		return "Incomplete packet at end of trace."
	case PktNoErrType:
		return "No Error Type."
	case PktBadSequence:
		return "Invalid Sequence in packet."
	case PktBadTraceMode:
		return "Invalid Packet for trace mode."
	case PktReserved:
		return "Reserved Packet Header"
	case PktReservedCfg:
		return "Reserved header for current configuration."
	case PktExtension:
		return "Extension packet header."
	case PktTraceInfo:
		return "Trace Info."
	case PktTimestamp:
		return "Timestamp."
	case PktTraceOn:
		return "Trace On."
	case PktFuncRet:
		return "V8M - function return."
	case PktExcept:
		return "Exception."
	case PktExceptRtn:
		return "Exception Return."
	case ETE_PktITE:
		return "Instrumentation"
	case ETE_PktTransSt:
		return "Transaction Start."
	case ETE_PktTransCommit:
		return "Transaction Commit."
	case PktCcntF1:
		return "Cycle Count format 1."
	case PktCcntF2:
		return "Cycle Count format 2."
	case PktCcntF3:
		return "Cycle Count format 3."
	case PktNumDsMkr:
		return "Data Synchronisation Marker - Numbered."
	case PktUnnumDsMkr:
		return "Data Synchronisation Marker - Unnumbered."
	case PktCommit:
		return "Commit"
	case PktCancelF1:
		return "Cancel Format 1."
	case PktCancelF1Mispred:
		return "Cancel Format 1 + Mispredict."
	case PktMispredict:
		return "Mispredict."
	case PktCancelF2:
		return "Cancel Format 2."
	case PktCancelF3:
		return "Cancel Format 3."
	case PktCondIF2:
		return "Conditional Instruction, format 2."
	case PktCondFlush:
		return "Conditional Flush."
	case PktCondResF4:
		return "Conditional Result, format 4."
	case PktCondResF2:
		return "Conditional Result, format 2."
	case PktCondResF3:
		return "Conditional Result, format 3."
	case PktCondResF1:
		return "Conditional Result, format 1."
	case PktCondIF1:
		return "Conditional Instruction, format 1."
	case PktCondIF3:
		return "Conditional Instruction, format 3."
	case PktIgnore:
		return "Ignore."
	case PktEvent:
		return "Trace Event."
	case PktCtxt:
		return "Context Packet."
	case PktAddrCtxtL_32IS0:
		return "Address & Context, Long, 32 bit, IS0."
	case PktAddrCtxtL_32IS1:
		return "Address & Context, Long, 32 bit, IS1."
	case PktAddrCtxtL_64IS0:
		return "Address & Context, Long, 64 bit, IS0."
	case PktAddrCtxtL_64IS1:
		return "Address & Context, Long, 64 bit, IS1."
	case ETE_PktTSMarker:
		return "Timestamp Marker"
	case PktAddrMatch:
		return "Exact Address Match."
	case PktAddrS_IS0:
		return "Address, Short, IS0."
	case PktAddrS_IS1:
		return "Address, Short, IS1."
	case PktAddrL_32IS0:
		return "Address, Long, 32 bit, IS0."
	case PktAddrL_32IS1:
		return "Address, Long, 32 bit, IS1."
	case PktAddrL_64IS0:
		return "Address, Long, 64 bit, IS0."
	case PktAddrL_64IS1:
		return "Address, Long, 64 bit, IS1."
	case PktQ:
		return "Q Packet."
	case ETE_PktSrcAddrMatch:
		return "Exact Source Address Match."
	case ETE_PktSrcAddrS_IS0:
		return "Source Address, Short, IS0."
	case ETE_PktSrcAddrS_IS1:
		return "Source Address, Short, IS1."
	case ETE_PktSrcAddrL_32IS0:
		return "Source Address, Long, 32 bit, IS0."
	case ETE_PktSrcAddrL_32IS1:
		return "Source Address, Long, 32 bit, IS1."
	case ETE_PktSrcAddrL_64IS0:
		return "Source Address, Long, 64 bit, IS0."
	case ETE_PktSrcAddrL_64IS1:
		return "Source Address, Long, 64 bit, IS1."
	case PktAtomF6:
		return "Atom format 6."
	case PktAtomF5:
		return "Atom format 5."
	case PktAtomF2:
		return "Atom format 2."
	case PktAtomF4:
		return "Atom format 4."
	case PktAtomF1:
		return "Atom format 1."
	case PktAtomF3:
		return "Atom format 3."
	case PktAsync:
		return "Alignment Synchronisation."
	case PktDiscard:
		return "Discard."
	case PktOverflow:
		return "Overflow."
	case ETE_PktPeReset:
		return "PE Reset."
	case ETE_PktTransFail:
		return "Transaction Fail."
	default:
		return "Unknown Packet Header"
	}
}

// HeaderString returns packet header text in trc_pkt_lister format.
func (p *TracePacket) HeaderString() string {
	var sb strings.Builder

	et := p.EffectiveType()
	sb.WriteString(et.String())
	sb.WriteString(" : ")

	var desc strings.Builder
	desc.WriteString(et.Description())

	if (et == PktAddrMatch || et == ETE_PktSrcAddrMatch) && p.Valid.ExactMatchIdxValid {
		fmt.Fprintf(&desc, ", [%d]", p.AddrExactMatchIdx)
	}
	// For I_INCOMPLETE_EOT, p.Type holds the original packet type that was interrupted.
	if et == PktIncompleteEOT && p.Type != PktNoErrType {
		fmt.Fprintf(&desc, "[%s]", p.Type.String())
	} else if et == PktBadSequence || et == PktReservedCfg {
		fmt.Fprintf(&desc, "[%s]", p.Type.String())
	}

	switch et {
	case PktTraceInfo:
		fmt.Fprintf(&desc, "; INFO=0x%x", p.TraceInfo.Val&0xFF)
		ccEnabled := 0
		if p.TraceInfo.CCEnabled {
			ccEnabled = 1
		}
		if p.isETE() {
			tstate := 0
			if p.TraceInfo.InTransState {
				tstate = 1
			}
			fmt.Fprintf(&desc, " { CC.%d, TSTATE.%d }", ccEnabled, tstate)
		} else {
			fmt.Fprintf(&desc, " { CC.%d }", ccEnabled)
		}
		if p.Valid.CCThreshold {
			fmt.Fprintf(&desc, "; CC_THRESHOLD=0x%x", p.CCThreshold)
		}
		if p.TraceInfo.InitialTInfo && p.Valid.SpecDepthValid && p.TraceInfo.SpecFieldPresent {
			fmt.Fprintf(&desc, "; INIT SPEC DEPTH=%d", p.CurrSpecDepth)
		}
		if p.TraceInfo.InitialTInfo {
			desc.WriteString("; Decoder Sync point TINFO")
		}
	case PktAddrCtxtL_32IS0, PktAddrCtxtL_32IS1:
		updateBits := uint8(0)
		if p.VAddrPktBits < 32 {
			updateBits = p.VAddrPktBits
		}
		fmt.Fprintf(&desc, "; Addr=%s; %s", p.addrValStr(updateBits), p.contextStr())
	case PktAddrL_32IS0, PktAddrL_32IS1, ETE_PktSrcAddrL_32IS0, ETE_PktSrcAddrL_32IS1:
		updateBits := uint8(0)
		if p.VAddrPktBits < 32 {
			updateBits = p.VAddrPktBits
		}
		fmt.Fprintf(&desc, "; Addr=%s; ", p.addrValStr(updateBits))
	case PktAddrCtxtL_64IS0, PktAddrCtxtL_64IS1:
		updateBits := uint8(0)
		if p.VAddrPktBits < 64 {
			updateBits = p.VAddrPktBits
		}
		fmt.Fprintf(&desc, "; Addr=%s; %s", p.addrValStr(updateBits), p.contextStr())
	case PktAddrL_64IS0, PktAddrL_64IS1, ETE_PktSrcAddrL_64IS0, ETE_PktSrcAddrL_64IS1:
		updateBits := uint8(0)
		if p.VAddrPktBits < 64 {
			updateBits = p.VAddrPktBits
		}
		fmt.Fprintf(&desc, "; Addr=%s; ", p.addrValStr(updateBits))
	case PktCtxt:
		fmt.Fprintf(&desc, "; %s", p.contextStr())
	case PktAddrS_IS0, PktAddrS_IS1, ETE_PktSrcAddrS_IS0, ETE_PktSrcAddrS_IS1:
		fmt.Fprintf(&desc, "; Addr=%s", p.addrValStr(p.VAddrPktBits))
	case PktAddrMatch, ETE_PktSrcAddrMatch:
		fmt.Fprintf(&desc, "; Addr=%s; ", p.addrValStr(0))
	case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
		fmt.Fprintf(&desc, "; %s", p.getAtomStr())
	case PktExcept:
		fmt.Fprintf(&desc, "; %s", p.getExceptionStr())
	case PktTimestamp:
		fmt.Fprintf(&desc, "; Updated val = 0x%x", p.Timestamp)
		if p.Valid.CycleCount {
			fmt.Fprintf(&desc, "; CC=0x%x", p.CycleCount)
		}
	case PktCcntF1, PktCcntF2, PktCcntF3:
		fmt.Fprintf(&desc, "; Count=0x%x", p.CycleCount)
		if p.Valid.CommitElem {
			fmt.Fprintf(&desc, "; Commit(%d)", p.CommitElements)
		}
	case PktCancelF1:
		fmt.Fprintf(&desc, "; Cancel(%d)", p.CancelElements)
	case PktCancelF1Mispred:
		fmt.Fprintf(&desc, "; Cancel(%d), Mispredict", p.CancelElements)
	case PktCancelF2:
		desc.WriteString("; ")
		if p.Atom.Num > 0 {
			fmt.Fprintf(&desc, "Atom: %s, ", p.getAtomStr())
		}
		desc.WriteString("Cancel(1), Mispredict")
	case PktCancelF3:
		desc.WriteString("; ")
		if p.Atom.Num > 0 {
			fmt.Fprintf(&desc, "Atom: %s, ", p.getAtomStr())
		}
		desc.WriteString("Cancel(1)")
	case PktMispredict:
		desc.WriteString("; ")
		if p.Atom.Num > 0 {
			fmt.Fprintf(&desc, "Atom: %s, ", p.getAtomStr())
		}
		desc.WriteString("Mispredict")
	case PktCommit:
		fmt.Fprintf(&desc, "; Commit(%d)", p.CommitElements)
	case PktQ:
		if p.QPkt.CountPresent {
			fmt.Fprintf(&desc, "; Count(%d)", p.QPkt.QCount)
		} else {
			desc.WriteString("; Count(Unknown)")
		}
		if p.QPkt.AddrMatch {
			fmt.Fprintf(&desc, "; [%d]", p.AddrExactMatchIdx)
		}
		if p.QPkt.AddrPresent || p.QPkt.AddrMatch {
			updateBits := uint8(0)
			if p.VAddrPktBits < 64 {
				updateBits = p.VAddrPktBits
			}
			fmt.Fprintf(&desc, "; Addr=%s", p.addrValStr(updateBits))
		}
	case ETE_PktITE:
		fmt.Fprintf(&desc, "; EL%d; Payload=0x%x", p.ITEPkt.EL, p.ITEPkt.Value)
	}

	sb.WriteString(strings.TrimSpace(desc.String()))
	return sb.String()
}

// String returns the trace packet header representation.
func (p *TracePacket) String() string {
	if p == nil {
		return ""
	}
	return p.HeaderString()
}

func (p *TracePacket) addrValStr(updateBits uint8) string {
	width := 8
	value := uint64(uint32(p.VAddr))
	if p.VAddrValidBits > 32 {
		width = 16
		value = uint64(p.VAddr)
	}

	hex := strings.ToUpper(strconv.FormatUint(value, 16))
	if len(hex) < width {
		hex = strings.Repeat("0", width-len(hex)) + hex
	}
	s := "0x" + hex
	if updateBits > 0 {
		mask := uint64((1 << updateBits) - 1)
		s += " ~[0x" + strings.ToUpper(strconv.FormatUint(uint64(p.VAddr)&mask, 16)) + "]"
	}
	return s
}

func (p *TracePacket) getExceptionStr() string {
	var sb strings.Builder
	arv8Excep := []string{
		"PE Reset", "Debug Halt", "Call", "Trap",
		"System Error", "Reserved", "Inst Debug", "Data Debug",
		"Reserved", "Reserved", "Alignment", "Inst Fault",
		"Data Fault", "Reserved", "IRQ", "FIQ",
	}
	mExcep := []string{
		"Reserved", "PE Reset", "NMI", "HardFault",
		"MemManage", "BusFault", "UsageFault", "Reserved",
		"Reserved", "Reserved", "Reserved", "SVC",
		"DebugMonitor", "Reserved", "PendSV", "SysTick",
		"IRQ0", "IRQ1", "IRQ2", "IRQ3",
		"IRQ4", "IRQ5", "IRQ6", "IRQ7",
		"DebugHalt", "LazyFP Push", "Lockup", "Reserved",
		"Reserved", "Reserved", "Reserved", "Reserved",
	}

	if !p.ExceptionInfo.MType {
		if p.ExceptionInfo.ExceptionType < 0x10 {
			sb.WriteString(arv8Excep[p.ExceptionInfo.ExceptionType] + ";")
		} else {
			sb.WriteString("Reserved;")
		}
	} else {
		if p.ExceptionInfo.ExceptionType < 0x20 {
			sb.WriteString(mExcep[p.ExceptionInfo.ExceptionType] + ";")
		} else if p.ExceptionInfo.ExceptionType >= 0x208 && p.ExceptionInfo.ExceptionType <= 0x3EF {
			fmt.Fprintf(&sb, "IRQ%d;", p.ExceptionInfo.ExceptionType-0x200)
		} else {
			sb.WriteString("Reserved;")
		}
		if p.ExceptionInfo.MFaultPending {
			sb.WriteString(" Fault Pending;")
		}
	}

	switch p.ExceptionInfo.AddrInterp {
	case 0x1:
		sb.WriteString(" Ret Addr Follows;")
	case 0x2:
		sb.WriteString(" Ret Addr Follows, Match Prev;")
	}

	return " " + sb.String()
}

// PushVAddr pushes the current VAddr and VAddrISA to the top of the history stack
func (p *TracePacket) PushVAddr() {
	p.VAddrStack[2] = p.VAddrStack[1]
	p.VAddrStack[1] = p.VAddrStack[0]
	p.VAddrStack[0] = p.VAddr
	p.VAddrValidBitsStack[2] = p.VAddrValidBitsStack[1]
	p.VAddrValidBitsStack[1] = p.VAddrValidBitsStack[0]
	p.VAddrValidBitsStack[0] = p.VAddrValidBits
	p.VAddrPktBitsStack[2] = p.VAddrPktBitsStack[1]
	p.VAddrPktBitsStack[1] = p.VAddrPktBitsStack[0]
	p.VAddrPktBitsStack[0] = p.VAddrPktBits
	p.VAddrISAStack[2] = p.VAddrISAStack[1]
	p.VAddrISAStack[1] = p.VAddrISAStack[0]
	p.VAddrISAStack[0] = p.VAddrISA
	p.Valid.VAddrValid = p.VAddrValidBits > 0
}

// PopVAddrIdx retrieves an address from the history stack
func (p *TracePacket) PopVAddrIdx(idx uint8) {
	if idx < 3 {
		p.VAddr = p.VAddrStack[idx]
		p.VAddrValidBits = p.VAddrValidBitsStack[idx]
		p.VAddrPktBits = p.VAddrPktBitsStack[idx]
		p.VAddrISA = p.VAddrISAStack[idx]
		p.Valid.VAddrValid = p.VAddrValidBits > 0
	}
}

// ClearTraceInfo resets trace info and address stack state
func (p *TracePacket) ClearTraceInfo() {
	p.Valid.Timestamp = false
	p.Valid.TInfo = false
	p.Valid.CCThreshold = false
	p.Valid.VAddrValid = false
	p.Valid.ExactMatchIdxValid = false

	p.TraceInfo = TraceInfo{}
	p.CurrSpecDepth = 0

	for i := range 3 {
		p.VAddrStack[i] = 0
		p.VAddrValidBitsStack[i] = ocsd.MaxVABitsize
		p.VAddrPktBitsStack[i] = 0
		p.VAddrISAStack[i] = 0
	}
	p.VAddr = p.VAddrStack[0]
	p.VAddrValidBits = p.VAddrValidBitsStack[0]
	p.VAddrPktBits = p.VAddrPktBitsStack[0]
	p.VAddrISA = p.VAddrISAStack[0]
	p.Valid.VAddrValid = p.VAddrValidBits > 0
}

func (p *TracePacket) getAtomStr() string {
	var sb strings.Builder
	bitPattern := p.Atom.EnBits
	for i := 0; i < int(p.Atom.Num); i++ {
		if (bitPattern & 0x1) != 0 {
			sb.WriteByte('E')
		} else {
			sb.WriteByte('N')
		}
		bitPattern >>= 1
	}
	return sb.String()
}

func (p *TracePacket) isETE() bool {
	return (p.ProtocolVersion & 0xF0) == 0x50
}

func (p *TracePacket) contextStr() string {
	if !p.Valid.Context {
		return ""
	}

	if !p.Context.Updated {
		return "Ctxt: Same"
	}

	var sb strings.Builder
	sb.WriteString("Ctxt: ")
	if p.Context.SF {
		sb.WriteString("AArch64,")
	} else {
		sb.WriteString("AArch32, ")
	}
	fmt.Fprintf(&sb, "EL%d, ", p.Context.EL)

	if p.Context.NSE {
		if p.Context.NS {
			sb.WriteString("Realm; ")
		} else {
			sb.WriteString("Root; ")
		}
	} else {
		if p.Context.NS {
			sb.WriteString("NS; ")
		} else {
			sb.WriteString("S; ")
		}
	}

	if p.Context.UpdatedC {
		fmt.Fprintf(&sb, "CID=0x%08x; ", p.Context.CtxtID)
	}
	if p.Context.UpdatedV {
		fmt.Fprintf(&sb, "VMID=0x%04x; ", p.Context.VMID)
	}

	return sb.String()
}
