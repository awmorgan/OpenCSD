package etmv4

import (
	"fmt"

	"opencsd/internal/ocsd"
)

// PktType is the ETMv4/ETE trace packet type.
// Equivalent to ocsd_etmv4_i_pkt_type.
type PktType int

const (
	/* state of decode markers */
	PktNotSync         PktType = 0x200 /*!< no sync found yet. */
	PktIncompleteEOT   PktType = 0x201 /*!< flushing incomplete/empty packet at end of trace.*/
	PktNoErrType       PktType = 0x202 /*!< error type not set for packet. */

	/* markers for unknown/bad packets */
	PktBadSequence     PktType = 0x300 /*!< invalid sequence for packet type. */
	PktBadTraceMode    PktType = 0x301 /*!< invalid packet type for this trace mode. */
	PktReserved        PktType = 0x302 /*!< packet type reserved. */
	PktReservedCfg     PktType = 0x303 /*!< packet type reserved for current configuration */

	/* I stream packet types. */
	/* extension header. */
	PktExtension       PktType = 0x00 /*!< b00000000  */

	/* sync */
	PktTraceInfo       PktType = 0x01 /*!< b00000001 */
	// timestamp
	PktTimestamp       PktType = 0x02 /*!< b0000001x */
	PktTraceOn         PktType = 0x04 /*!< b00000100 */
	PktFuncRet         PktType = 0x05 /*!< b00000101 (V8M only) */
	// Exceptions
	PktExcept          PktType = 0x06 /*!< b00000110 */
	PktExceptRtn       PktType = 0x07 /*!< b00000111 (ETE invalid) */

	/* unused encoding              0x08         b00001000 */
	ETE_PktITE         PktType = 0x09 /*!  b00001001 (ETE only) */
	ETE_PktTransSt     PktType = 0x0A /*!  b00001010 (ETE only) */
	ETE_PktTransCommit PktType = 0x0B /*!  b00001011 (ETE only) */

	/* cycle count packets */
	PktCcntF2          PktType = 0x0C /*!< b0000110x */
	PktCcntF1          PktType = 0x0E /*!< b0000111x */
	PktCcntF3          PktType = 0x10 /*!< b0001xxxx */

	// data synchronisation markers
	PktNumDsMkr        PktType = 0x20 /*!< b00100xxx */
	PktUnnumDsMkr      PktType = 0x28 /*!< b00101000 to b00101100 0x2C */

	// commit packets
	PktCommit          PktType = 0x30 /*!< b0011xxxx */

	// cancel packets
	PktCancelF1        PktType = 0x2E /*!< b00101110 */
	PktCancelF1Mispred PktType = 0x2F /*!< b00101111 */

	// mispredict packets
	PktMispredict      PktType = 0x30 /*!< b001100xx */
	PktCancelF2        PktType = 0x34 /*!< b001101xx */
	PktCancelF3        PktType = 0x38 /*!< b00111xxx */

	// condition codes
	PktCondIF2         PktType = 0x40 /*!< b0100000x */
	PktCondFlush       PktType = 0x43 /*!< b01000011 */
	PktCondResF4       PktType = 0x44 /*!< b0100010x */
	PktCondResF2       PktType = 0x48 /*!< b0100100x */
	PktCondResF3       PktType = 0x50 /*!< b0101xxxx */
	PktCondResF1       PktType = 0x68 /*!< b011010xx */
	PktCondIF1         PktType = 0x6C /*!< b01101100 */
	PktCondIF3         PktType = 0x6D /*!< b01101101 */

	PktIgnore          PktType = 0x70 /*!< b01110000 */
	PktEvent           PktType = 0x71 /*!< b01110001 */

	// address / context
	PktCtxtF1          PktType = 0x60 /*!< b0110xxxx */
	PktCtxtF2          PktType = 0x61 /*!< b0110xxxx */
	PktCtxtF3          PktType = 0x62 /*!< b0110xxxx */
	PktCtxtF4          PktType = 0x63 /*!< b0110xxxx */

	PktCtxt              PktType = 0x80 /*!< b1000xxxx */

	PktAddrCtxtL_32IS0   PktType = 0x82 /*!< b10000010  */
	PktAddrCtxtL_32IS1   PktType = 0x83 /*!< b10000011  */
	PktAddrCtxtL_64IS0   PktType = 0x85 /*!< b10000101  */
	PktAddrCtxtL_64IS1   PktType = 0x86 /*!< b10000110  */

	ETE_PktTSMarker      PktType = 0x88 /*!< b10001000 (ETE 1.1) */

	PktAddrMatch         PktType = 0x90 /*!< exact address match packet */

	PktAddrS_IS0         PktType = 0x95 /*!< Short addr IS0 */
	PktAddrS_IS1         PktType = 0x96 /*!< Short addr IS1 */

	PktAddrL_32IS0       PktType = 0x9A /*!< long address instruction format 5 */
	PktAddrL_32IS1       PktType = 0x9B /*!< long address instruction format 6 */
	PktAddrL_64IS0       PktType = 0x9D /*!< long address instruction format 7 */
	PktAddrL_64IS1       PktType = 0x9E /*!< long address instruction format 8 */

	PktQ               PktType = 0xA0 /*!< b1010xxxx */

	ETE_PktSrcAddrMatch   PktType = 0xB0
	ETE_PktSrcAddrS_IS0   PktType = 0xB4
	ETE_PktSrcAddrS_IS1   PktType = 0xB5
	ETE_PktSrcAddrL_32IS0 PktType = 0xB6
	ETE_PktSrcAddrL_32IS1 PktType = 0xB7
	ETE_PktSrcAddrL_64IS0 PktType = 0xB8
	ETE_PktSrcAddrL_64IS1 PktType = 0xB9

	// atoms
	PktAtomF6          PktType = 0xC0 /*!< b11000000 - b11010100 0xC0 - 0xD4, b11100000 - b11110100 0xE0 - 0xF4 */
	PktAtomF5          PktType = 0xD5 /*!< b11010101 - b11010111 0xD5 - 0xD7, b11110101 0xF5 */
	PktAtomF2          PktType = 0xD8 /*!< b110110xx to 0xDB */
	PktAtomF4          PktType = 0xDC /*!< b110111xx to 0xDF */
	PktAtomF1          PktType = 0xF6 /*!< b1111011x to 0xF7 */
	PktAtomF3          PktType = 0xF8 /*!< b11111xxx to 0xFF */

	// extension packets - follow 0x00 header
	PktAsync           PktType = 0x100 /*!< b00000000 */
	PktDiscard         PktType = 0x103 /*!< b00000011 */
	PktOverflow        PktType = 0x105 /*!< b00000101 */

	// ETE extended types 
	ETE_PktPeReset     PktType = 0x400 // base type is exception packet.
	ETE_PktTransFail   PktType = 0x401 // base type is exception packet.
)

// Info for TINFO packet.
type TraceInfo struct {
	CCEnabled        bool // 1 if cycle count enabled
	CondEnabled      uint8 // conditional trace enabled type.
	P0Load           bool // 1 if tracing with P0 load elements (for data trace)
	P0Store          bool // 1 if tracing with P0 store elements (for data trace)
	InTransState     bool // 1 if starting trace when in a transactional state (ETE trace).

	// internal decoder info for processing TINFO packets
	InitialTInfo     bool // 1 if this tinfo is the initial one used to start decode
	SpecFieldPresent bool // 1 if this tinfo had a spec depth field
}

// Trace context.
type Context struct {
	EL          uint8 // exception level.
	SF          bool  // sixty four bit
	NS          bool  // none secure
	Updated     bool  // updated this context packet (otherwise same as last time)
	UpdatedC    bool  // updated CtxtID
	UpdatedV    bool  // updated VMID
	NSE         bool  // PE FEAT_RME: root / realm indicator

	CtxtID      uint32 // Current ctxtID
	VMID        uint32 // current VMID
}

// Exception information.
type ExceptionInfo struct {
	ExceptionType uint16 // exception number
	AddrInterp    uint8  // address value interpretation
	MFaultPending bool   // M class fault pending.
	MType         bool   // 1 if M class exception.
}

type CondInstr struct {
	CondCKey     uint32
	NumCElem     uint8
	CondKeySet   bool
	F3FinalElem  bool
	F2CondIncr   bool
}

type CondResult struct {
	CondRKey0    uint32
	CondRKey1    uint32
	Res0         uint8
	Res1         uint8
	CI0          bool
	CI1          bool
	KeyRes0Set   bool
	KeyRes1Set   bool
	F2KeyIncr    uint8
	F2F4Token    uint8
	F3Tokens     uint16
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
	Context       bool
	Timestamp     bool
	CycleCount    bool
	CCThreshold   bool
	TInfo         bool
	TraceOnReason bool
	CommitElem    bool
	CancelElem    bool
	CondInstr     bool
	CondResult    bool
}

// Trace packet element.
type TracePacket struct {
	Type          PktType
	ErrType       PktType
	ErrHdrVal     uint8

	// intra-packet data - valid across packets.
	VAddr         ocsd.VAddr
	VAddrISA      uint8
	Context       Context

	Timestamp     uint64
	TSBitsChanged uint8

	CCThreshold   uint32

	// single packet data - only valid for specific packet types on packet instance.
	Atom          ocsd.PktAtom
	CycleCount    uint32

	CurrSpecDepth uint32
	P0Key         uint32

	CommitElements uint32
	CancelElements uint32

	TraceInfo     TraceInfo

	ExceptionInfo ExceptionInfo

	AddrExactMatchIdx uint8
	DsmVal            uint8
	EventVal          uint8

	CondInstr     CondInstr
	CondResult    CondResult
	QPkt          QPkt
	ITEPkt        ITEPkt

	Valid         Valid
	
	ProtocolVersion uint8
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
		return "I_ETE_ITE"
	case ETE_PktTransSt:
		return "I_ETE_TRANS_ST"
	case ETE_PktTransCommit:
		return "I_ETE_TRANS_COMMIT"
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
		return "ETE_PKT_I_SRC_ADDR_MATCH"
	case ETE_PktSrcAddrS_IS0:
		return "ETE_PKT_I_SRC_ADDR_S_IS0"
	case ETE_PktSrcAddrS_IS1:
		return "ETE_PKT_I_SRC_ADDR_S_IS1"
	case ETE_PktSrcAddrL_32IS0:
		return "ETE_PKT_I_SRC_ADDR_L_32IS0"
	case ETE_PktSrcAddrL_32IS1:
		return "ETE_PKT_I_SRC_ADDR_L_32IS1"
	case ETE_PktSrcAddrL_64IS0:
		return "ETE_PKT_I_SRC_ADDR_L_64IS0"
	case ETE_PktSrcAddrL_64IS1:
		return "ETE_PKT_I_SRC_ADDR_L_64IS1"
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
		return "I_ETE_PE_RESET"
	case ETE_PktTransFail:
		return "I_ETE_TRANS_FAIL"
	}
	return "I_UNKNOWN"
}
