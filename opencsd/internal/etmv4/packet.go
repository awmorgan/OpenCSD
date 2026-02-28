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
	PktCancelF1        PktType = 0x40 /*!< b01000000 */
	// mispredict packets
	PktMispredict      PktType = 0x41 /*!< b01000001 */
	PktCancelF2        PktType = 0x42 /*!< b01000010 */
	PktCancelF3        PktType = 0x43 /*!< b01000011 */

	// address / context
	PktCtxtF1          PktType = 0x60 /*!< b0110xxxx */
	PktCtxtF2          PktType = 0x61 /*!< b0110xxxx */
	PktCtxtF3          PktType = 0x62 /*!< b0110xxxx */
	PktCtxtF4          PktType = 0x63 /*!< b0110xxxx */

	PktAddrCtxtF1      PktType = 0x80 /*!< b1000xxxx */
	PktAddrCtxtF2      PktType = 0x81 /*!< b1000xxxx */

	PktAddrCtxtF3      PktType = 0x82 /*!< b1000xxxx */
	PktAddrCtxtF4      PktType = 0x83 /*!< b1000xxxx */
	PktAddrCtxtF5      PktType = 0x84 /*!< b1000xxxx */
	PktAddrCtxtF6      PktType = 0x85 /*!< b1000xxxx */

	PktAddrMatch       PktType = 0x86 /*!< exact address match packet */
	PktAddrCtxtF3_6    PktType = 0x87 /*!< b1000xxxx */

	PktAddrMatch_IS0   PktType = 0x88 /*!< exact match + IS0 */
	PktAddrMatch_IS1   PktType = 0x89 /*!< exact match + IS1 */

	PktShortAddrCtxt   PktType = 0x8a /*!< Short addr + ctx */
	PktShortAddr       PktType = 0x8b /*!< Short addr */

	PktAddrF1          PktType = 0x90 /*!< b1001xxxx */
	PktAddrF2          PktType = 0x91 /*!< b1001xxxx */
	PktAddrF3          PktType = 0x92 /*!< b1001xxxx */
	PktAddrF4          PktType = 0x93 /*!< b1001xxxx */
	PktAddrF5          PktType = 0x9A /*!< long address instruction format 5 */
	PktAddrF6          PktType = 0x9B /*!< long address instruction format 6 */

	PktQ               PktType = 0xA0 /*!< b1010xxxx */

	// Instruction Condition Result
	PktCondResF1       PktType = 0xB0 /*!< b101100xx */
	PktCondResF2       PktType = 0xB4 /*!< b1011010x */
	PktCondResF3       PktType = 0xB6 /*!< b10110110 */
	PktCondResF4       PktType = 0xB7 /*!< b10110111 */

	PktCondInstrF1     PktType = 0xB8 /*!< b10111xx0 */
	PktCondInstrF2     PktType = 0xB9 /*!< b10111001 */
	PktCondInstrF3     PktType = 0xBB /*!< b10111011 */
	PktEvent           PktType = 0xBD /*!< b10111101 */
	PktRes0            PktType = 0xBE /*!< b1011111x */

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
	case PktMispredict:
		return "I_MISPREDICT"
	case PktCancelF2:
		return "I_CANCEL_F2"
	case PktCancelF3:
		return "I_CANCEL_F3"
	case PktCtxtF1:
		return "I_CTXT_F1"
	case PktCtxtF2:
		return "I_CTXT_F2"
	case PktCtxtF3:
		return "I_CTXT_F3"
	case PktCtxtF4:
		return "I_CTXT_F4"
	case PktAddrCtxtF1:
		return "I_ADDR_CTXT_F1"
	case PktAddrCtxtF2:
		return "I_ADDR_CTXT_F2"
	case PktAddrCtxtF3:
		return "I_ADDR_CTXT_F3"
	case PktAddrCtxtF4:
		return "I_ADDR_CTXT_F4"
	case PktAddrCtxtF5:
		return "I_ADDR_CTXT_F5"
	case PktAddrCtxtF6:
		return "I_ADDR_CTXT_F6"
	case PktAddrMatch:
		return "I_ADDR_MATCH"
	case PktAddrCtxtF3_6:
		return "I_ADDR_CTXT_F3_6"
	case PktAddrMatch_IS0:
		return "I_ADDR_MATCH_IS0"
	case PktAddrMatch_IS1:
		return "I_ADDR_MATCH_IS1"
	case PktShortAddrCtxt:
		return "I_SHORT_ADDR_CTXT"
	case PktShortAddr:
		return "I_SHORT_ADDR"
	case PktAddrF1:
		return "I_ADDR_F1"
	case PktAddrF2:
		return "I_ADDR_F2"
	case PktAddrF3:
		return "I_ADDR_F3"
	case PktAddrF4:
		return "I_ADDR_F4"
	case PktAddrF5:
		return "I_ADDR_F5"
	case PktAddrF6:
		return "I_ADDR_F6"
	case PktQ:
		return "I_Q"
	case PktCondResF1:
		return "I_COND_RES_F1"
	case PktCondResF2:
		return "I_COND_RES_F2"
	case PktCondResF3:
		return "I_COND_RES_F3"
	case PktCondResF4:
		return "I_COND_RES_F4"
	case PktCondInstrF1:
		return "I_COND_INSTR_F1"
	case PktCondInstrF2:
		return "I_COND_INSTR_F2"
	case PktCondInstrF3:
		return "I_COND_INSTR_F3"
	case PktEvent:
		return "I_EVENT"
	case PktRes0:
		return "I_RES_0"
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
