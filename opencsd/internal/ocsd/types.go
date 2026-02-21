package ocsd

// Trace Indexing and Channel IDs

// TrcIndex is the trace source index type.
// Equivalent to ocsd_trc_index_t 64-bit fallback.
type TrcIndex uint64

const (
	// BadTrcIndex is an invalid trace index value
	BadTrcIndex TrcIndex = ^TrcIndex(0)

	// BadCSSrcID is an invalid trace source ID value
	BadCSSrcID uint8 = 0xFF
)

// IsValidCSSrcID returns true if trace source ID is in valid range (0x0 < ID < 0x70)
func IsValidCSSrcID(id uint8) bool {
	return id > 0 && id < 0x70
}

// IsReservedCSSrcID returns true if trace source ID is in reserved range (ID == 0 || 0x70 <= ID <= 0x7F)
func IsReservedCSSrcID(id uint8) bool {
	return id == 0 || (id >= 0x70 && id <= 0x7F)
}

// General Library Return and Error Codes

// Err represents library error return type
type Err uint32

const (
	OK                       Err = 0
	ErrFail                  Err = 1
	ErrMem                   Err = 2
	ErrNotInit               Err = 3
	ErrInvalidID             Err = 4
	ErrBadHandle             Err = 5
	ErrInvalidParamVal       Err = 6
	ErrInvalidParamType      Err = 7
	ErrFileError             Err = 8
	ErrNoProtocol            Err = 9
	ErrAttachTooMany         Err = 10
	ErrAttachInvalidParam    Err = 11
	ErrAttachCompNotFound    Err = 12
	ErrRdrFileNotFound       Err = 13
	ErrRdrInvalidInit        Err = 14
	ErrRdrNoDecoder          Err = 15
	ErrDataDecodeFatal       Err = 16
	ErrDfrmtrNotconttrace    Err = 17
	ErrDfrmtrBadFhsync       Err = 18
	ErrBadPacketSeq          Err = 19
	ErrInvalidPcktHdr        Err = 20
	ErrPktInterpFail         Err = 21
	ErrUnsupportedISA        Err = 22
	ErrHWCfgUnsupp           Err = 23
	ErrUnsuppDecodePkt       Err = 24
	ErrBadDecodePkt          Err = 25
	ErrCommitPktOverrun      Err = 26
	ErrMemNacc               Err = 27
	ErrRetStackOverflow      Err = 28
	ErrDcdtNoFormatter       Err = 29
	ErrMemAccOverlap         Err = 30
	ErrMemAccFileNotFound    Err = 31
	ErrMemAccFileDiffRange   Err = 32
	ErrMemAccRangeInvalid    Err = 33
	ErrMemAccBadLen          Err = 34
	ErrTestSnapshotParse     Err = 35
	ErrTestSnapshotParseInfo Err = 36
	ErrTestSnapshotRead      Err = 37
	ErrTestSSToDecoder       Err = 38
	ErrDcdregNameRepeat      Err = 39
	ErrDcdregNameUnknown     Err = 40
	ErrDcdregTypeUnknown     Err = 41
	ErrDcdregToomany         Err = 42
	ErrDcdInterfaceUnused    Err = 43
	ErrInvalidOpcode         Err = 44
	ErrIRangeLimitOverrun    Err = 45
	ErrBadDecodeImage        Err = 46
	ErrLast                  Err = 47
)

type HandleRdr uint32
type HandleErrLog uint32

const InvalidHandle uint32 = 0xFFFFFFFF

// ErrSeverity used to indicate the severity of an error or logger verbosity
type ErrSeverity uint32

const (
	ErrSevNone  ErrSeverity = 0
	ErrSevError ErrSeverity = 1
	ErrSevWarn  ErrSeverity = 2
	ErrSevInfo  ErrSeverity = 3
)

// Trace Datapath

// DatapathOp represents trace datapath operations.
type DatapathOp uint32

const (
	OpData  DatapathOp = 0
	OpEOT   DatapathOp = 1
	OpFlush DatapathOp = 2
	OpReset DatapathOp = 3
)

// DatapathResp represents trace datapath responses.
type DatapathResp uint32

const (
	RespCont              DatapathResp = 0
	RespWarnCont          DatapathResp = 1
	RespErrCont           DatapathResp = 2
	RespWait              DatapathResp = 3
	RespWarnWait          DatapathResp = 4
	RespErrWait           DatapathResp = 5
	RespFatalNotInit      DatapathResp = 6
	RespFatalInvalidOp    DatapathResp = 7
	RespFatalInvalidParam DatapathResp = 8
	RespFatalInvalidData  DatapathResp = 9
	RespFatalSysErr       DatapathResp = 10
)

func DataRespIsFatal(x DatapathResp) bool     { return x >= RespFatalNotInit }
func DataRespIsWarn(x DatapathResp) bool      { return x == RespWarnCont || x == RespWarnWait }
func DataRespIsErr(x DatapathResp) bool       { return x == RespErrCont || x == RespErrWait }
func DataRespIsWarnOrErr(x DatapathResp) bool { return DataRespIsErr(x) || DataRespIsWarn(x) }
func DataRespIsCont(x DatapathResp) bool      { return x < RespWait }
func DataRespIsWait(x DatapathResp) bool      { return x >= RespWait && x < RespFatalNotInit }

// Trace Decode component types

type RawframeElem uint32

const (
	FrmNone   RawframeElem = 0
	FrmPacked RawframeElem = 1
	FrmHsync  RawframeElem = 2
	FrmFsync  RawframeElem = 3
	FrmIDData RawframeElem = 4
)

type DcdTreeSrc uint32

const (
	TrcSrcFrameFormatted DcdTreeSrc = 0
	TrcSrcSingle         DcdTreeSrc = 1
)

const (
	DfrmtrHasFsyncs      = 0x01
	DfrmtrHasHsyncs      = 0x02
	DfrmtrFrameMemAlign  = 0x04
	DfrmtrPackedRawOut   = 0x08
	DfrmtrUnpackedRawOut = 0x10
	DfrmtrResetOn4xFsync = 0x20
	DfrmtrValidMask      = 0x3F

	DfrmtrFrameSize = 0x10
)

// Trace Decode Component Name Prefixes

const (
	CmpnamePrefixSourceReader     = "SRDR"
	CmpnamePrefixFramedeformatter = "DFMT"
	CmpnamePrefixPktproc          = "PKTP"
	CmpnamePrefixPktdec           = "PDEC"
)

// Trace Decode Arch and Profile

type ArchVersion uint32

const (
	ArchUnknown ArchVersion = 0x0000
	ArchCustom  ArchVersion = 0x0001
	ArchV7      ArchVersion = 0x0700
	ArchV8      ArchVersion = 0x0800
	ArchV8r3    ArchVersion = 0x0803
	ArchAA64    ArchVersion = 0x0864
	ArchV8max   ArchVersion = ArchAA64
)

func IsV8Arch(arch ArchVersion) bool              { return arch >= ArchV8 && arch <= ArchV8max }
func IsArchMinVer(arch, minArch ArchVersion) bool { return arch >= minArch }

type CoreProfile uint32

const (
	ProfileUnknown CoreProfile = 0
	ProfileCortexM CoreProfile = 1
	ProfileCortexR CoreProfile = 2
	ProfileCortexA CoreProfile = 3
	ProfileCustom  CoreProfile = 4
)

type ArchProfile struct {
	Arch    ArchVersion
	Profile CoreProfile
}

// VAddr type
type VAddr uint64

const (
	MaxVABitsize = 64
	VAMask       = ^uint64(0)
)

func BitMask(bits int) uint64 {
	if bits == MaxVABitsize {
		return VAMask
	}
	return (uint64(1) << bits) - 1
}

// Instruction Decode Information

type ISA uint32

const (
	ISAArm     ISA = 0
	ISAThumb2  ISA = 1
	ISAAArch64 ISA = 2
	ISATee     ISA = 3
	ISAJazelle ISA = 4
	ISACustom  ISA = 5
	ISAUnknown ISA = 6
)

type SecLevel uint32

const (
	SecSecure    SecLevel = 0
	SecNonsecure SecLevel = 1
	SecRoot      SecLevel = 2
	SecRealm     SecLevel = 3
)

type ExLevel int32

const (
	ELUnknown ExLevel = -1
	EL0       ExLevel = 0
	EL1       ExLevel = 1
	EL2       ExLevel = 2
	EL3       ExLevel = 3
)

type InstrType uint32

const (
	InstrOther      InstrType = 0
	InstrBr         InstrType = 1
	InstrBrIndirect InstrType = 2
	InstrIsb        InstrType = 3
	InstrDsbDmb     InstrType = 4
	InstrWfiWfe     InstrType = 5
	InstrTstart     InstrType = 6
)

type InstrSubtype uint32

const (
	SInstrNone         InstrSubtype = 0
	SInstrBrLink       InstrSubtype = 1
	SInstrV8Ret        InstrSubtype = 2
	SInstrV8Eret       InstrSubtype = 3
	SInstrV7ImpliedRet InstrSubtype = 4
)

type InstrInfo struct {
	PeType          ArchProfile
	Isa             ISA
	InstrAddr       VAddr
	Opcode          uint32
	DsbDmbWaypoints uint8
	WfiWfeBranch    uint8
	TrackItBlock    uint8

	Type              InstrType
	BranchAddr        VAddr
	NextIsa           ISA
	InstrSize         uint8
	IsConditional     uint8
	IsLink            uint8
	ThumbItConditions uint8
	SubType           InstrSubtype
}

type PEContext struct {
	SecurityLevel  SecLevel
	ExceptionLevel ExLevel
	ContextID      uint32
	VMID           uint32
	bits           uint32 // backing field for bitfields
}

func (p *PEContext) Bits64() bool { return (p.bits & 1) != 0 }
func (p *PEContext) SetBits64(v bool) {
	if v {
		p.bits |= 1
	} else {
		p.bits &^= 1
	}
}

func (p *PEContext) CtxtIDValid() bool { return (p.bits & 2) != 0 }
func (p *PEContext) SetCtxtIDValid(v bool) {
	if v {
		p.bits |= 2
	} else {
		p.bits &^= 2
	}
}

func (p *PEContext) VMIDValid() bool { return (p.bits & 4) != 0 }
func (p *PEContext) SetVMIDValid(v bool) {
	if v {
		p.bits |= 4
	} else {
		p.bits &^= 4
	}
}

func (p *PEContext) ELValid() bool { return (p.bits & 8) != 0 }
func (p *PEContext) SetELValid(v bool) {
	if v {
		p.bits |= 8
	} else {
		p.bits &^= 8
	}
}

// Opcode Memory Access

type MemSpaceAcc uint32

const (
	MemSpaceNone MemSpaceAcc = 0x0
	MemSpaceEL1S MemSpaceAcc = 0x1
	MemSpaceEL1N MemSpaceAcc = 0x2
	MemSpaceEL2  MemSpaceAcc = 0x4
	MemSpaceEL3  MemSpaceAcc = 0x8
	MemSpaceEL2S MemSpaceAcc = 0x10
	MemSpaceEL1R MemSpaceAcc = 0x20
	MemSpaceEL2R MemSpaceAcc = 0x40
	MemSpaceRoot MemSpaceAcc = 0x80
	MemSpaceS    MemSpaceAcc = 0x19
	MemSpaceN    MemSpaceAcc = 0x6
	MemSpaceR    MemSpaceAcc = 0x60
	MemSpaceAny  MemSpaceAcc = 0xFF
)

type FileMemRegion struct {
	FileOffset   uint64 // size_t
	StartAddress VAddr
	RegionSize   uint64 // size_t
}

// Packet Processor Operation Control Flags

const (
	OpflgPktprocNofwdBadPkts    = 0x00000010
	OpflgPktprocNomonBadPkts    = 0x00000020
	OpflgPktprocErrBadPkts      = 0x00000040
	OpflgPktprocUnsyncOnBadPkts = 0x00000080

	OpflgPktprocCommon = OpflgPktprocNofwdBadPkts | OpflgPktprocNomonBadPkts | OpflgPktprocErrBadPkts | OpflgPktprocUnsyncOnBadPkts

	OpflgCompModeMask = 0xFFFF0000
)

// Packet Decoder Operation Control Flags

const (
	OpflgPktdecErrorBadPkts = 0x00000100
	OpflgPktdecHaltBadPkts  = 0x00000200
	OpflgNUncondDirBrChk    = 0x00000400
	OpflgStrictNUncondBrChk = 0x00000800
	OpflgChkRangeContinue   = 0x00001000
	OpflgNUncondChkNoThumb  = 0x00002000

	OpflgPktdecCommon = OpflgPktdecErrorBadPkts | OpflgPktdecHaltBadPkts | OpflgNUncondDirBrChk | OpflgStrictNUncondBrChk | OpflgChkRangeContinue | OpflgNUncondChkNoThumb
)

// Decoder creation information

const (
	CreateFlgPacketProc  = 0x01
	CreateFlgFullDecoder = 0x02
	CreateFlgInstID      = 0x04

	BuiltinDcdSTM    = "STM"
	BuiltinDcdETMV3  = "ETMV3"
	BuiltinDcdETMV4I = "ETMV4I"
	BuiltinDcdETMV4D = "ETMV4D"
	BuiltinDcdPTM    = "PTM"
	BuiltinDcdETE    = "ETE"
	BuiltinDcdITM    = "ITM"
)

type TraceProtocol uint32

const (
	ProtocolUnknown    TraceProtocol = 0
	ProtocolETMV3      TraceProtocol = 1
	ProtocolETMV4I     TraceProtocol = 2
	ProtocolETMV4D     TraceProtocol = 3
	ProtocolPTM        TraceProtocol = 4
	ProtocolSTM        TraceProtocol = 5
	ProtocolETE        TraceProtocol = 6
	ProtocolITM        TraceProtocol = 7
	ProtocolBuiltinEnd TraceProtocol = 8

	ProtocolCustom0 TraceProtocol = 100
	ProtocolCustom1 TraceProtocol = 101
	ProtocolCustom2 TraceProtocol = 102
	ProtocolCustom3 TraceProtocol = 103
	ProtocolCustom4 TraceProtocol = 104
	ProtocolCustom5 TraceProtocol = 105
	ProtocolCustom6 TraceProtocol = 106
	ProtocolCustom7 TraceProtocol = 107
	ProtocolCustom8 TraceProtocol = 108
	ProtocolCustom9 TraceProtocol = 109
	ProtocolEnd     TraceProtocol = 110
)

func ProtocolIsBuiltin(p TraceProtocol) bool { return p > ProtocolUnknown && p < ProtocolBuiltinEnd }
func ProtocolIsCustom(p TraceProtocol) bool  { return p >= ProtocolCustom0 && p < ProtocolEnd }

// Software Trace Packets Info

type SWTInfo struct {
	MasterID  uint16
	ChannelID uint16
	FlagBits  uint32
}

func (s *SWTInfo) PayloadPktBitsize() uint8 { return uint8(s.FlagBits & 0xFF) }
func (s *SWTInfo) SetPayloadPktBitsize(v uint8) {
	s.FlagBits = (s.FlagBits &^ 0xFF) | uint32(v)
}

func (s *SWTInfo) PayloadNumPackets() uint8 { return uint8((s.FlagBits >> 8) & 0xFF) }
func (s *SWTInfo) SetPayloadNumPackets(v uint8) {
	s.FlagBits = (s.FlagBits &^ (0xFF << 8)) | (uint32(v) << 8)
}

func (s *SWTInfo) MarkerPacket() bool { return (s.FlagBits & (1 << 16)) != 0 }
func (s *SWTInfo) SetMarkerPacket(v bool) {
	if v {
		s.FlagBits |= (1 << 16)
	} else {
		s.FlagBits &^= (1 << 16)
	}
}

func (s *SWTInfo) HasTimestamp() bool { return (s.FlagBits & (1 << 17)) != 0 }
func (s *SWTInfo) SetHasTimestamp(v bool) {
	if v {
		s.FlagBits |= (1 << 17)
	} else {
		s.FlagBits &^= (1 << 17)
	}
}

func (s *SWTInfo) MarkerFirst() bool { return (s.FlagBits & (1 << 18)) != 0 }
func (s *SWTInfo) SetMarkerFirst(v bool) {
	if v {
		s.FlagBits |= (1 << 18)
	} else {
		s.FlagBits &^= (1 << 18)
	}
}

func (s *SWTInfo) MasterErr() bool { return (s.FlagBits & (1 << 19)) != 0 }
func (s *SWTInfo) SetMasterErr(v bool) {
	if v {
		s.FlagBits |= (1 << 19)
	} else {
		s.FlagBits &^= (1 << 19)
	}
}

func (s *SWTInfo) GlobalErr() bool { return (s.FlagBits & (1 << 20)) != 0 }
func (s *SWTInfo) SetGlobalErr(v bool) {
	if v {
		s.FlagBits |= (1 << 20)
	} else {
		s.FlagBits &^= (1 << 20)
	}
}

func (s *SWTInfo) TriggerEvent() bool { return (s.FlagBits & (1 << 21)) != 0 }
func (s *SWTInfo) SetTriggerEvent(v bool) {
	if v {
		s.FlagBits |= (1 << 21)
	} else {
		s.FlagBits &^= (1 << 21)
	}
}

func (s *SWTInfo) Frequency() bool { return (s.FlagBits & (1 << 22)) != 0 }
func (s *SWTInfo) SetFrequency(v bool) {
	if v {
		s.FlagBits |= (1 << 22)
	} else {
		s.FlagBits &^= (1 << 22)
	}
}

func (s *SWTInfo) IDValid() bool { return (s.FlagBits & (1 << 23)) != 0 }
func (s *SWTInfo) SetIDValid(v bool) {
	if v {
		s.FlagBits |= (1 << 23)
	} else {
		s.FlagBits &^= (1 << 23)
	}
}

const SwtIDValidMask = 0x1 << 23

// Demux Statistics

type DemuxStats struct {
	ValidIDBytes    uint64
	NoIDBytes       uint64
	ReservedIDBytes uint64
	UnknownIDBytes  uint64
	FrameBytes      uint64
}

// Decode statistics

type DecodeStats struct {
	Version         uint32
	Revision        uint16
	ChannelTotal    uint64
	ChannelUnsynced uint64
	BadHeaderErrs   uint32
	BadSequenceErrs uint32
	Demux           DemuxStats
}

const StatsRevision = 0x1
