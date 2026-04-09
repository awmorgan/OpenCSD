package ocsd

import "errors"

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

var (
	ErrFail                  = errors.New("general failure")
	ErrMem                   = errors.New("internal memory allocation error")
	ErrNotInit               = errors.New("component not initialised")
	ErrInvalidID             = errors.New("invalid CoreSight Trace Source ID")
	ErrBadHandle             = errors.New("invalid handle passed to component")
	ErrInvalidParamVal       = errors.New("invalid value parameter passed to component")
	ErrInvalidParamType      = errors.New("type mismatch on abstract interface")
	ErrFileError             = errors.New("file access error")
	ErrNoProtocol            = errors.New("trace protocol unsupported")
	ErrAttachTooMany         = errors.New("cannot attach - attach device limit reached")
	ErrAttachInvalidParam    = errors.New("cannot attach - invalid parameter")
	ErrAttachCompNotFound    = errors.New("cannot detach - component not found")
	ErrRdrFileNotFound       = errors.New("source reader - file not found")
	ErrRdrInvalidInit        = errors.New("source reader - invalid initialisation parameter")
	ErrRdrNoDecoder          = errors.New("source reader - no trace decoder set")
	ErrDataDecodeFatal       = errors.New("a decoder in the data path has returned a fatal error")
	ErrDfrmtrNotconttrace    = errors.New("trace input to deformatter non-continuous")
	ErrDfrmtrBadFhsync       = errors.New("bad frame or half frame sync in trace deformatter")
	ErrBadPacketSeq          = errors.New("bad packet sequence")
	ErrInvalidPcktHdr        = errors.New("invalid packet header")
	ErrPktInterpFail         = errors.New("interpreter failed - cannot recover - bad data or sequence")
	ErrUnsupportedISA        = errors.New("ISA not supported in decoder")
	ErrHWCfgUnsupp           = errors.New("programmed trace configuration not supported by decoder")
	ErrUnsuppDecodePkt       = errors.New("packet not supported in decoder")
	ErrBadDecodePkt          = errors.New("reserved or unknown packet in decoder")
	ErrCommitPktOverrun      = errors.New("overrun in commit packet stack - tried to commit more than available")
	ErrMemNacc               = errors.New("unable to access required memory address")
	ErrRetStackOverflow      = errors.New("internal return stack overflow checks failed - popped more than we pushed")
	ErrDcdtNoFormatter       = errors.New("no formatter in use - operation not valid")
	ErrMemAccOverlap         = errors.New("attempted to set an overlapping range in memory access map")
	ErrMemAccFileNotFound    = errors.New("memory access file could not be opened")
	ErrMemAccFileDiffRange   = errors.New("attempt to re-use the same memory access file for a different address range")
	ErrMemAccRangeInvalid    = errors.New("address range in accessor set to invalid values")
	ErrMemAccBadLen          = errors.New("memory accessor returned a bad read length value (larger than requested)")
	ErrTestSnapshotParse     = errors.New("test snapshot file parse error")
	ErrTestSnapshotParseInfo = errors.New("test snapshot file parse information")
	ErrTestSnapshotRead      = errors.New("test snapshot reader error")
	ErrTestSSToDecoder       = errors.New("test snapshot to decode tree conversion error")
	ErrDcdregNameRepeat      = errors.New("attempted to register a decoder with the same name as another one")
	ErrDcdregNameUnknown     = errors.New("attempted to find a decoder with a name that is not known in the library")
	ErrDcdregTypeUnknown     = errors.New("attempted to find a decoder with a type that is not known in the library")
	ErrDcdregToomany         = errors.New("attempted to register too many custom decoders")
	ErrDcdInterfaceUnused    = errors.New("attempt to connect or use and interface not supported by this decoder")
	ErrInvalidOpcode         = errors.New("illegal Opcode found while decoding program memory")
	ErrIRangeLimitOverrun    = errors.New("an optional limit on consecutive instructions in range during decode has been exceeded")
	ErrBadDecodeImage        = errors.New("mismatch between trace packets and decode image")
)

type HandleRdr uint32
type HandleErrLog uint32

const InvalidHandle uint32 = 0xFFFFFFFF

// Generic error log handles, matching ITraceErrorLog::generic_handles in C++.
const (
	HandleGenErr                   HandleErrLog = 0 // generic handle for error messages
	HandleGenWarn                  HandleErrLog = 1 // generic handle for warning messages
	HandleGenInfo                  HandleErrLog = 2 // generic handle for info messages
	HandleFirstRegisteredComponent HandleErrLog = 3 // first valid handle for registered components
)

// ErrSeverity used to indicate the severity of an error or logger verbosity
type ErrSeverity uint32

const (
	ErrSevNone  ErrSeverity = 0
	ErrSevError ErrSeverity = 1
	ErrSevWarn  ErrSeverity = 2
	ErrSevInfo  ErrSeverity = 3
)

// DatapathResp is a transitional uint32 alias while datapath code migrates
// to standard Go error-only control flow.
type DatapathResp = uint32

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

// Transitional flow-control sentinel errors used while migrating datapath
// interfaces away from DatapathResp values.
var (
	ErrWait = errors.New("datapath flow-control wait")
)

func DataRespIsFatal(x DatapathResp) bool     { return x >= RespFatalNotInit }
func DataRespIsWarn(x DatapathResp) bool      { return x == RespWarnCont || x == RespWarnWait }
func DataRespIsErr(x DatapathResp) bool       { return x == RespErrCont || x == RespErrWait }
func DataRespIsWarnOrErr(x DatapathResp) bool { return DataRespIsErr(x) || DataRespIsWarn(x) }
func DataRespIsCont(x DatapathResp) bool      { return x < RespWait }
func DataRespIsWait(x DatapathResp) bool      { return x >= RespWait && x < RespFatalNotInit }

// IsDataWaitErr returns true when err is the flow-control wait sentinel.
func IsDataWaitErr(err error) bool { return errors.Is(err, ErrWait) }

// IsDataContErr returns true when err indicates continue semantics.
func IsDataContErr(err error) bool { return err == nil }

// DataRespFromErr maps transitional datapath sentinel errors to DatapathResp.
func DataRespFromErr(err error) DatapathResp {
	if IsDataContErr(err) {
		return RespCont
	}
	if IsDataWaitErr(err) {
		return RespWait
	}
	if errors.Is(err, ErrNotInit) {
		return RespFatalNotInit
	}
	if errors.Is(err, ErrInvalidParamVal) || errors.Is(err, ErrInvalidParamType) {
		return RespFatalInvalidParam
	}
	return RespFatalInvalidData
}

// DataErrFromResp maps legacy DatapathResp values to transitional error flow control.
func DataErrFromResp(resp DatapathResp, err error) error {
	if err != nil {
		return err
	}
	if DataRespIsCont(resp) {
		return nil
	}
	if DataRespIsWait(resp) {
		return ErrWait
	}
	switch resp {
	case RespFatalNotInit:
		return ErrNotInit
	case RespFatalInvalidParam, RespFatalInvalidOp:
		return ErrInvalidParamVal
	case RespFatalSysErr:
		return ErrFail
	default:
		return ErrDataDecodeFatal
	}
}

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
	ISA             ISA
	InstrAddr       VAddr
	Opcode          uint32
	DsbDmbWaypoints uint8
	WfiWfeBranch    uint8
	TrackItBlock    uint8

	Type              InstrType
	BranchAddr        VAddr
	NextISA           ISA
	InstrSize         uint8
	IsConditional     uint8
	IsLink            uint8
	ThumbItConditions uint8
	Subtype           InstrSubtype
}

type PEContext struct {
	SecurityLevel  SecLevel
	ExceptionLevel ExLevel
	ContextID      uint32
	VMID           uint32
	Bits64         bool
	CtxtIDValid    bool
	VMIDValid      bool
	ELValid        bool
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
	OpflgPktdecErrorBadPkts  = 0x00000100
	OpflgPktdecHaltBadPkts   = 0x00000200
	OpflgNUncondDirBrChk     = 0x00000400
	OpflgStrictNUncondBrChk  = 0x00000800
	OpflgChkRangeContinue    = 0x00001000
	OpflgNUncondChkNoThumb   = 0x00002000
	OpflgPktdecSrcAddrNAtoms = 0x00010000
	OpflgPktdecAA64OpcodeChk = 0x00020000

	OpflgPktdecCommon = OpflgPktdecErrorBadPkts | OpflgPktdecHaltBadPkts | OpflgNUncondDirBrChk | OpflgStrictNUncondBrChk | OpflgChkRangeContinue | OpflgNUncondChkNoThumb
)

// Decoder creation information

const (
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
	MasterID          uint16
	ChannelID         uint16
	PayloadPktBitsize uint8
	PayloadNumPackets uint8
	MarkerPacket      bool
	HasTimestamp      bool
	MarkerFirst       bool
	MasterErr         bool
	GlobalErr         bool
	TriggerEvent      bool
	Frequency         bool
	IDValid           bool
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

// Library version constants, matching OCSD_VER_MAJOR/MINOR/PATCH and OCSD_VER_NUM in ocsd_if_version.h.
const (
	VerMajor = 0x1
	VerMinor = 0x8
	VerPatch = 0x0
	VerNum   = (VerMajor << 16) | (VerMinor << 8) | VerPatch // 0x010800
)
