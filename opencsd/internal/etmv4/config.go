package etmv4

import "opencsd/internal/ocsd"

type CondType int

const (
	CondPassFail CondType = iota
	CondHasAspr
)

type QSuppType int

const (
	QNone QSuppType = iota
	QCountOnly
	QNoCountOnly
	QFull
)

type LSP0Type int

const (
	LSP0None LSP0Type = iota
	LSP0L
	LSP0S
	LSP0LS
)

type CondITraceType int

const (
	CondTrDis  CondITraceType = 0
	CondTrLd   CondITraceType = 1
	CondTrSt   CondITraceType = 2
	CondTrLdSt CondITraceType = 3
	CondTrAll  CondITraceType = 7
)

type Config struct {
	RegIdr0       uint32
	RegIdr1       uint32
	RegIdr2       uint32
	RegIdr8       uint32
	RegIdr9       uint32
	RegIdr10      uint32
	RegIdr11      uint32
	RegIdr12      uint32
	RegIdr13      uint32
	RegConfigr    uint32
	RegTraceidr   uint32
	RegVipcssctlr uint32
	RegVinstcctlr uint32
	RegViiectlr   uint32
	RegVissctlr   uint32
	RegVipciectlr uint32
	RegVseqr      uint32
	ArchVer       ocsd.ArchVersion
	CoreProf      ocsd.CoreProfile
}

const (
	idr0LSasInstP0Mask       uint32 = 0x6
	idr0DataTraceMask        uint32 = 0x18
	idr0BranchBroadcastBit   uint32 = 0x20
	idr0CondTraceBit         uint32 = 0x40
	idr0CycleCountIBit       uint32 = 0x80
	idr0RetStackBit          uint32 = 0x200
	idr0CondTypeMask         uint32 = 0x3000
	idr0CondTypeASPR         uint32 = 0x1000
	idr0QFilterBit           uint32 = 0x4000
	idr0TrcExcpDataBit       uint32 = 0x20000
	idr0EteTSMarkerBit       uint32 = 0x800000
	idr0CommitOpt1Bit        uint32 = 0x20000000
	idr0CommTransP0ClearMask uint32 = 0x40000000

	idr2VmidOptBit       uint32 = 0x20000000
	idr2VmidOptV45Bit    uint32 = 1 << 30
	idr2WfiwfeBranchBit  uint32 = 0x80000000
	configDataAddrBit    uint32 = 1 << 16
	configDataValueBit   uint32 = 1 << 17
	configBranchBroadBit uint32 = 1 << 3
	configCCIEnableBit   uint32 = 1 << 4
	configCIDEnableBit   uint32 = 1 << 6
	configVMIDEnableBit  uint32 = 1 << 7
	configVMIDOptBit     uint32 = 1 << 15
	configTSEnableBit    uint32 = 1 << 11
	configRetStackBit    uint32 = 1 << 12
)

var condITraceTypes = map[uint32]CondITraceType{
	1: CondTrLd,
	2: CondTrSt,
	3: CondTrLdSt,
	7: CondTrAll,
}

func hasAll(value, mask uint32) bool                     { return value&mask == mask }
func hasAny(value, mask uint32) bool                     { return value&mask != 0 }
func field(value uint32, shift uint, mask uint32) uint32 { return (value >> shift) & mask }

func bits32or64(encoded uint32) uint32 {
	if encoded == 0 {
		return 0
	}
	if encoded == 0x8 {
		return 64
	}
	return 32
}

func (c *Config) LSasInstP0() bool { return hasAll(c.RegIdr0, idr0LSasInstP0Mask) }

func (c *Config) HasDataTrace() bool { return hasAll(c.RegIdr0, idr0DataTraceMask) }

func (c *Config) HasBranchBroadcast() bool { return hasAll(c.RegIdr0, idr0BranchBroadcastBit) }

func (c *Config) HasCondTrace() bool { return hasAll(c.RegIdr0, idr0CondTraceBit) }

func (c *Config) HasCycleCountI() bool { return hasAll(c.RegIdr0, idr0CycleCountIBit) }

func (c *Config) HasRetStack() bool { return hasAll(c.RegIdr0, idr0RetStackBit) }

func (c *Config) NumEvents() uint8 { return uint8(field(c.RegIdr0, 10, 0x3) + 1) }

func (c *Config) HasCondType() CondType {
	if c.RegIdr0&idr0CondTypeMask == idr0CondTypeASPR {
		return CondHasAspr
	}
	return CondPassFail
}

func (c *Config) QSuppType() QSuppType { return QSuppType(field(c.RegIdr0, 15, 0x3)) }

func (c *Config) HasQElem() bool { return c.QSuppType() != QNone }

func (c *Config) HasQFilter() bool { return hasAll(c.RegIdr0, idr0QFilterBit) && c.HasQElem() }

func (c *Config) HasTrcExcpData() bool { return hasAll(c.RegIdr0, idr0TrcExcpDataBit) }

func (c *Config) EteHasTSMarker() bool {
	return c.FullVersion() >= 0x51 && hasAll(c.RegIdr0, idr0EteTSMarkerBit)
}

func (c *Config) TimeStampSize() uint32 {
	switch field(c.RegIdr0, 24, 0x1F) {
	case 0x6:
		return 48
	case 0x8:
		return 64
	default:
		return 0
	}
}

func (c *Config) CommitOpt1() bool { return hasAll(c.RegIdr0, idr0CommitOpt1Bit) && c.HasCycleCountI() }

func (c *Config) CommTransP0() bool { return c.RegIdr0&idr0CommTransP0ClearMask == 0 }

func (c *Config) MajVersion() uint8 { return uint8(field(c.RegIdr1, 8, 0xF)) }

func (c *Config) MinVersion() uint8 { return uint8(field(c.RegIdr1, 4, 0xF)) }

func (c *Config) FullVersion() uint8 { return (c.MajVersion() << 4) | c.MinVersion() }

func (c *Config) IaSizeMax() uint32 {
	if field(c.RegIdr2, 0, 0x1F) == 0x8 {
		return 64
	}
	return 32
}

func (c *Config) CidSize() uint32 {
	if field(c.RegIdr2, 5, 0x1F) == 0x4 {
		return 32
	}
	return 0
}

func (c *Config) VmidSize() uint32 {
	vmidszF := field(c.RegIdr2, 10, 0x1F)
	if vmidszF == 1 {
		return 8
	}
	if c.FullVersion() <= 0x40 {
		return 0
	}
	switch vmidszF {
	case 2:
		return 16
	case 4:
		return 32
	default:
		return 0
	}
}

func (c *Config) DaSize() uint32 { return bits32or64(field(c.RegIdr2, 15, 0x1F)) }

func (c *Config) DvSize() uint32 { return bits32or64(field(c.RegIdr2, 20, 0x1F)) }

func (c *Config) CcSize() uint32 { return field(c.RegIdr2, 25, 0xF) + 12 }

func (c *Config) VmidOpt() bool { return hasAll(c.RegIdr2, idr2VmidOptBit) && c.MinVersion() > 0 }

func (c *Config) WfiwfeBranch() bool {
	return hasAny(c.RegIdr2, idr2WfiwfeBranchBit) && c.FullVersion() >= 0x43
}

func (c *Config) MaxSpecDepth() uint32 { return c.RegIdr8 }

func (c *Config) P0_Key_Max() uint32 {
	if c.RegIdr9 == 0 {
		return 1
	}
	return c.RegIdr9
}

func (c *Config) P1_Key_Max() uint32      { return c.RegIdr10 }
func (c *Config) P1_Spcl_Key_Max() uint32 { return c.RegIdr11 }
func (c *Config) CondKeyMax() uint32      { return c.RegIdr12 }
func (c *Config) CondSpecKeyMax() uint32  { return c.RegIdr13 }
func (c *Config) CondKeyMaxIncr() uint32  { return c.RegIdr12 - c.RegIdr13 }
func (c *Config) TraceID() uint8          { return uint8(c.RegTraceidr & 0x7F) }

func (c *Config) EnabledLSP0Trace() bool { return hasAny(c.RegConfigr, 0x6) }

func (c *Config) EnabledDVTrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && hasAny(c.RegConfigr, configDataValueBit)
}

func (c *Config) EnabledDATrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && hasAny(c.RegConfigr, configDataAddrBit)
}

func (c *Config) EnabledDataTrace() bool { return c.EnabledDATrace() || c.EnabledDVTrace() }

func (c *Config) LSP0Type() LSP0Type { return LSP0Type((c.RegConfigr & 0x6) >> 1) }

func (c *Config) EnabledBrBroad() bool { return hasAny(c.RegConfigr, configBranchBroadBit) }

func (c *Config) EnabledCCI() bool { return hasAny(c.RegConfigr, configCCIEnableBit) }

func (c *Config) EnabledCID() bool { return hasAny(c.RegConfigr, configCIDEnableBit) }

func (c *Config) EnabledVMID() bool { return hasAny(c.RegConfigr, configVMIDEnableBit) }

func (c *Config) EnabledVMIDOpt() bool {
	if c.VmidOpt() {
		return hasAny(c.RegConfigr, configVMIDOptBit)
	}
	return c.FullVersion() >= 0x45 && hasAny(c.RegIdr2, idr2VmidOptV45Bit)
}

func (c *Config) EnabledCondITrace() CondITraceType {
	if typ, ok := condITraceTypes[field(c.RegConfigr, 8, 0x7)]; ok {
		return typ
	}
	return CondTrDis
}

func (c *Config) EnabledTS() bool { return hasAny(c.RegConfigr, configTSEnableBit) }

func (c *Config) EnabledRetStack() bool { return hasAny(c.RegConfigr, configRetStackBit) }

func (c *Config) EnabledQE() bool { return hasAny(c.RegConfigr, 3<<13) }
