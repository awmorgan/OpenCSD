package etmv4

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"opencsd/common"
)

// ArchVersion matches ocsd_arch_version_t values.
type ArchVersion uint32

const (
	ArchUnknown ArchVersion = 0x0000
	ArchCustom  ArchVersion = 0x0001
	ArchV7      ArchVersion = 0x0700
	ArchV8      ArchVersion = 0x0800
	ArchV8r3    ArchVersion = 0x0803
	ArchAA64    ArchVersion = 0x0864
)

// CoreProfile matches ocsd_core_profile_t values.
type CoreProfile int

const (
	ProfileUnknown CoreProfile = iota
	ProfileCortexM
	ProfileCortexR
	ProfileCortexA
	ProfileCustom
)

// Config mirrors ocsd_etmv4_cfg.
type Config struct {
	RegIDR0     uint32
	RegIDR1     uint32
	RegIDR2     uint32
	RegIDR8     uint32
	RegIDR9     uint32
	RegIDR10    uint32
	RegIDR11    uint32
	RegIDR12    uint32
	RegIDR13    uint32
	RegCONFIGR  uint32
	RegTRACEIDR uint32
	RegAUTHSTAT uint32
	ArchVer     ArchVersion
	CoreProf    CoreProfile
}

// QSuppType indicates the Q element support level.
type QSuppType int

const (
	QNone QSuppType = iota
	QICountOnly
	QNoICountOnly
	QFull
)

// CondType indicates conditional trace encoding type.
type CondType int

const (
	CondPassFail CondType = iota
	CondHasASPR
)

// LSP0Type indicates Load/Store P0 trace enable type.
type LSP0Type int

const (
	LSP0None LSP0Type = iota
	LSP0L
	LSP0S
	LSP0LS
)

// CondITraceType indicates conditional instruction trace setting.
type CondITraceType int

const (
	CondTraceDisabled CondITraceType = iota
	CondTraceLoad
	CondTraceStore
	CondTraceLoadStore
	CondTraceAll
)

// EtmV4Config provides helper accessors for ETMv4 config registers.
type EtmV4Config struct {
	cfg Config

	qSuppCalc   bool
	qSuppFilter bool
	qSuppType   QSuppType

	vmidSzCalc bool
	vmidSize   uint32

	condTraceCalc bool
	condTrace     CondITraceType

	majVer uint8
	minVer uint8
}

// NewConfig returns a default ETMv4 config helper with default register values.
func NewConfig() *EtmV4Config {
	cfg := Config{
		RegIDR0:     0x28000EA1,
		RegIDR1:     0x4100F403,
		RegIDR2:     0x00000488,
		RegIDR8:     0,
		RegIDR9:     0,
		RegIDR10:    0,
		RegIDR11:    0,
		RegIDR12:    0,
		RegIDR13:    0,
		RegCONFIGR:  0xC1,
		RegTRACEIDR: 0,
		ArchVer:     ArchV7,
		CoreProf:    ProfileCortexA,
	}
	return NewConfigFrom(cfg)
}

// NewConfigFrom returns a config helper using the supplied register values.
func NewConfigFrom(cfg Config) *EtmV4Config {
	c := &EtmV4Config{cfg: cfg}
	c.privateInit()
	return c
}

// Config returns the underlying config values.
func (c *EtmV4Config) Config() Config {
	return c.cfg
}

// TraceID returns the CoreSight trace ID.
func (c *EtmV4Config) TraceID() uint8 {
	return uint8(c.cfg.RegTRACEIDR & 0x7F)
}

// LSasInstP0 indicates that loads/stores are treated as instruction P0.
func (c *EtmV4Config) LSasInstP0() bool {
	return (c.cfg.RegIDR0 & 0x6) == 0x6
}

func (c *EtmV4Config) HasDataTrace() bool {
	return (c.cfg.RegIDR0 & 0x18) == 0x18
}

func (c *EtmV4Config) HasBranchBroadcast() bool {
	return (c.cfg.RegIDR0 & 0x20) == 0x20
}

func (c *EtmV4Config) HasCondTrace() bool {
	return (c.cfg.RegIDR0 & 0x40) == 0x40
}

func (c *EtmV4Config) HasCycleCountI() bool {
	return (c.cfg.RegIDR0 & 0x80) == 0x80
}

func (c *EtmV4Config) HasRetStack() bool {
	return (c.cfg.RegIDR0 & 0x200) == 0x200
}

func (c *EtmV4Config) NumEvents() uint8 {
	return uint8(((c.cfg.RegIDR0 >> 10) & 0x3) + 1)
}

func (c *EtmV4Config) HasCondType() CondType {
	if (c.cfg.RegIDR0 & 0x3000) == 0x1000 {
		return CondHasASPR
	}
	return CondPassFail
}

func (c *EtmV4Config) QSuppType() QSuppType {
	if !c.qSuppCalc {
		c.calcQSupp()
	}
	return c.qSuppType
}

func (c *EtmV4Config) HasQElem() bool {
	if !c.qSuppCalc {
		c.calcQSupp()
	}
	return c.qSuppType != QNone
}

func (c *EtmV4Config) HasQFilter() bool {
	if !c.qSuppCalc {
		c.calcQSupp()
	}
	return c.qSuppFilter
}

func (c *EtmV4Config) HasTrcExcpData() bool {
	return (c.cfg.RegIDR0 & 0x20000) == 0x20000
}

func (c *EtmV4Config) EteHasTSMarker() bool {
	return c.FullVersion() >= 0x51 && (c.cfg.RegIDR0&0x800000) == 0x800000
}

func (c *EtmV4Config) TimeStampSize() uint32 {
	tsSizeF := (c.cfg.RegIDR0 >> 24) & 0x1F
	if tsSizeF == 0x6 {
		return 48
	}
	if tsSizeF == 0x8 {
		return 64
	}
	return 0
}

func (c *EtmV4Config) CommitOpt1() bool {
	return (c.cfg.RegIDR0&0x20000000) == 0x20000000 && c.HasCycleCountI()
}

func (c *EtmV4Config) CommTransP0() bool {
	return (c.cfg.RegIDR0 & 0x40000000) == 0
}

func (c *EtmV4Config) MajVersion() uint8 {
	return c.majVer
}

func (c *EtmV4Config) MinVersion() uint8 {
	return c.minVer
}

func (c *EtmV4Config) FullVersion() uint8 {
	return (c.majVer << 4) | c.minVer
}

func (c *EtmV4Config) IASizeMax() uint32 {
	if (c.cfg.RegIDR2 & 0x1F) == 0x8 {
		return 64
	}
	return 32
}

func (c *EtmV4Config) CIDSize() uint32 {
	if ((c.cfg.RegIDR2 >> 5) & 0x1F) == 0x4 {
		return 32
	}
	return 0
}

func (c *EtmV4Config) VMIDSize() uint32 {
	if !c.vmidSzCalc {
		c.calcVMIDSize()
	}
	return c.vmidSize
}

func (c *EtmV4Config) DASize() uint32 {
	daSizeF := (c.cfg.RegIDR2 >> 15) & 0x1F
	if daSizeF == 0 {
		return 0
	}
	if daSizeF == 0x8 {
		return 64
	}
	return 32
}

func (c *EtmV4Config) DVSize() uint32 {
	dvSizeF := (c.cfg.RegIDR2 >> 20) & 0x1F
	if dvSizeF == 0 {
		return 0
	}
	if dvSizeF == 0x8 {
		return 64
	}
	return 32
}

func (c *EtmV4Config) CCSize() uint32 {
	return ((c.cfg.RegIDR2 >> 25) & 0xF) + 12
}

func (c *EtmV4Config) VMIDOpt() bool {
	return (c.cfg.RegIDR2&0x20000000) == 0x20000000 && c.MinVersion() > 0
}

func (c *EtmV4Config) WFIWFEBranch() bool {
	return (c.cfg.RegIDR2&0x80000000) != 0 && c.FullVersion() >= 0x43
}

func (c *EtmV4Config) MaxSpecDepth() uint32 {
	return c.cfg.RegIDR8
}

func (c *EtmV4Config) P0KeyMax() uint32 {
	if c.cfg.RegIDR9 == 0 {
		return 1
	}
	return c.cfg.RegIDR9
}

func (c *EtmV4Config) P1KeyMax() uint32 {
	return c.cfg.RegIDR10
}

func (c *EtmV4Config) P1SpclKeyMax() uint32 {
	return c.cfg.RegIDR11
}

func (c *EtmV4Config) CondKeyMax() uint32 {
	return c.cfg.RegIDR12
}

func (c *EtmV4Config) CondSpecKeyMax() uint32 {
	return c.cfg.RegIDR13
}

func (c *EtmV4Config) CondKeyMaxIncr() uint32 {
	return c.cfg.RegIDR12 - c.cfg.RegIDR13
}

func (c *EtmV4Config) EnabledDVTrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && (c.cfg.RegCONFIGR&(1<<17)) != 0
}

func (c *EtmV4Config) EnabledDATrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && (c.cfg.RegCONFIGR&(1<<16)) != 0
}

func (c *EtmV4Config) EnabledDataTrace() bool {
	return c.EnabledDATrace() || c.EnabledDVTrace()
}

func (c *EtmV4Config) EnabledLSP0Trace() bool {
	return (c.cfg.RegCONFIGR & 0x6) != 0
}

func (c *EtmV4Config) LSP0Type() LSP0Type {
	return LSP0Type((c.cfg.RegCONFIGR & 0x6) >> 1)
}

func (c *EtmV4Config) EnabledBrBroad() bool {
	return (c.cfg.RegCONFIGR & (1 << 3)) != 0
}

func (c *EtmV4Config) EnabledCCI() bool {
	return (c.cfg.RegCONFIGR & (1 << 4)) != 0
}

func (c *EtmV4Config) EnabledCID() bool {
	return (c.cfg.RegCONFIGR & (1 << 6)) != 0
}

func (c *EtmV4Config) EnabledVMID() bool {
	return (c.cfg.RegCONFIGR & (1 << 7)) != 0
}

func (c *EtmV4Config) EnabledVMIDOpt() bool {
	vmidOptVal := (c.cfg.RegCONFIGR & (1 << 15)) != 0
	if !c.VMIDOpt() {
		vmidOptVal = false
		if c.FullVersion() >= 0x45 {
			vmidOptVal = (c.cfg.RegIDR2 & (1 << 30)) != 0
		}
	}
	return vmidOptVal
}

func (c *EtmV4Config) EnabledCondITrace() CondITraceType {
	if !c.condTraceCalc {
		switch (c.cfg.RegCONFIGR >> 8) & 0x7 {
		default:
			c.condTrace = CondTraceDisabled
		case 1:
			c.condTrace = CondTraceLoad
		case 2:
			c.condTrace = CondTraceStore
		case 3:
			c.condTrace = CondTraceLoadStore
		case 7:
			c.condTrace = CondTraceAll
		}
		c.condTraceCalc = true
	}
	return c.condTrace
}

func (c *EtmV4Config) EnabledTS() bool {
	return (c.cfg.RegCONFIGR & (1 << 11)) != 0
}

func (c *EtmV4Config) EnabledRetStack() bool {
	return (c.cfg.RegCONFIGR & (1 << 12)) != 0
}

func (c *EtmV4Config) EnabledQE() bool {
	return (c.cfg.RegCONFIGR & (0x3 << 13)) != 0
}

func (c *EtmV4Config) privateInit() {
	c.qSuppCalc = false
	c.qSuppFilter = false
	c.qSuppType = QNone
	c.vmidSzCalc = false
	c.vmidSize = 0
	c.condTraceCalc = false
	c.condTrace = CondTraceDisabled
	c.majVer = uint8((c.cfg.RegIDR1 >> 8) & 0xF)
	c.minVer = uint8((c.cfg.RegIDR1 >> 4) & 0xF)
}

func (c *EtmV4Config) calcQSupp() {
	qtypes := []QSuppType{QNone, QICountOnly, QNoICountOnly, QFull}
	qSupp := (c.cfg.RegIDR0 >> 15) & 0x3
	c.qSuppType = qtypes[qSupp]
	c.qSuppFilter = (c.cfg.RegIDR0&0x4000) == 0x4000 && c.qSuppType != QNone
	c.qSuppCalc = true
}

func (c *EtmV4Config) calcVMIDSize() {
	vmidSzF := (c.cfg.RegIDR2 >> 10) & 0x1F
	switch vmidSzF {
	case 1:
		c.vmidSize = 8
	default:
		if c.FullVersion() > 0x40 {
			switch vmidSzF {
			case 2:
				c.vmidSize = 16
			case 4:
				c.vmidSize = 32
			}
		}
	}
	c.vmidSzCalc = true
}

// LoadConfig parses an ETMv4 device ini file into a Config.
func LoadConfig(deviceIniPath string) (Config, error) {
	data, err := os.ReadFile(deviceIniPath)
	if err != nil {
		return Config{}, fmt.Errorf("read device ini: %w", err)
	}

	cfg := Config{ArchVer: ArchV7, CoreProf: ProfileCortexA}
	section := ""
	foundIDR0 := false
	foundIDR1 := false
	foundIDR2 := false
	foundCONFIGR := false
	foundTRACEIDR := false

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		if section != "regs" {
			continue
		}

		key, value, ok := splitIniKV(line)
		if !ok {
			continue
		}
		regName := normalizeRegName(key)
		parsed, parseErr := parseHexUint32(value)
		if parseErr != nil {
			continue
		}

		switch regName {
		case "TRCIDR0":
			cfg.RegIDR0 = parsed
			foundIDR0 = true
		case "TRCIDR1":
			cfg.RegIDR1 = parsed
			foundIDR1 = true
		case "TRCIDR2":
			cfg.RegIDR2 = parsed
			foundIDR2 = true
		case "TRCIDR8":
			cfg.RegIDR8 = parsed
		case "TRCIDR9":
			cfg.RegIDR9 = parsed
		case "TRCIDR10":
			cfg.RegIDR10 = parsed
		case "TRCIDR11":
			cfg.RegIDR11 = parsed
		case "TRCIDR12":
			cfg.RegIDR12 = parsed
		case "TRCIDR13":
			cfg.RegIDR13 = parsed
		case "TRCCONFIGR":
			cfg.RegCONFIGR = parsed
			foundCONFIGR = true
		case "TRCTRACEIDR":
			cfg.RegTRACEIDR = parsed
			foundTRACEIDR = true
		case "TRCAUTHSTATUS":
			cfg.RegAUTHSTAT = parsed
		}
	}

	if !foundIDR0 || !foundIDR1 || !foundIDR2 || !foundCONFIGR || !foundTRACEIDR {
		return Config{}, fmt.Errorf("missing required ETMv4 registers in %s", deviceIniPath)
	}
	return cfg, nil
}

// FindDeviceIniByTraceID scans snapshot.ini and ETMv4 device ini files for a matching trace ID.
func FindDeviceIniByTraceID(snapshotDir string, traceID uint8) (string, Config, error) {
	deviceList, err := common.ParseSnapshotIni(snapshotDir)
	if err != nil {
		return "", Config{}, err
	}
	for _, deviceIni := range deviceList.DeviceList {
		path := filepath.Join(snapshotDir, deviceIni)
		cfg, err := LoadConfig(path)
		if err != nil {
			continue
		}
		if uint8(cfg.RegTRACEIDR&0x7F) == traceID {
			return path, cfg, nil
		}
	}
	return "", Config{}, fmt.Errorf("no ETMv4 device ini found for trace ID 0x%02X in %s", traceID, snapshotDir)
}

func splitIniKV(line string) (string, string, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func normalizeRegName(key string) string {
	if idx := strings.Index(key, "("); idx >= 0 {
		key = key[:idx]
	}
	return strings.TrimSpace(key)
}

func parseHexUint32(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return 0, fmt.Errorf("empty value")
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}
