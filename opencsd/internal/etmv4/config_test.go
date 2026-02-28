package etmv4

import (
	"testing"
)

func TestConfigDefaultValues(t *testing.T) {
	// These values mirror the default constructor in trc_cmp_cfg_etmv4.cpp
	cfg := Config{
		RegIdr0:     0x28000EA1,
		RegIdr1:     0x4100F403,
		RegIdr2:     0x00000488,
		RegIdr8:     0,
		RegIdr9:     0,
		RegIdr10:    0,
		RegIdr11:    0,
		RegIdr12:    0,
		RegIdr13:    0,
		RegConfigr:  0xC1,
		RegTraceidr: 0,
		ArchVer:     0, // Placeholder, assuming 0 maps to ARCH_V7
		CoreProf:    0, // Placeholder
	}

	// IDR0 tests
	if cfg.LSasInstP0() {
		t.Errorf("expected LSasInstP0 to be false")
	}
	if cfg.HasDataTrace() {
		t.Errorf("expected HasDataTrace to be false")
	}
	if !cfg.HasBranchBroadcast() {
		t.Errorf("expected HasBranchBroadcast to be true")
	}
	if cfg.HasCondTrace() {
		t.Errorf("expected HasCondTrace to be false")
	}
	if !cfg.HasCycleCountI() {
		t.Errorf("expected HasCycleCountI to be true")
	}
	if !cfg.HasRetStack() {
		t.Errorf("expected HasRetStack to be true")
	}
	if cols := cfg.NumEvents(); cols != 4 {
		t.Errorf("expected NumEvents to be 4, got %d", cols)
	}
	if typ := cfg.HasCondType(); typ != CondPassFail {
		t.Errorf("expected HasCondType to be CondPassFail, got %d", typ)
	}
	if typ := cfg.QSuppType(); typ != QNone {
		t.Errorf("expected QSuppType to be QNone, got %d", typ)
	}
	if cfg.HasQElem() {
		t.Errorf("expected HasQElem to be false")
	}
	if cfg.HasQFilter() {
		t.Errorf("expected HasQFilter to be false")
	}
	if cfg.HasTrcExcpData() {
		t.Errorf("expected HasTrcExcpData to be false")
	}
	if cfg.EteHasTSMarker() {
		t.Errorf("expected EteHasTSMarker to be false")
	}
	if size := cfg.TimeStampSize(); size != 64 {
		t.Errorf("expected TimeStampSize to be 64, got %d", size)
	}
	if !cfg.CommitOpt1() {
		t.Errorf("expected CommitOpt1 to be true")
	}
	if !cfg.CommTransP0() {
		t.Errorf("expected CommTransP0 to be true")
	}

	// IDR1 tests
	if cfg.MajVersion() != 4 {
		t.Errorf("expected MajVersion to be 4")
	}
	if cfg.MinVersion() != 0 {
		t.Errorf("expected MinVersion to be 0")
	}
	if cfg.FullVersion() != 0x40 {
		t.Errorf("expected FullVersion to be 0x40")
	}

	// IDR2 tests
	if size := cfg.IaSizeMax(); size != 64 {
		t.Errorf("expected IaSizeMax to be 64, got %d", size)
	}
	if size := cfg.CidSize(); size != 32 {
		t.Errorf("expected CidSize to be 32, got %d", size)
	}
	if size := cfg.VmidSize(); size != 8 {
		t.Errorf("expected VmidSize to be 8, got %d", size)
	}
	if size := cfg.DaSize(); size != 0 {
		t.Errorf("expected DaSize to be 0, got %d", size)
	}
	if size := cfg.DvSize(); size != 0 {
		t.Errorf("expected DvSize to be 0, got %d", size)
	}
	if size := cfg.CcSize(); size != 12 {
		t.Errorf("expected CcSize to be 12, got %d", size)
	}
	if cfg.VmidOpt() {
		t.Errorf("expected VmidOpt to be false")
	}
	if cfg.WfiwfeBranch() {
		t.Errorf("expected WfiwfeBranch to be false")
	}

	// ID regs 8-13
	if cfg.MaxSpecDepth() != 0 {
		t.Errorf("expected MaxSpecDepth to be 0")
	}
	if cfg.P0_Key_Max() != 1 {
		t.Errorf("expected P0_Key_Max to be 1")
	}
	if cfg.P1_Key_Max() != 0 {
		t.Errorf("expected P1_Key_Max to be 0")
	}
	if cfg.P1_Spcl_Key_Max() != 0 {
		t.Errorf("expected P1_Spcl_Key_Max to be 0")
	}
	if cfg.CondKeyMax() != 0 {
		t.Errorf("expected CondKeyMax to be 0")
	}
	if cfg.CondSpecKeyMax() != 0 {
		t.Errorf("expected CondSpecKeyMax to be 0")
	}
	if cfg.CondKeyMaxIncr() != 0 {
		t.Errorf("expected CondKeyMaxIncr to be 0")
	}

	// Config tests
	if cfg.EnabledDVTrace() {
		t.Errorf("expected EnabledDVTrace to be false")
	}
	if cfg.EnabledDATrace() {
		t.Errorf("expected EnabledDATrace to be false")
	}
	if cfg.EnabledDataTrace() {
		t.Errorf("expected EnabledDataTrace to be false")
	}
	if cfg.EnabledLSP0Trace() {
		t.Errorf("expected EnabledLSP0Trace to be false") // 0xC1 & 0x6 == 0
	}
	if typ := cfg.LSP0Type(); typ != LSP0None {
		t.Errorf("expected LSP0Type to be LSP0None")
	}
	if cfg.EnabledBrBroad() {
		t.Errorf("expected EnabledBrBroad to be false")
	}
	if cfg.EnabledCCI() {
		t.Errorf("expected EnabledCCI to be false")
	}
	if !cfg.EnabledCID() {
		t.Errorf("expected EnabledCID to be true")
	}
	if !cfg.EnabledVMID() {
		t.Errorf("expected EnabledVMID to be true")
	}
	if cfg.EnabledVMIDOpt() {
		t.Errorf("expected EnabledVMIDOpt to be false")
	}
	if typ := cfg.EnabledCondITrace(); typ != CondTrDis {
		t.Errorf("expected EnabledCondITrace to be CondTrDis")
	}
	if cfg.EnabledTS() {
		t.Errorf("expected EnabledTS to be false")
	}
	if cfg.EnabledRetStack() {
		t.Errorf("expected EnabledRetStack to be false")
	}
	if cfg.EnabledQE() {
		t.Errorf("expected EnabledQE to be false")
	}
}

func TestConfigSpecificValues(t *testing.T) {
	// Let's test a Config that activates the other branches and logic
	cfg := Config{
		// 0x6 = LSasInstP0
		// 0x18 = HasDataTrace
		// 0x40 = HasCondTrace
		// 0x3000 -> 0x1000 = HasCondType (CondHasAspr)
		// 0x18000 (0x3 << 15) -> QFull
		// 0x4000 = HasQFilter
		// 0x20000 = HasTrcExcpData
		// 0x800000 = EteHasTSMarker
		// 0x6000000 (0x6 << 24) -> TimeStampSize = 48
		RegIdr0: 0x6000000 | 0x800000 | 0x20000 | 0x4000 | 0x18000 | 0x1000 | 0x40 | 0x18 | 0x6,
		// FullVersion >= 0x51
		RegIdr1: 0x510, // MajVer=5 (0x5<<8), MinVer=1 (0x1<<4)
		// CidSize = 0x4 << 5
		// VmidSize = 0x2 << 10 (16)
		// DaSize = 0x8 << 15 (64)
		// DvSize = 0x8 << 20 (64)
		// CcSize = 0x2 << 25 (14)
		// 0x20000000 VmidOpt
		// 0x80000000 WfiwfeBranch
		RegIdr2: 0x80000000 | 0x20000000 | (0x2 << 25) | (0x8 << 20) | (0x8 << 15) | (0x2 << 10) | (0x4 << 5) | 0x1F, // 0x1F -> 64 iaSizeMax wait 0x1F isn't 8. let's put 0x8
		RegIdr9: 42,
		// Configr: 0x6 -> LSP0LS
		// EnabledDVTrace=0x1<<17
		// EnabledDATrace=0x1<<16
		// EnabledBrBroad=0x1<<3
		// EnabledCCI=0x1<<4
		// EnabledVMIDOpt=0x1<<15
		// EnabledCondITrace=0x7<<8 (CondTrAll)
		// EnabledTS=0x1<<11
		// EnabledRetStack=0x1<<12
		// EnabledQE=0x3<<13
		RegConfigr:  (0x3 << 13) | (1 << 12) | (1 << 11) | (0x7 << 8) | (1 << 15) | (1 << 4) | (1 << 3) | (1 << 16) | (1 << 17) | 0x6,
		RegTraceidr: 0x7F | 0x80, // TraceID is only lowest 7 bits, so 0x7F
	}
	cfg.RegIdr2 = (cfg.RegIdr2 &^ 0x1F) | 0x8 // Fix IaSizeMax

	if !cfg.LSasInstP0() {
		t.Errorf("expected LSasInstP0 true")
	}
	if !cfg.HasDataTrace() {
		t.Errorf("expected HasDataTrace true")
	}
	if !cfg.HasCondTrace() {
		t.Errorf("expected HasCondTrace true")
	}
	if typ := cfg.HasCondType(); typ != CondHasAspr {
		t.Errorf("expected HasCondType CondHasAspr, got %v", typ)
	}
	if typ := cfg.QSuppType(); typ != QFull {
		t.Errorf("expected QSuppType QFull, got %v", typ)
	}
	if !cfg.HasQFilter() {
		t.Errorf("expected HasQFilter true")
	}
	if !cfg.HasTrcExcpData() {
		t.Errorf("expected HasTrcExcpData true")
	}
	if !cfg.EteHasTSMarker() {
		t.Errorf("expected EteHasTSMarker true")
	}
	if size := cfg.TimeStampSize(); size != 48 {
		t.Errorf("expected TimeStampSize 48, got %v", size)
	}

	if ver := cfg.MajVersion(); ver != 5 {
		t.Errorf("expected MajVersion 5, got %v", ver)
	}
	if ver := cfg.MinVersion(); ver != 1 {
		t.Errorf("expected MinVersion 1, got %v", ver)
	}
	if ver := cfg.FullVersion(); ver != 0x51 {
		t.Errorf("expected FullVersion 0x51, got %v", ver)
	}

	if size := cfg.IaSizeMax(); size != 64 {
		t.Errorf("expected IaSizeMax 64, got %v", size)
	}
	if size := cfg.CidSize(); size != 32 {
		t.Errorf("expected CidSize 32, got %v", size)
	}
	if size := cfg.VmidSize(); size != 16 {
		t.Errorf("expected VmidSize 16, got %v", size)
	}
	if size := cfg.DaSize(); size != 64 {
		t.Errorf("expected DaSize 64, got %v", size)
	}
	if size := cfg.DvSize(); size != 64 {
		t.Errorf("expected DvSize 64, got %v", size)
	}
	if size := cfg.CcSize(); size != 14 {
		t.Errorf("expected CcSize 14, got %v", size)
	}
	if !cfg.VmidOpt() {
		t.Errorf("expected VmidOpt true")
	}
	if !cfg.WfiwfeBranch() {
		t.Errorf("expected WfiwfeBranch true")
	}
	if cfg.P0_Key_Max() != 42 {
		t.Errorf("expected P0_Key_Max 42")
	}
	if cfg.TraceID() != 0x7F {
		t.Errorf("expected TraceID 0x7F")
	}

	if !cfg.EnabledLSP0Trace() {
		t.Errorf("expected EnabledLSP0Trace true")
	}
	if typ := cfg.LSP0Type(); typ != LSP0LS {
		t.Errorf("expected LSP0Type LSP0LS, got %v", typ)
	}
	if !cfg.EnabledDVTrace() {
		t.Errorf("expected EnabledDVTrace true")
	}
	if !cfg.EnabledDATrace() {
		t.Errorf("expected EnabledDATrace true")
	}
	if !cfg.EnabledDataTrace() {
		t.Errorf("expected EnabledDataTrace true")
	}
	if !cfg.EnabledBrBroad() {
		t.Errorf("expected EnabledBrBroad true")
	}
	if !cfg.EnabledCCI() {
		t.Errorf("expected EnabledCCI true")
	}
	if !cfg.EnabledVMIDOpt() {
		t.Errorf("expected EnabledVMIDOpt true")
	}

	if typ := cfg.EnabledCondITrace(); typ != CondTrAll {
		t.Errorf("expected EnabledCondITrace CondTrAll, got %v", typ)
	}
	if !cfg.EnabledTS() {
		t.Errorf("expected EnabledTS true")
	}
	if !cfg.EnabledRetStack() {
		t.Errorf("expected EnabledRetStack true")
	}
	if !cfg.EnabledQE() {
		t.Errorf("expected EnabledQE true")
	}
}

func TestVmidSizeLogic(t *testing.T) {
	// Tests VMIDSize logic since it has a specific branching
	c := Config{}
	c.RegIdr2 = (0x1 << 10)
	if size := c.VmidSize(); size != 8 {
		t.Errorf("expected VmidSize 8, got %d", size)
	}

	c.RegIdr2 = (0x2 << 10)
	c.RegIdr1 = 0x410 // Maj=4, Min=1 -> 0x41
	if size := c.VmidSize(); size != 16 {
		t.Errorf("expected VmidSize 16, got %d", size)
	}

	c.RegIdr2 = (0x4 << 10)
	if size := c.VmidSize(); size != 32 {
		t.Errorf("expected VmidSize 32, got %d", size)
	}

	c.RegIdr1 = 0x400 // 0x40, shouldn't evaluate > 0x40
	if size := c.VmidSize(); size != 0 {
		t.Errorf("expected VmidSize 0, got %d", size)
	}
}

func TestEnabledVMIDOptLogic(t *testing.T) {
	c := Config{}

	// Base case where it uses RegConfigr[15] due to VmidOpt() being true
	c.RegIdr1 = 0x410      // MinVer > 0 -> 0x41
	c.RegIdr2 = 0x20000000 // VmidOpt() is true
	c.RegConfigr = 0x8000  // bit 15
	if !c.EnabledVMIDOpt() {
		t.Errorf("expected true")
	}

	// Case where VmidOpt() is false and FullVersion >= 0x45
	c.RegIdr1 = 0x450      // MinVer=5 -> 0x45
	c.RegIdr2 = 0x40000000 // Bit 30 set, Bit 29 clear
	c.RegConfigr = 0       // Does not rely on configr
	if !c.EnabledVMIDOpt() {
		t.Errorf("expected true")
	}

	// Case where FullVersion < 0x45 and VmidOpt() false
	c.RegIdr1 = 0x440
	c.RegIdr2 = 0x40000000
	if c.EnabledVMIDOpt() {
		t.Errorf("expected false")
	}
}
