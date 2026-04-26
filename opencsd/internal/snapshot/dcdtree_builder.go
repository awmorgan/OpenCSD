package snapshot

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/ete"
	"opencsd/internal/etmv3"
	"opencsd/internal/etmv4"
	"opencsd/internal/idec"
	"opencsd/internal/itm"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/ptm"
	"opencsd/internal/stm"
	"os"
	"path/filepath"
	"strings"
)

// archProfileMap is a package-level cache of the core architecture map (shared, read-only after init).
var archProfileMap = common.NewCoreArchProfileMap()

var newDecodeTree = dcdtree.NewDecodeTree

type mapperAdapter struct {
	mapper memacc.Mapper
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *mapperAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

var dumpSpaceMap = map[string]ocsd.MemSpaceAcc{
	"":           ocsd.MemSpaceAny,
	"ANY":        ocsd.MemSpaceAny,
	"MEMORY":     ocsd.MemSpaceAny,
	"N":          ocsd.MemSpaceN,
	"NS":         ocsd.MemSpaceN,
	"NONSECURE":  ocsd.MemSpaceN,
	"NON-SECURE": ocsd.MemSpaceN,
	"S":          ocsd.MemSpaceS,
	"SECURE":     ocsd.MemSpaceS,
	"R":          ocsd.MemSpaceR,
	"REALM":      ocsd.MemSpaceR,
	"ROOT":       ocsd.MemSpaceRoot,
	"EL1S":       ocsd.MemSpaceEL1S,
	"EL1N":       ocsd.MemSpaceEL1N,
	"EL2":        ocsd.MemSpaceEL2,
	"EL2N":       ocsd.MemSpaceEL2, // alias: non-secure EL2
	"EL3":        ocsd.MemSpaceEL3,
	"EL2S":       ocsd.MemSpaceEL2S,
	"EL1R":       ocsd.MemSpaceEL1R,
	"EL2R":       ocsd.MemSpaceEL2R,
	// Legacy aliases matching the C++ space_map
	"H":  ocsd.MemSpaceEL2,  // hypervisor – EL2 NS
	"P":  ocsd.MemSpaceEL1N, // privileged – EL1 NS
	"NP": ocsd.MemSpaceEL1N, // non-secure privileged – EL1 NS
	"SP": ocsd.MemSpaceEL1S, // secure privileged – EL1 S
}

func mapDumpMemSpace(space string) ocsd.MemSpaceAcc {
	key := strings.ToUpper(strings.TrimSpace(space))
	if memSpace, ok := dumpSpaceMap[key]; ok {
		return memSpace
	}
	return ocsd.MemSpaceAny
}

// DecodeTreeBuilder builds a decode tree from snapshot metadata.
type DecodeTreeBuilder struct {
	reader         *Reader
	tree           *dcdtree.DecodeTree
	packetProcOnly bool
	bufferFileName string
	mapper         *memacc.GlobalMapper
	memIf          common.TargetMemAccess
	instrDecode    common.InstrDecode
}

// NewDecodeTreeBuilder creates a new builder for DecodeTree from a snapshot.
func NewDecodeTreeBuilder(r *Reader) *DecodeTreeBuilder {
	return &DecodeTreeBuilder{
		reader: r,
	}
}

// DecodeTree returns the built decode tree.
func (b *DecodeTreeBuilder) DecodeTree() *dcdtree.DecodeTree {
	return b.tree
}

// BufferFileName returns the full path of the trace binary buffer file to load.
func (b *DecodeTreeBuilder) BufferFileName() string {
	return b.bufferFileName
}

// MemoryMapper returns the builder-managed memory mapper used in full decode mode.
// It returns nil when packet-only mode is selected.
func (b *DecodeTreeBuilder) MemoryMapper() *memacc.GlobalMapper {
	return b.mapper
}

// Build builds the tree for a specific named source buffer (e.g., "ETB_0").
func (b *DecodeTreeBuilder) Build(sourceName string, packetProcOnly bool) (*dcdtree.DecodeTree, error) {
	if !b.reader.ReadOK {
		return nil, fmt.Errorf("supplied snapshot reader has not correctly read the snapshot")
	}

	if b.reader.Trace == nil {
		return nil, fmt.Errorf("trace metadata not loaded")
	}

	b.packetProcOnly = packetProcOnly
	tree, ok := SourceTree(sourceName, b.reader.Trace)
	if !ok {
		return nil, fmt.Errorf("source tree for buffer %q not found", sourceName)
	}

	formatterFlags := uint32(ocsd.DfrmtrFrameMemAlign)
	b.bufferFileName = filepath.Join(b.reader.SnapshotPath, tree.BufferInfo.DataFileName)

	dataFormat := strings.ToLower(tree.BufferInfo.DataFormat)
	srcFormat := ocsd.TrcSrcFrameFormatted
	if dataFormat == "source_data" {
		srcFormat = ocsd.TrcSrcSingle
	}
	if dataFormat == "dstream_coresight" {
		formatterFlags = ocsd.DfrmtrHasFsyncs
	}

	newTree, err := newDecodeTree(srcFormat, formatterFlags)
	if err != nil {
		return nil, fmt.Errorf("failed to create decode tree object: %w", err)
	}
	b.tree = newTree

	// Create a memory accessor mapper in full-decoder mode only.
	b.mapper = nil
	b.memIf = nil
	b.instrDecode = nil
	if !packetProcOnly {
		b.mapper = memacc.NewGlobalMapper()
		b.memIf = &mapperAdapter{mapper: b.mapper}
		b.instrDecode = idec.NewDecoder()
	}

	numDecodersCreated := 0
	for srcName, coreName := range tree.SourceCoreAssoc {
		devSrc, ok := b.reader.ParsedDeviceList[srcName]
		if !ok || devSrc == nil {
			continue
		}

		if coreName != "<none>" && coreName != "" {
			coreDev, ok := b.reader.ParsedDeviceList[coreName]
			if !ok || coreDev == nil {
				continue
			}

			err := b.createPEDecoder(devSrc.Type, devSrc, coreName)
			if err != nil {
				continue
			}

			numDecodersCreated++
			if !packetProcOnly && len(coreDev.Memory) > 0 {
				b.addCoreDumpMemory(b.mapper, coreDev)
			}
			continue
		}

		err := b.createSTDecoder(devSrc)
		if err != nil {
			continue
		}
		numDecodersCreated++
	}

	if numDecodersCreated == 0 {
		b.tree = nil
		return nil, fmt.Errorf("no supported protocols found")
	}

	return b.tree, nil
}

func setReg32(dev *Device, name string, dst *uint32) {
	if val, ok := dev.RegValue(name); ok {
		parsed, _ := parseUint(val)
		*dst = uint32(parsed)
	}
}

func protocolBase(name string) string {
	base, _, _ := strings.Cut(name, ".")
	return base
}

// getCoreProfile maps a core device type name (e.g. "Cortex-A57") to its architecture version
// and core profile, matching the C++ CoreArchProfileMap / getCoreProfile behaviour.
func getCoreProfile(coreName string) (ocsd.ArchVersion, ocsd.CoreProfile) {
	if ap, ok := archProfileMap.ArchProfile(coreName); ok {
		return ap.Arch, ap.Profile
	}
	return ocsd.ArchUnknown, ocsd.ProfileUnknown
}

func (b *DecodeTreeBuilder) createPEDecoder(devTypeName string, devSrc *Device, coreName string) error {
	switch devTypeName = protocolBase(devTypeName); {
	case devTypeName == ETMv3Protocol || strings.HasPrefix(devTypeName, "ETMv3"):
		return b.createETMv3Decoder(coreName, devSrc)
	case devTypeName == ETMv4Protocol || strings.HasPrefix(devTypeName, "ETMv4"):
		return b.createETMv4Decoder(coreName, devSrc)
	case devTypeName == ETEProtocol:
		return b.createETEDecoder(coreName, devSrc)
	case devTypeName == PTMProtocol || devTypeName == PFTProtocol:
		return b.createPTMDecoder(coreName, devSrc)
	default:
		return fmt.Errorf("unknown PE device type %q", devTypeName)
	}
}

func (b *DecodeTreeBuilder) createSTDecoder(devSrc *Device) error {
	devTypeName := protocolBase(devSrc.Type)
	switch devTypeName {
	case STMProtocol:
		return b.createSTMDecoder(devSrc)
	case ITMProtocol:
		return b.createITMDecoder(devSrc)
	default:
		return fmt.Errorf("unknown ST device type %q", devTypeName)
	}
}

func (b *DecodeTreeBuilder) createETMv3Decoder(coreName string, devSrc *Device) error {
	cfg := &etmv3.Config{}

	setReg32(devSrc, "etmcr", &cfg.RegCtrl)
	setReg32(devSrc, "etmtraceidr", &cfg.RegTrcID)
	setReg32(devSrc, "etmidr", &cfg.RegIDR)
	setReg32(devSrc, "etmccer", &cfg.RegCCER)

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc, err := etmv3.NewConfiguredPktProc(int(cfg.TraceID()), cfg)
		if err != nil {
			return fmt.Errorf("ETMv3 NewConfiguredPktProc failed: %w", err)
		}
		return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV3, ocsd.ProtocolETMV3, proc, nil, proc)
	}

	proc, dec, err := etmv3.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ETMv3 NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV3, ocsd.ProtocolETMV3, proc, dec, dec)
}

func (b *DecodeTreeBuilder) createPTMDecoder(coreName string, devSrc *Device) error {
	cfg := ptm.NewConfig()

	setReg32(devSrc, "etmcr", &cfg.RegCtrl)
	setReg32(devSrc, "etmtraceidr", &cfg.RegTrcID)
	setReg32(devSrc, "etmidr", &cfg.RegIDR)
	setReg32(devSrc, "etmccer", &cfg.RegCCER)

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc, err := ptm.NewConfiguredPktProc(int(cfg.TraceID()), cfg)
		if err != nil {
			return fmt.Errorf("PTM NewConfiguredPktProc failed: %w", err)
		}
		return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdPTM, ocsd.ProtocolPTM, proc, nil, proc)
	}

	proc, dec, err := ptm.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("PTM NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdPTM, ocsd.ProtocolPTM, proc, dec, dec)
}

func (b *DecodeTreeBuilder) createETEDecoder(coreName string, devSrc *Device) error {
	cfg := ete.NewConfig()

	setReg32(devSrc, "trcidr0", &cfg.RegIdr0)
	setReg32(devSrc, "trcidr1", &cfg.RegIdr1)
	setReg32(devSrc, "trcidr2", &cfg.RegIdr2)
	setReg32(devSrc, "trcidr8", &cfg.RegIdr8)
	setReg32(devSrc, "trcdevarch", &cfg.RegDevArch)
	setReg32(devSrc, "trcconfigr", &cfg.RegConfigr)
	setReg32(devSrc, "trctraceidr", &cfg.RegTraceidr)

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc := ete.NewProcessor(cfg)
		return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETE, ocsd.ProtocolETE, proc, nil, proc)
	}

	proc, dec, err := ete.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ETE NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETE, ocsd.ProtocolETE, proc, dec, dec)
}

func (b *DecodeTreeBuilder) createETMv4Decoder(coreName string, devSrc *Device) error {
	cfg := &etmv4.Config{
		RegIdr1: 0x4100F403,
	}

	setReg32(devSrc, "trcidr0", &cfg.RegIdr0)
	setReg32(devSrc, "trcidr1", &cfg.RegIdr1)
	setReg32(devSrc, "trcidr2", &cfg.RegIdr2)
	setReg32(devSrc, "trcidr8", &cfg.RegIdr8)
	setReg32(devSrc, "trcidr9", &cfg.RegIdr9)
	setReg32(devSrc, "trcidr10", &cfg.RegIdr10)
	setReg32(devSrc, "trcidr11", &cfg.RegIdr11)
	setReg32(devSrc, "trcidr12", &cfg.RegIdr12)
	setReg32(devSrc, "trcidr13", &cfg.RegIdr13)
	setReg32(devSrc, "trcconfigr", &cfg.RegConfigr)
	setReg32(devSrc, "trctraceidr", &cfg.RegTraceidr)

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc, err := etmv4.NewConfiguredProcessor(cfg)
		if err != nil {
			return fmt.Errorf("ETMv4 NewConfiguredProcessor failed: %w", err)
		}
		return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV4I, ocsd.ProtocolETMV4I, proc, nil, proc)
	}

	proc, dec, err := etmv4.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ETMv4 NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV4I, ocsd.ProtocolETMV4I, proc, dec, dec)
}

func (b *DecodeTreeBuilder) createSTMDecoder(devSrc *Device) error {
	cfg := stm.NewConfig()
	setReg32(devSrc, "stmtcsr", &cfg.RegTCSR)
	if b.packetProcOnly {
		proc, err := stm.NewConfiguredPktProc(int(cfg.TraceID()), cfg)
		if err != nil {
			return fmt.Errorf("STM NewConfiguredPktProc failed: %w", err)
		}
		return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdSTM, ocsd.ProtocolSTM, proc, nil, proc)
	}

	proc, dec, err := stm.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("STM NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdSTM, ocsd.ProtocolSTM, proc, dec, dec)
}

func (b *DecodeTreeBuilder) createITMDecoder(devSrc *Device) error {
	cfg := &itm.Config{}
	setReg32(devSrc, "itmtcr", &cfg.RegTCR)
	if b.packetProcOnly {
		proc, _, err := itm.NewPipeline(int(cfg.TraceID()), cfg, nil, nil)
		if err != nil {
			return fmt.Errorf("ITM NewPipeline failed: %w", err)
		}
		return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdITM, ocsd.ProtocolITM, proc, nil, proc)
	}

	proc, dec, err := itm.NewPipeline(int(cfg.TraceID()), cfg, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ITM NewPipeline failed: %w", err)
	}
	return b.tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdITM, ocsd.ProtocolITM, proc, dec, dec)
}

// addCoreDumpMemory adds memory region accessors from a core device's dump definitions.
// It is called once per PE decoder that is successfully created, only in full-decoder mode.
func (b *DecodeTreeBuilder) addCoreDumpMemory(mapper memacc.Mapper, dev *Device) {
	for _, dump := range dev.Memory {
		if strings.TrimSpace(dump.Path) == "" {
			continue
		}

		path := filepath.Join(b.reader.SnapshotPath, dump.Path)
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		if dump.Offset > 0 {
			if dump.Offset >= uint64(len(fileBytes)) {
				continue
			}
			fileBytes = fileBytes[dump.Offset:]
		}

		if dump.Length > 0 && dump.Length < uint64(len(fileBytes)) {
			fileBytes = fileBytes[:dump.Length]
		}

		if len(fileBytes) == 0 {
			continue
		}

		acc := memacc.NewBufferAccessor(ocsd.VAddr(dump.Address), fileBytes)
		acc.SetMemSpace(mapDumpMemSpace(dump.Space))
		if err := mapper.AddAccessor(acc, ocsd.BadCSSrcID); err != nil {
		}
	}
}
