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
	if !b.reader.ReadOK() {
		err := fmt.Errorf("supplied snapshot reader has not correctly read the snapshot")
		b.reader.logError(err.Error())
		return nil, err
	}

	b.packetProcOnly = packetProcOnly
	tree := NewTraceBufferSourceTree()
	if !ExtractSourceTree(sourceName, b.reader.Trace(), tree) {
		err := fmt.Errorf("failed to get parsed source tree for buffer %s", sourceName)
		b.reader.logError(err.Error())
		return nil, err
	}

	formatterFlags := uint32(ocsd.DfrmtrFrameMemAlign)
	b.bufferFileName = filepath.Join(b.reader.Dir(), tree.BufferInfo.DataFileName)

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
		err = fmt.Errorf("failed to create decode tree object: %w", err)
		b.reader.logError(err.Error())
		return nil, err
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
		devSrc, ok := b.reader.Device(srcName)
		if !ok || devSrc == nil {
			b.reader.logError(fmt.Sprintf("Failed to find device data for source %s.", srcName))
			continue
		}

		if coreName != "<none>" && coreName != "" {
			coreDev, ok := b.reader.Device(coreName)
			if !ok || coreDev == nil {
				b.reader.logError(fmt.Sprintf("Failed to get device data for core %s.", coreName))
				continue
			}

			err := b.createPEDecoder(devSrc.DeviceTypeName, devSrc, coreName)
			if err != nil {
				b.reader.logError(fmt.Sprintf("Failed to create PEDecoder for source %s: %v", srcName, err))
				continue
			}

			numDecodersCreated++
			if !packetProcOnly && len(coreDev.DumpDefs) > 0 {
				b.addCoreDumpMemory(b.mapper, coreDev)
			}
			continue
		}

		err := b.createSTDecoder(devSrc)
		if err != nil {
			b.reader.logError(fmt.Sprintf("Failed to create STDecoder for none core source %s: %v", srcName, err))
			continue
		}
		numDecodersCreated++
	}

	if numDecodersCreated == 0 {
		b.tree = nil
		err := fmt.Errorf("no supported protocols found")
		b.reader.logError(err.Error())
		return nil, err
	}

	return b.tree, nil
}

// CreateDecodeTree builds the tree for a specific named source buffer (e.g., "ETB_0").
// Deprecated: prefer Build, which returns an error.
func (b *DecodeTreeBuilder) CreateDecodeTree(sourceName string, packetProcOnly bool) bool {
	_, err := b.Build(sourceName, packetProcOnly)
	return err == nil
}

// getCoreProfile maps a core device type name (e.g. "Cortex-A57") to its architecture version
// and core profile, matching the C++ CoreArchProfileMap / getCoreProfile behaviour.
func getCoreProfile(coreName string) (ocsd.ArchVersion, ocsd.CoreProfile) {
	if ap, ok := archProfileMap.ArchProfile(coreName); ok {
		return ap.Arch, ap.Profile
	}
	return ocsd.ArchUnknown, ocsd.ProfileUnknown
}

func (b *DecodeTreeBuilder) createPEDecoder(devTypeName string, devSrc *ParsedDevice, coreName string) error {
	// Strip any trailing ".x" version suffix from the device type name (e.g. "ETM4.1" → "ETM4").
	if pos := strings.IndexByte(devTypeName, '.'); pos >= 0 {
		devTypeName = devTypeName[:pos]
	}

	if devTypeName == ETMv3Protocol || strings.HasPrefix(devTypeName, "ETMv3") {
		return b.createETMv3Decoder(coreName, devSrc)
	} else if devTypeName == ETMv4Protocol || strings.HasPrefix(devTypeName, "ETMv4") {
		return b.createETMv4Decoder(coreName, devSrc)
	} else if devTypeName == ETEProtocol {
		return b.createETEDecoder(coreName, devSrc)
	} else if devTypeName == PTMProtocol || devTypeName == PFTProtocol {
		return b.createPTMDecoder(coreName, devSrc)
	}
	return fmt.Errorf("unknown PE devType: %s", devTypeName)
}

func (b *DecodeTreeBuilder) createSTDecoder(devSrc *ParsedDevice) error {
	devTypeName := devSrc.DeviceTypeName
	// Strip any trailing ".x" version suffix (e.g. "STM.1" → "STM").
	if pos := strings.IndexByte(devTypeName, '.'); pos >= 0 {
		devTypeName = devTypeName[:pos]
	}

	switch devTypeName {
	case STMProtocol:
		return b.createSTMDecoder(devSrc)
	case ITMProtocol:
		return b.createITMDecoder(devSrc)
	}
	return fmt.Errorf("unknown ST devType: %s", devTypeName)
}

func (b *DecodeTreeBuilder) createETMv3Decoder(coreName string, devSrc *ParsedDevice) error {
	cfg := &etmv3.Config{}

	if val, ok := devSrc.RegValue("etmcr"); ok {
		cfg.RegCtrl = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("etmtraceidr"); ok {
		cfg.RegTrcID = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("etmidr"); ok {
		cfg.RegIDR = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("etmccer"); ok {
		cfg.RegCCER = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc, err := etmv3.NewConfiguredPktProc(int(cfg.TraceID()), cfg)
		if err != nil {
			return fmt.Errorf("ETMv3 NewConfiguredPktProc failed: %w", err)
		}
		return b.tree.AddDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV3, ocsd.ProtocolETMV3, proc, proc)
	}

	proc, dec, err := etmv3.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, nil, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ETMv3 NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddWiredDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV3, ocsd.ProtocolETMV3, proc, dec, dec.SetTraceElemOut)
}

func (b *DecodeTreeBuilder) createPTMDecoder(coreName string, devSrc *ParsedDevice) error {
	cfg := ptm.NewConfig()

	if val, ok := devSrc.RegValue("etmcr"); ok {
		cfg.RegCtrl = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("etmtraceidr"); ok {
		cfg.RegTrcID = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("etmidr"); ok {
		cfg.RegIDR = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("etmccer"); ok {
		cfg.RegCCER = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc, err := ptm.NewConfiguredPktProc(int(cfg.TraceID()), cfg)
		if err != nil {
			return fmt.Errorf("PTM NewConfiguredPktProc failed: %w", err)
		}
		return b.tree.AddDecoder(cfg.TraceID(), ocsd.BuiltinDcdPTM, ocsd.ProtocolPTM, proc, proc)
	}

	proc, dec, err := ptm.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, nil, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("PTM NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddWiredDecoder(cfg.TraceID(), ocsd.BuiltinDcdPTM, ocsd.ProtocolPTM, proc, dec, dec.SetTraceElemOut)
}

func (b *DecodeTreeBuilder) createETEDecoder(coreName string, devSrc *ParsedDevice) error {
	cfg := ete.NewConfig()

	if val, ok := devSrc.RegValue("trcidr0"); ok {
		cfg.RegIdr0 = uint32(parseUint(val))
	}
	// TRCIDR1: use snapshot value if present; ete.NewConfig() already sets the correct ETE default.
	if val, ok := devSrc.RegValue("trcidr1"); ok {
		cfg.RegIdr1 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr2"); ok {
		cfg.RegIdr2 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr8"); ok {
		cfg.RegIdr8 = uint32(parseUint(val))
	}
	// TRCDEVARCH: use snapshot value if present; ete.NewConfig() already sets the correct default.
	if val, ok := devSrc.RegValue("trcdevarch"); ok {
		cfg.RegDevArch = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcconfigr"); ok {
		cfg.RegConfigr = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trctraceidr"); ok {
		cfg.RegTraceidr = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc := ete.NewProcessor(cfg)
		return b.tree.AddDecoder(cfg.TraceID(), ocsd.BuiltinDcdETE, ocsd.ProtocolETE, proc, proc)
	}

	proc, dec, err := ete.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, nil, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ETE NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddWiredDecoder(cfg.TraceID(), ocsd.BuiltinDcdETE, ocsd.ProtocolETE, proc, dec, dec.SetTraceElemOut)
}

func (b *DecodeTreeBuilder) createETMv4Decoder(coreName string, devSrc *ParsedDevice) error {
	cfg := &etmv4.Config{}

	if val, ok := devSrc.RegValue("trcidr0"); ok {
		cfg.RegIdr0 = uint32(parseUint(val))
	}
	// TRCIDR1: use snapshot value if present, otherwise fall back to the C++ default 0x4100F403.
	if val, ok := devSrc.RegValue("trcidr1"); ok {
		cfg.RegIdr1 = uint32(parseUint(val))
	} else {
		cfg.RegIdr1 = 0x4100F403
	}
	if val, ok := devSrc.RegValue("trcidr2"); ok {
		cfg.RegIdr2 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr8"); ok {
		cfg.RegIdr8 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr9"); ok {
		cfg.RegIdr9 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr10"); ok {
		cfg.RegIdr10 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr11"); ok {
		cfg.RegIdr11 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr12"); ok {
		cfg.RegIdr12 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcidr13"); ok {
		cfg.RegIdr13 = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trcconfigr"); ok {
		cfg.RegConfigr = uint32(parseUint(val))
	}
	if val, ok := devSrc.RegValue("trctraceidr"); ok {
		cfg.RegTraceidr = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if b.packetProcOnly {
		proc, err := etmv4.NewConfiguredProcessor(cfg)
		if err != nil {
			return fmt.Errorf("ETMv4 NewConfiguredProcessor failed: %w", err)
		}
		return b.tree.AddDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV4I, ocsd.ProtocolETMV4I, proc, proc)
	}

	proc, dec, err := etmv4.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, nil, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ETMv4 NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddWiredDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV4I, ocsd.ProtocolETMV4I, proc, dec, dec.SetTraceElemOut)
}

func (b *DecodeTreeBuilder) createSTMDecoder(devSrc *ParsedDevice) error {
	cfg := stm.NewConfig()
	if val, ok := devSrc.RegValue("stmtcsr"); ok {
		cfg.RegTCSR = uint32(parseUint(val))
	}
	if b.packetProcOnly {
		proc, err := stm.NewConfiguredPktProc(int(cfg.TraceID()), cfg)
		if err != nil {
			return fmt.Errorf("STM NewConfiguredPktProc failed: %w", err)
		}
		return b.tree.AddDecoder(cfg.TraceID(), ocsd.BuiltinDcdSTM, ocsd.ProtocolSTM, proc, proc)
	}

	proc, dec, err := stm.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, nil, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("STM NewConfiguredPipeline failed: %w", err)
	}
	return b.tree.AddWiredDecoder(cfg.TraceID(), ocsd.BuiltinDcdSTM, ocsd.ProtocolSTM, proc, dec, dec.SetTraceElemOut)
}

func (b *DecodeTreeBuilder) createITMDecoder(devSrc *ParsedDevice) error {
	cfg := &itm.Config{}
	if val, ok := devSrc.RegValue("itmtcr"); ok {
		cfg.RegTCR = uint32(parseUint(val))
	}
	if b.packetProcOnly {
		proc, _, err := itm.NewPipeline(int(cfg.TraceID()), cfg, nil, nil, nil)
		if err != nil {
			return fmt.Errorf("ITM NewPipeline failed: %w", err)
		}
		return b.tree.AddDecoder(cfg.TraceID(), ocsd.BuiltinDcdITM, ocsd.ProtocolITM, proc, proc)
	}

	proc, dec, err := itm.NewPipeline(int(cfg.TraceID()), cfg, nil, b.memIf, b.instrDecode)
	if err != nil {
		return fmt.Errorf("ITM NewPipeline failed: %w", err)
	}
	return b.tree.AddWiredDecoder(cfg.TraceID(), ocsd.BuiltinDcdITM, ocsd.ProtocolITM, proc, dec, dec.SetTraceElemOut)
}

// addCoreDumpMemory adds memory region accessors from a core device's dump definitions.
// It is called once per PE decoder that is successfully created, only in full-decoder mode.
func (b *DecodeTreeBuilder) addCoreDumpMemory(mapper memacc.Mapper, dev *ParsedDevice) {
	for _, dump := range dev.DumpDefs {
		if strings.TrimSpace(dump.Path) == "" {
			continue
		}

		path := filepath.Join(b.reader.Dir(), dump.Path)
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			b.reader.logError(fmt.Sprintf("Failed to read dump file for %s at %s: %v", dev.DeviceName, path, err))
			continue
		}

		if dump.Offset > 0 {
			if dump.Offset >= uint64(len(fileBytes)) {
				b.reader.logError(fmt.Sprintf("Dump offset out of range for %s at %s", dev.DeviceName, path))
				continue
			}
			fileBytes = fileBytes[dump.Offset:]
		}

		if dump.Length > 0 && dump.Length < uint64(len(fileBytes)) {
			fileBytes = fileBytes[:dump.Length]
		}

		if len(fileBytes) == 0 {
			b.reader.logError(fmt.Sprintf("Empty dump mapping for %s at %s", dev.DeviceName, path))
			continue
		}

		acc := memacc.NewBufferAccessor(ocsd.VAddr(dump.Address), fileBytes)
		acc.SetMemSpace(mapDumpMemSpace(dump.Space))
		if err := mapper.AddAccessor(acc, ocsd.BadCSSrcID); err != nil {
			b.reader.logError(fmt.Sprintf("Failed to add memory accessor for %s (%s): %v", dev.DeviceName, path, err))
		}
	}
}
