package snapshot

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/ete"
	"opencsd/internal/etmv3"
	"opencsd/internal/etmv4"
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

type mapperAdapter struct {
	mapper memacc.Mapper
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	buf := make([]byte, reqBytes)
	readBytes := reqBytes
	err := m.mapper.ReadTargetMemory(address, csTraceID, memSpace, &readBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *mapperAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

type snapshotErrorLogger struct {
	reader *Reader
}

func (l *snapshotErrorLogger) LogError(_ ocsd.HandleErrLog, err *common.Error) {
	if l == nil || l.reader == nil || err == nil {
		return
	}
	l.reader.logError(err.Error())
}

func (l *snapshotErrorLogger) LogMessage(_ ocsd.HandleErrLog, sev ocsd.ErrSeverity, msg string) {
	if l == nil || l.reader == nil {
		return
	}
	if sev <= ocsd.ErrSevWarn {
		l.reader.logError(msg)
		return
	}
	l.reader.logInfo(msg)
}

func (l *snapshotErrorLogger) GetLastError() *common.Error          { return nil }
func (l *snapshotErrorLogger) GetLastIDError(_ uint8) *common.Error { return nil }

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
	reader          *Reader
	registry        *dcdtree.DecoderRegister
	dcdTree         *dcdtree.DecodeTree
	bPacketProcOnly bool
	bufferFileName  string
}

// CreateDcdTreeFromSnapShot is a compatibility alias for the legacy C++-style type name.
type CreateDcdTreeFromSnapShot = DecodeTreeBuilder

// NewDecodeTreeBuilder creates a new builder for DecodeTree from a snapshot.
func NewDecodeTreeBuilder(r *Reader) *DecodeTreeBuilder {
	return NewDecodeTreeBuilderWithRegistry(r, nil)
}

// NewDecodeTreeBuilderWithRegistry creates a new builder with an explicit decoder registry.
// If registry is nil, the package default registry is used when the tree is created.
func NewDecodeTreeBuilderWithRegistry(r *Reader, registry *dcdtree.DecoderRegister) *DecodeTreeBuilder {
	return &DecodeTreeBuilder{
		reader:   r,
		registry: registry,
	}
}

// NewCreateDcdTreeFromSnapShot creates a new builder for DecodeTree from a snapshot.
func NewCreateDcdTreeFromSnapShot(r *Reader) *DecodeTreeBuilder {
	return NewDecodeTreeBuilder(r)
}

// NewCreateDcdTreeFromSnapShotWithRegistry creates a new builder with an explicit decoder registry.
// If registry is nil, the package default registry is used when the tree is created.
func NewCreateDcdTreeFromSnapShotWithRegistry(r *Reader, registry *dcdtree.DecoderRegister) *DecodeTreeBuilder {
	return NewDecodeTreeBuilderWithRegistry(r, registry)
}

// DecodeTree returns the built decode tree.
func (b *DecodeTreeBuilder) DecodeTree() *dcdtree.DecodeTree {
	return b.dcdTree
}

// BufferFileName returns the full path of the trace binary buffer file to load.
func (b *DecodeTreeBuilder) BufferFileName() string {
	return b.bufferFileName
}

// GetDecodeTree returns the built properties.
func (b *DecodeTreeBuilder) GetDecodeTree() *dcdtree.DecodeTree {
	return b.DecodeTree()
}

// GetBufferFileName returns the full path of the trace binary buffer file to load.
func (b *DecodeTreeBuilder) GetBufferFileName() string {
	return b.BufferFileName()
}

// CreateDecodeTree builds the tree for a specific named source buffer (e.g., "ETB_0").
func (b *DecodeTreeBuilder) CreateDecodeTree(sourceName string, bPacketProcOnly bool) bool {
	if !b.reader.SnapshotReadOK() {
		b.reader.logError("Supplied snapshot reader has not correctly read the snapshot.")
		return false
	}

	b.bPacketProcOnly = bPacketProcOnly
	tree := NewTraceBufferSourceTree()

	if ExtractSourceTree(sourceName, b.reader.ParsedTrace, tree) {
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

		b.dcdTree = dcdtree.NewDecodeTree(srcFormat, formatterFlags, b.registry)
		if b.dcdTree == nil {
			b.reader.logError("Failed to create decode tree object")
			return false
		}

		if df := b.dcdTree.GetFrameDeformatter(); df != nil {
			df.SetErrorLogger(&snapshotErrorLogger{reader: b.reader})
		}

		// Create a memory accessor mapper in full-decoder mode only.
		var mapper memacc.Mapper
		if !bPacketProcOnly {
			mapper = memacc.NewGlobalMapper()
			b.dcdTree.SetMemAccessI(&mapperAdapter{mapper: mapper})
		}

		numDecodersCreated := 0

		for srcName, coreName := range tree.SourceCoreAssoc {
			// Direct map lookup — ParsedDeviceList is keyed by device name.
			devSrc := b.reader.ParsedDeviceList[srcName]

			if devSrc != nil {
				if coreName != "<none>" && coreName != "" {
					coreDev := b.reader.ParsedDeviceList[coreName]
					if coreDev != nil {
						err := b.createPEDecoder(devSrc.DeviceTypeName, devSrc, coreName)
						if err == nil {
							numDecodersCreated++
							// Process dump files for this core device in full-decoder mode only.
							if !bPacketProcOnly && len(coreDev.DumpDefs) > 0 {
								b.addCoreDumpMemory(mapper, coreDev)
							}
						} else {
							b.reader.logError(fmt.Sprintf("Failed to create PEDecoder for source %s: %v", srcName, err))
						}
					} else {
						b.reader.logError(fmt.Sprintf("Failed to get device data for core %s.", coreName))
					}
				} else {
					err := b.createSTDecoder(devSrc)
					if err == nil {
						numDecodersCreated++
					} else {
						b.reader.logError(fmt.Sprintf("Failed to create STDecoder for none core source %s: %v", srcName, err))
					}
				}
			} else {
				b.reader.logError(fmt.Sprintf("Failed to find device data for source %s.", srcName))
			}
		}

		if numDecodersCreated == 0 {
			b.dcdTree = nil
			return false
		}
		return true

	} else {
		b.reader.logError(fmt.Sprintf("Failed to get parsed source tree for buffer %s.", sourceName))
		return false
	}
}

// getCoreProfile maps a core device type name (e.g. "Cortex-A57") to its architecture version
// and core profile, matching the C++ CoreArchProfileMap / getCoreProfile behaviour.
func getCoreProfile(coreName string) (ocsd.ArchVersion, ocsd.CoreProfile) {
	if ap, ok := archProfileMap.GetArchProfile(coreName); ok {
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

	if devTypeName == STMProtocol {
		return b.createSTMDecoder(devSrc)
	} else if devTypeName == ITMProtocol {
		return b.createITMDecoder(devSrc)
	}
	return fmt.Errorf("unknown ST devType: %s", devTypeName)
}

func (b *DecodeTreeBuilder) createETMv3Decoder(coreName string, devSrc *ParsedDevice) error {
	cfg := &etmv3.Config{}

	if val, ok := devSrc.GetRegValue("etmcr"); ok {
		cfg.RegCtrl = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("etmtraceidr"); ok {
		cfg.RegTrcID = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("etmidr"); ok {
		cfg.RegIDR = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("etmccer"); ok {
		cfg.RegCCER = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if err := b.createDecoder(ocsd.BuiltinDcdETMV3, cfg); err != nil {
		return fmt.Errorf("dcdTree.CreateDecoder ETMv3 failed: %w", err)
	}
	return nil
}

func (b *DecodeTreeBuilder) createPTMDecoder(coreName string, devSrc *ParsedDevice) error {
	cfg := ptm.NewConfig()

	if val, ok := devSrc.GetRegValue("etmcr"); ok {
		cfg.RegCtrl = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("etmtraceidr"); ok {
		cfg.RegTrcID = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("etmidr"); ok {
		cfg.RegIDR = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("etmccer"); ok {
		cfg.RegCCER = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if err := b.createDecoder(ocsd.BuiltinDcdPTM, cfg); err != nil {
		return fmt.Errorf("dcdTree.CreateDecoder PTM failed: %w", err)
	}
	return nil
}

func (b *DecodeTreeBuilder) createETEDecoder(coreName string, devSrc *ParsedDevice) error {
	cfg := ete.NewConfig()

	if val, ok := devSrc.GetRegValue("trcidr0"); ok {
		cfg.RegIdr0 = uint32(parseUint(val))
	}
	// TRCIDR1: use snapshot value if present; ete.NewConfig() already sets the correct ETE default.
	if val, ok := devSrc.GetRegValue("trcidr1"); ok {
		cfg.RegIdr1 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr2"); ok {
		cfg.RegIdr2 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr8"); ok {
		cfg.RegIdr8 = uint32(parseUint(val))
	}
	// TRCDEVARCH: use snapshot value if present; ete.NewConfig() already sets the correct default.
	if val, ok := devSrc.GetRegValue("trcdevarch"); ok {
		cfg.RegDevArch = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcconfigr"); ok {
		cfg.RegConfigr = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trctraceidr"); ok {
		cfg.RegTraceidr = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if err := b.createDecoder(ocsd.BuiltinDcdETE, cfg); err != nil {
		return fmt.Errorf("dcdTree.CreateDecoder ETE failed: %w", err)
	}
	return nil
}

func (b *DecodeTreeBuilder) createETMv4Decoder(coreName string, devSrc *ParsedDevice) error {
	cfg := &etmv4.Config{}

	if val, ok := devSrc.GetRegValue("trcidr0"); ok {
		cfg.RegIdr0 = uint32(parseUint(val))
	}
	// TRCIDR1: use snapshot value if present, otherwise fall back to the C++ default 0x4100F403.
	if val, ok := devSrc.GetRegValue("trcidr1"); ok {
		cfg.RegIdr1 = uint32(parseUint(val))
	} else {
		cfg.RegIdr1 = 0x4100F403
	}
	if val, ok := devSrc.GetRegValue("trcidr2"); ok {
		cfg.RegIdr2 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr8"); ok {
		cfg.RegIdr8 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr9"); ok {
		cfg.RegIdr9 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr10"); ok {
		cfg.RegIdr10 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr11"); ok {
		cfg.RegIdr11 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr12"); ok {
		cfg.RegIdr12 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr13"); ok {
		cfg.RegIdr13 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcconfigr"); ok {
		cfg.RegConfigr = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trctraceidr"); ok {
		cfg.RegTraceidr = uint32(parseUint(val))
	}

	cfg.ArchVer, cfg.CoreProf = getCoreProfile(coreName)

	if err := b.createDecoder(ocsd.BuiltinDcdETMV4I, cfg); err != nil {
		return fmt.Errorf("dcdTree.CreateDecoder ETMv4 failed: %w", err)
	}
	return nil
}

func (b *DecodeTreeBuilder) createSTMDecoder(devSrc *ParsedDevice) error {
	cfg := stm.NewConfig()
	if val, ok := devSrc.GetRegValue("stmtcsr"); ok {
		cfg.RegTCSR = uint32(parseUint(val))
	}
	if err := b.createDecoder(ocsd.BuiltinDcdSTM, cfg); err != nil {
		return fmt.Errorf("dcdTree.CreateDecoder STM failed: %w", err)
	}
	return nil
}

func (b *DecodeTreeBuilder) createITMDecoder(devSrc *ParsedDevice) error {
	cfg := itm.NewConfig()
	if val, ok := devSrc.GetRegValue("itmtcr"); ok {
		cfg.RegTCR = uint32(parseUint(val))
	}
	if err := b.createDecoder(ocsd.BuiltinDcdITM, cfg); err != nil {
		return fmt.Errorf("dcdTree.CreateDecoder ITM failed: %w", err)
	}
	return nil
}

func (b *DecodeTreeBuilder) createDecoder(decoderName string, cfg any) error {
	if b.bPacketProcOnly {
		err := b.dcdTree.CreatePacketProcessor(decoderName, cfg)
		if err != ocsd.OK {
			return err
		}
		return nil
	}
	err := b.dcdTree.CreateFullDecoder(decoderName, cfg)
	if err != ocsd.OK {
		return err
	}
	return nil
}

// addCoreDumpMemory adds memory region accessors from a core device's dump definitions.
// It is called once per PE decoder that is successfully created, only in full-decoder mode.
func (b *DecodeTreeBuilder) addCoreDumpMemory(mapper memacc.Mapper, dev *ParsedDevice) {
	for _, dump := range dev.DumpDefs {
		if strings.TrimSpace(dump.Path) == "" {
			continue
		}

		path := filepath.Join(b.reader.SnapshotPath, dump.Path)
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
		if errCode := mapper.AddAccessor(acc, 0); errCode != ocsd.OK {
			b.reader.logError(fmt.Sprintf("Failed to add memory accessor for %s (%s): %v", dev.DeviceName, path, errCode))
		}
	}
}
