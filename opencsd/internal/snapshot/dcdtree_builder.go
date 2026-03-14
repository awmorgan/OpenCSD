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

func (l *snapshotErrorLogger) LogError(err *common.Error) {
	if l == nil || l.reader == nil || err == nil {
		return
	}
	l.reader.logError(err.Error())
}

func (l *snapshotErrorLogger) LogMessage(sev ocsd.ErrSeverity, msg string) {
	if l == nil || l.reader == nil {
		return
	}
	if sev <= ocsd.ErrSevWarn {
		l.reader.logError(msg)
		return
	}
	l.reader.logInfo(msg)
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
	"EL3":        ocsd.MemSpaceEL3,
	"EL2S":       ocsd.MemSpaceEL2S,
	"EL1R":       ocsd.MemSpaceEL1R,
	"EL2R":       ocsd.MemSpaceEL2R,
}

func mapDumpMemSpace(space string) ocsd.MemSpaceAcc {
	key := strings.ToUpper(strings.TrimSpace(space))
	if memSpace, ok := dumpSpaceMap[key]; ok {
		return memSpace
	}
	return ocsd.MemSpaceAny
}

// CreateDcdTreeFromSnapShot mimics the C++ class CreateDcdTreeFromSnapShot.
type CreateDcdTreeFromSnapShot struct {
	reader          *Reader
	dcdTree         *dcdtree.DecodeTree
	bPacketProcOnly bool
	bufferFileName  string
}

// NewCreateDcdTreeFromSnapShot creates a new builder for DecodeTree from a snapshot.
func NewCreateDcdTreeFromSnapShot(r *Reader) *CreateDcdTreeFromSnapShot {
	return &CreateDcdTreeFromSnapShot{
		reader: r,
	}
}

// GetDecodeTree returns the built properties.
func (b *CreateDcdTreeFromSnapShot) GetDecodeTree() *dcdtree.DecodeTree {
	return b.dcdTree
}

// GetBufferFileName returns the full path of the trace binary buffer file to load.
func (b *CreateDcdTreeFromSnapShot) GetBufferFileName() string {
	return b.bufferFileName
}

// CreateDecodeTree builds the tree for a specific named source buffer (e.g., "ETB_0").
func (b *CreateDcdTreeFromSnapShot) CreateDecodeTree(sourceName string, bPacketProcOnly bool) bool {
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

		b.dcdTree = dcdtree.CreateDecodeTree(srcFormat, formatterFlags)
		if b.dcdTree == nil {
			b.reader.logError("Failed to create decode tree object")
			return false
		}

		if df := b.dcdTree.GetFrameDeformatter(); df != nil {
			df.SetErrorLogger(&snapshotErrorLogger{reader: b.reader})
		}

		if err := b.setupMemoryAccessors(); err != nil {
			b.reader.logError(fmt.Sprintf("Failed to set up memory accessors: %v", err))
		}

		numDecodersCreated := 0

		for srcName, coreName := range tree.SourceCoreAssoc {
			var devSrc *ParsedDevice
			for _, dev := range b.reader.ParsedDeviceList {
				if dev.DeviceName == srcName {
					devSrc = dev
					break
				}
			}

			if devSrc != nil {
				if coreName != "<none>" && coreName != "" {
					var coreDev *ParsedDevice
					for _, dev := range b.reader.ParsedDeviceList {
						if dev.DeviceName == coreName {
							coreDev = dev
							break
						}
					}
					if coreDev != nil {
						err := b.createPEDecoder(coreDev.DeviceTypeName, devSrc, coreDev)
						if err == nil {
							numDecodersCreated++
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

func (b *CreateDcdTreeFromSnapShot) createPEDecoder(coreName string, devSrc *ParsedDevice, coreDev *ParsedDevice) error {
	devTypeName := devSrc.DeviceTypeName

	if strings.HasPrefix(devTypeName, "ETMv3") || strings.HasPrefix(devTypeName, "ETM3") {
		return b.createETMv3Decoder(coreName, devSrc)
	} else if strings.HasPrefix(devTypeName, "ETMv4") || strings.HasPrefix(devTypeName, "ETM4") {
		return b.createETMv4Decoder(coreName, devSrc)
	} else if strings.HasPrefix(devTypeName, "ETE") {
		return b.createETEDecoder(coreName, devSrc)
	} else if strings.HasPrefix(devTypeName, "PTM") || strings.HasPrefix(devTypeName, "PFT") {
		return b.createPTMDecoder(coreName, devSrc)
	}
	return fmt.Errorf("unknown PE devType: %s", devTypeName)
}

func (b *CreateDcdTreeFromSnapShot) createSTDecoder(devSrc *ParsedDevice) error {
	devTypeName := devSrc.DeviceTypeName

	if strings.HasPrefix(devTypeName, "STM") {
		return b.createSTMDecoder(devSrc)
	} else if strings.HasPrefix(devTypeName, "ITM") {
		return b.createITMDecoder(devSrc)
	}
	return fmt.Errorf("unknown ST devType: %s", devTypeName)
}

func (b *CreateDcdTreeFromSnapShot) createETMv3Decoder(coreName string, devSrc *ParsedDevice) error {
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

	createFlags := ocsd.CreateFlgFullDecoder
	if b.bPacketProcOnly {
		createFlags = ocsd.CreateFlgPacketProc
	}
	err := b.dcdTree.CreateDecoder(ocsd.BuiltinDcdETMV3, int(createFlags), cfg)
	if err != ocsd.OK {
		return fmt.Errorf("dcdTree.CreateDecoder ETMv3 failed: %v", err)
	}
	return nil
}

func (b *CreateDcdTreeFromSnapShot) createPTMDecoder(coreName string, devSrc *ParsedDevice) error {
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

	createFlags := ocsd.CreateFlgFullDecoder
	if b.bPacketProcOnly {
		createFlags = ocsd.CreateFlgPacketProc
	}
	err := b.dcdTree.CreateDecoder(ocsd.BuiltinDcdPTM, int(createFlags), cfg)
	if err != ocsd.OK {
		return fmt.Errorf("dcdTree.CreateDecoder PTM failed: %v", err)
	}
	return nil
}

func (b *CreateDcdTreeFromSnapShot) createETEDecoder(coreName string, devSrc *ParsedDevice) error {
	cfg := ete.NewConfig()

	if val, ok := devSrc.GetRegValue("trcidr0"); ok {
		cfg.RegIdr0 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr1"); ok {
		cfg.RegIdr1 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr2"); ok {
		cfg.RegIdr2 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr8"); ok {
		cfg.RegIdr8 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcdevarch"); ok {
		cfg.RegDevArch = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcconfigr"); ok {
		cfg.RegConfigr = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trctraceidr"); ok {
		cfg.RegTraceidr = uint32(parseUint(val))
	}

	createFlags := ocsd.CreateFlgFullDecoder
	if b.bPacketProcOnly {
		createFlags = ocsd.CreateFlgPacketProc
	}
	err := b.dcdTree.CreateDecoder(ocsd.BuiltinDcdETE, int(createFlags), cfg)
	if err != ocsd.OK {
		return fmt.Errorf("dcdTree.CreateDecoder ETE failed: %v", err)
	}
	return nil
}

func (b *CreateDcdTreeFromSnapShot) createETMv4Decoder(coreName string, devSrc *ParsedDevice) error {
	cfg := &etmv4.Config{}

	if val, ok := devSrc.GetRegValue("trcidr0"); ok {
		cfg.RegIdr0 = uint32(parseUint(val))
	}
	if val, ok := devSrc.GetRegValue("trcidr1"); ok {
		cfg.RegIdr1 = uint32(parseUint(val))
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

	createFlags := ocsd.CreateFlgFullDecoder
	if b.bPacketProcOnly {
		createFlags = ocsd.CreateFlgPacketProc
	}
	err := b.dcdTree.CreateDecoder(ocsd.BuiltinDcdETMV4I, int(createFlags), cfg)
	if err != ocsd.OK {
		return fmt.Errorf("dcdTree.CreateDecoder ETMv4 failed: %v", err)
	}
	return nil
}

func (b *CreateDcdTreeFromSnapShot) createSTMDecoder(devSrc *ParsedDevice) error {
	cfg := stm.NewConfig()
	if val, ok := devSrc.GetRegValue("stmtcsr"); ok {
		cfg.RegTCSR = uint32(parseUint(val))
	}
	createFlags := ocsd.CreateFlgFullDecoder
	if b.bPacketProcOnly {
		createFlags = ocsd.CreateFlgPacketProc
	}
	err := b.dcdTree.CreateDecoder(ocsd.BuiltinDcdSTM, int(createFlags), cfg)
	if err != ocsd.OK {
		return fmt.Errorf("dcdTree.CreateDecoder STM failed: %v", err)
	}
	return nil
}

func (b *CreateDcdTreeFromSnapShot) createITMDecoder(devSrc *ParsedDevice) error {
	cfg := itm.NewConfig()
	if val, ok := devSrc.GetRegValue("itmtcr"); ok {
		cfg.RegTCR = uint32(parseUint(val))
	}
	createFlags := ocsd.CreateFlgFullDecoder
	if b.bPacketProcOnly {
		createFlags = ocsd.CreateFlgPacketProc
	}
	err := b.dcdTree.CreateDecoder(ocsd.BuiltinDcdITM, int(createFlags), cfg)
	if err != ocsd.OK {
		return fmt.Errorf("dcdTree.CreateDecoder ITM failed: %v", err)
	}
	return nil
}

func (b *CreateDcdTreeFromSnapShot) setupMemoryAccessors() error {
	if b.dcdTree == nil {
		return fmt.Errorf("decode tree is nil")
	}

	mapper := memacc.NewGlobalMapper()
	b.dcdTree.SetMemAccessI(&mapperAdapter{mapper: mapper})

	for devName, dev := range b.reader.ParsedDeviceList {
		for _, dump := range dev.DumpDefs {
			if strings.TrimSpace(dump.Path) == "" {
				continue
			}

			path := filepath.Join(b.reader.SnapshotPath, dump.Path)
			fileBytes, err := os.ReadFile(path)
			if err != nil {
				b.reader.logError(fmt.Sprintf("Failed to read dump file for %s at %s: %v", devName, path, err))
				continue
			}

			if dump.Offset > 0 {
				if dump.Offset >= uint64(len(fileBytes)) {
					b.reader.logError(fmt.Sprintf("Dump offset out of range for %s at %s", devName, path))
					continue
				}
				fileBytes = fileBytes[dump.Offset:]
			}

			if dump.Length > 0 {
				if dump.Length < uint64(len(fileBytes)) {
					fileBytes = fileBytes[:dump.Length]
				}
			}

			if len(fileBytes) == 0 {
				b.reader.logError(fmt.Sprintf("Empty dump mapping for %s at %s", devName, path))
				continue
			}

			acc := memacc.NewBufferAccessor(ocsd.VAddr(dump.Address), fileBytes)
			acc.SetMemSpace(mapDumpMemSpace(dump.Space))
			if errCode := mapper.AddAccessor(acc, 0); errCode != ocsd.OK {
				b.reader.logError(fmt.Sprintf("Failed to add memory accessor for %s (%s): %v", devName, path, errCode))
				continue
			}
		}
	}

	return nil
}
