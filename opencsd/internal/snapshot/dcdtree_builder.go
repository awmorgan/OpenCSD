package snapshot

import (
	"fmt"
	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv3"
	"opencsd/internal/itm"
	"opencsd/internal/ocsd"
	"opencsd/internal/ptm"
	"opencsd/internal/stm"
	"path/filepath"
	"strings"
)

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
