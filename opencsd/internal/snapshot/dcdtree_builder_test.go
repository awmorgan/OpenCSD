package snapshot

import (
	"errors"
	"path/filepath"
	"testing"

	"opencsd/internal/dcdtree"
	"opencsd/internal/ocsd"
)

func TestMapDumpMemSpace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want ocsd.MemSpaceAcc
	}{
		{name: "el1s", in: "EL1S", want: ocsd.MemSpaceEL1S},
		{name: "el2", in: "el2", want: ocsd.MemSpaceEL2},
		{name: "el2n alias", in: "EL2N", want: ocsd.MemSpaceEL2},
		{name: "secure", in: "S", want: ocsd.MemSpaceS},
		{name: "nonsecure", in: "N", want: ocsd.MemSpaceN},
		{name: "any", in: "ANY", want: ocsd.MemSpaceAny},
		{name: "unknown defaults any", in: "UNKNOWN", want: ocsd.MemSpaceAny},
		// Legacy C++ aliases
		{name: "H hypervisor", in: "H", want: ocsd.MemSpaceEL2},
		{name: "P privileged", in: "P", want: ocsd.MemSpaceEL1N},
		{name: "NP non-secure privileged", in: "NP", want: ocsd.MemSpaceEL1N},
		{name: "SP secure privileged", in: "SP", want: ocsd.MemSpaceEL1S},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mapDumpMemSpace(tc.in)
			if got != tc.want {
				t.Fatalf("mapDumpMemSpace(%q)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCreatePEDecoderRoutesETMv4(t *testing.T) {
	t.Parallel()

	b := NewDecodeTreeBuilder(NewReader())
	tree, err := dcdtree.NewDecodeTree(ocsd.TrcSrcSingle, ocsd.DfrmtrFrameMemAlign)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	b.tree = tree
	if b.tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}

	devSrc := NewParsedDevice()
	devSrc.DeviceTypeName = "ETMv4"
	devSrc.RegDefs["trctraceidr"] = "0x10"

	if err := b.createPEDecoder(devSrc.DeviceTypeName, devSrc, "Cortex-A53"); err != nil {
		t.Fatalf("createPEDecoder ETMv4 route failed: %v", err)
	}
}

func TestNewDecodeTreeBuilderWithRegistryStoresRegistry(t *testing.T) {
	t.Parallel()

	reg := dcdtree.NewDecoderRegister()
	b := NewDecodeTreeBuilderWithRegistry(NewReader(), reg)
	if b.registry != reg {
		t.Fatal("expected builder to keep the injected registry")
	}
}

func TestBuildPropagatesFormatterConfigFailure(t *testing.T) {
	reader := NewReader()
	reader.readOK = true
	reader.SnapshotPath = "C:/snapshot"
	reader.ParsedTrace = &ParsedTrace{
		TraceBuffers: []TraceBufferInfo{{
			BufferName:   "BUF0",
			DataFileName: "trace.bin",
			DataFormat:   "frame_data",
		}},
		SourceBufferAssoc: map[string]string{},
		CPUSourceAssoc:    map[string]string{},
	}

	b := NewDecodeTreeBuilder(reader)

	origNewDecodeTree := newDecodeTree
	t.Cleanup(func() { newDecodeTree = origNewDecodeTree })
	newDecodeTree = func(srcType ocsd.DcdTreeSrc, _ uint32) (*dcdtree.DecodeTree, error) {
		return dcdtree.NewDecodeTree(srcType, 0)
	}

	tree, err := b.Build("BUF0", true)
	if err == nil {
		t.Fatal("expected formatter configuration failure to propagate from builder")
	}
	if !errors.Is(err, dcdtree.ErrCreateDecodeTree) {
		t.Fatalf("expected ErrCreateDecodeTree, got %v", err)
	}
	if tree != nil {
		t.Fatal("expected nil tree on formatter configuration failure")
	}
}

func TestBuildStillCreatesDecodeTreeOnValidFormatterConfig(t *testing.T) {
	reader := NewReader()
	reader.readOK = true
	reader.SnapshotPath = "C:/snapshot"
	reader.ParsedTrace = &ParsedTrace{
		TraceBuffers: []TraceBufferInfo{{
			BufferName:   "BUF0",
			DataFileName: "trace.bin",
			DataFormat:   "dstream_coresight",
		}},
		SourceBufferAssoc: map[string]string{
			"STM_0": "BUF0",
		},
		CPUSourceAssoc: map[string]string{},
	}
	reader.ParsedDeviceList["STM_0"] = &ParsedDevice{
		DeviceName:     "STM_0",
		DeviceTypeName: "STM",
		RegDefs:        map[string]string{"stmtcsr": "0x0"},
	}

	b := NewDecodeTreeBuilder(reader)
	tree, err := b.Build("BUF0", true)
	if err != nil {
		t.Fatalf("expected build success, got %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	if tree.FrameDeformatter() == nil {
		t.Fatal("expected frame deformatter to remain configured")
	}
	if b.BufferFileName() != filepath.Join("C:/snapshot", "trace.bin") {
		t.Fatalf("unexpected buffer file name: %s", b.BufferFileName())
	}
}
