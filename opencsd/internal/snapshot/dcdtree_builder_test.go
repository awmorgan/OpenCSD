package snapshot

import (
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
	b.dcdTree = dcdtree.CreateDecodeTree(ocsd.TrcSrcSingle, ocsd.DfrmtrFrameMemAlign)
	if b.dcdTree == nil {
		t.Fatal("CreateDecodeTree returned nil")
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
