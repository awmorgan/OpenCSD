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
		{name: "secure", in: "S", want: ocsd.MemSpaceS},
		{name: "nonsecure", in: "N", want: ocsd.MemSpaceN},
		{name: "any", in: "ANY", want: ocsd.MemSpaceAny},
		{name: "unknown defaults any", in: "UNKNOWN", want: ocsd.MemSpaceAny},
	}

	for _, tc := range tests {
		tc := tc
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

	b := NewCreateDcdTreeFromSnapShot(NewReader())
	b.dcdTree = dcdtree.CreateDecodeTree(ocsd.TrcSrcSingle, ocsd.DfrmtrFrameMemAlign)
	if b.dcdTree == nil {
		t.Fatal("CreateDecodeTree returned nil")
	}

	devSrc := NewParsedDevice()
	devSrc.DeviceTypeName = "ETMv4"
	devSrc.RegDefs["trctraceidr"] = "0x10"

	coreDev := NewParsedDevice()
	if err := b.createPEDecoder("cpu_0", devSrc, coreDev); err != nil {
		t.Fatalf("createPEDecoder ETMv4 route failed: %v", err)
	}
}
