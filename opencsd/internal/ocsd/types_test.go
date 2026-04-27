package ocsd

import (
	"errors"
	"testing"
)

func TestConstantsAndMasks(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{name: "DfrmtrHasFsyncs", got: DfrmtrHasFsyncs, want: 0x01},
		{name: "DfrmtrValidMask", got: DfrmtrValidMask, want: 0x3F},
		{name: "DfrmtrFrameSize", got: DfrmtrFrameSize, want: 0x10},
		{
			name: "OpflgPktprocCommon",
			got:  OpflgPktprocCommon,
			want: OpflgPktprocNofwdBadPkts | OpflgPktprocNomonBadPkts | OpflgPktprocErrBadPkts | OpflgPktprocUnsyncOnBadPkts,
		},
		{
			name: "OpflgPktdecCommon",
			got:  OpflgPktdecCommon,
			want: OpflgPktdecErrorBadPkts | OpflgPktdecHaltBadPkts | OpflgNUncondDirBrChk | OpflgStrictNUncondBrChk | OpflgChkRangeContinue | OpflgNUncondChkNoThumb,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got 0x%X, want 0x%X", tt.got, tt.want)
			}
		})
	}
}

func TestDatapathRespPredicates(t *testing.T) {
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "fatal", got: DataRespIsFatal(RespFatalNotInit), want: true},
		{name: "wait not fatal", got: DataRespIsFatal(RespErrWait), want: false},
		{name: "warn cont", got: DataRespIsWarn(RespWarnCont), want: true},
		{name: "warn wait", got: DataRespIsWarn(RespWarnWait), want: true},
		{name: "err is not warn", got: DataRespIsWarn(RespErrCont), want: false},
		{name: "err cont", got: DataRespIsErr(RespErrCont), want: true},
		{name: "err wait", got: DataRespIsErr(RespErrWait), want: true},
		{name: "warn is not err", got: DataRespIsErr(RespWarnCont), want: false},
		{name: "warn or err warn", got: DataRespIsWarnOrErr(RespWarnWait), want: true},
		{name: "warn or err err", got: DataRespIsWarnOrErr(RespErrCont), want: true},
		{name: "continue", got: DataRespIsCont(RespWarnCont), want: true},
		{name: "wait not continue", got: DataRespIsCont(RespWait), want: false},
		{name: "wait", got: DataRespIsWait(RespWait), want: true},
		{name: "fatal not wait", got: DataRespIsWait(RespFatalSysErr), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestTypeHelpers(t *testing.T) {
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "IsV8Arch v8.3", got: IsV8Arch(ArchV8r3), want: true},
		{name: "IsV8Arch aa64", got: IsV8Arch(ArchAA64), want: true},
		{name: "IsV8Arch v8", got: IsV8Arch(ArchV8), want: true},
		{name: "IsV8Arch v7", got: IsV8Arch(ArchV7), want: false},
		{name: "IsV8Arch custom", got: IsV8Arch(ArchCustom), want: false},
		{name: "IsArchMinVer true", got: IsArchMinVer(ArchV8, ArchV7), want: true},
		{name: "IsArchMinVer false", got: IsArchMinVer(ArchV7, ArchV8), want: false},
		{name: "ProtocolIsBuiltin true", got: ProtocolIsBuiltin(ProtocolETMV4I), want: true},
		{name: "ProtocolIsBuiltin custom", got: ProtocolIsBuiltin(ProtocolCustom0), want: false},
		{name: "ProtocolIsBuiltin unknown", got: ProtocolIsBuiltin(ProtocolUnknown), want: false},
		{name: "ProtocolIsCustom first", got: ProtocolIsCustom(ProtocolCustom0), want: true},
		{name: "ProtocolIsCustom last", got: ProtocolIsCustom(ProtocolCustom9), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %v, want %v", tt.got, tt.want)
			}
		})
	}

	if BitMask(32) != 0xFFFFFFFF {
		t.Errorf("BitMask(32) expected 0xFFFFFFFF, got 0x%X", BitMask(32))
	}
	if BitMask(MaxVABitsize) != VAMask {
		t.Errorf("BitMask(MaxVABitsize) failed")
	}
}

func TestErrorStandardMapping(t *testing.T) {
	for _, err := range []error{nil, ErrFail, ErrNotInit} {
		if err != nil && err.Error() == "" {
			t.Errorf("Error codes should map to an error interface with content")
		}
	}
}

func TestErrHelpers(t *testing.T) {
	// IsMemNacc etc are no longer helpers if we use errors.Is
	if !errors.Is(ErrMemNacc, ErrMemNacc) {
		t.Error("errors.Is(ErrMemNacc, ErrMemNacc) should be true")
	}
	if errors.Is(ErrMemAccOverlap, ErrMemNacc) {
		t.Error("errors.Is(ErrMemAccOverlap, ErrMemNacc) should be false")
	}
}

func TestDatapathFlowControlSentinels(t *testing.T) {
	if !IsDataWaitErr(ErrWait) {
		t.Error("IsDataWaitErr(ErrWait) should be true")
	}
	if IsDataWaitErr(nil) {
		t.Error("IsDataWaitErr(nil) should be false")
	}

	if !IsDataContErr(nil) {
		t.Error("IsDataContErr(nil) should be true")
	}
	if IsDataContErr(ErrWait) {
		t.Error("IsDataContErr(ErrWait) should be false")
	}
}

func TestDataResponseErrorMappings(t *testing.T) {
	respTests := []struct {
		err  error
		want DatapathResp
	}{
		{nil, RespCont},
		{ErrWait, RespWait},
		{ErrNotInit, RespFatalNotInit},
		{ErrInvalidParamVal, RespFatalInvalidParam},
		{ErrInvalidParamType, RespFatalInvalidParam},
		{ErrBadPacketSeq, RespFatalInvalidData},
	}
	for _, tt := range respTests {
		if got := DataRespFromErr(tt.err); got != tt.want {
			t.Fatalf("DataRespFromErr(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}

	errTests := []struct {
		resp DatapathResp
		want error
	}{
		{RespCont, nil},
		{RespWait, ErrWait},
		{RespFatalNotInit, ErrNotInit},
		{RespFatalInvalidParam, ErrInvalidParamVal},
		{RespFatalInvalidOp, ErrInvalidParamVal},
		{RespFatalSysErr, ErrFail},
		{RespFatalInvalidData, ErrDataDecodeFatal},
	}
	for _, tt := range errTests {
		if got := DataErrFromResp(tt.resp, nil); !errors.Is(got, tt.want) {
			t.Fatalf("DataErrFromResp(%v) = %v, want %v", tt.resp, got, tt.want)
		}
	}
}

func TestEnumCombinations(t *testing.T) {
	inMemSpace := func(acc MemSpaceAcc, target MemSpaceAcc) bool {
		if target == MemSpaceNone {
			return false
		}
		if target == MemSpaceAny {
			return true
		}
		return (acc & target) != 0
	}

	if !inMemSpace(MemSpaceEL1S, MemSpaceS) {
		t.Error("MemSpaceEL1S should be in MemSpaceS")
	}
	if !inMemSpace(MemSpaceEL2, MemSpaceN) {
		t.Error("MemSpaceEL2 should be in MemSpaceN")
	}
	if inMemSpace(MemSpaceEL1N, MemSpaceS) {
		t.Error("MemSpaceEL1N should not be in MemSpaceS")
	}
	if !inMemSpace(MemSpaceEL1R, MemSpaceAny) {
		t.Error("Everything should be in MemSpaceAny")
	}
}

func TestMemSpaceString(t *testing.T) {
	tests := []struct {
		space MemSpaceAcc
		want  string
	}{
		{MemSpaceNone, "None"},
		{MemSpaceEL2, "EL2N"},
		{MemSpaceN, "Any NS"},
		{MemSpaceEL1S | MemSpaceEL2, "EL1S,EL2N"},
		{MemSpaceAcc(0), "None"},
	}
	for _, tt := range tests {
		if got := tt.space.String(); got != tt.want {
			t.Fatalf("%#x.String() = %q, want %q", tt.space, got, tt.want)
		}
	}
}

func TestIDs(t *testing.T) {
	tests := []struct {
		id       uint8
		valid    bool
		reserved bool
	}{
		{id: 0x00, valid: false, reserved: true},
		{id: 0x01, valid: true, reserved: false},
		{id: 0x6F, valid: true, reserved: false},
		{id: 0x70, valid: false, reserved: true},
		{id: 0x7A, valid: false, reserved: true},
	}

	for _, tt := range tests {
		if got := IsValidCSSrcID(tt.id); got != tt.valid {
			t.Fatalf("IsValidCSSrcID(0x%02X) = %v, want %v", tt.id, got, tt.valid)
		}
		if got := IsReservedCSSrcID(tt.id); got != tt.reserved {
			t.Fatalf("IsReservedCSSrcID(0x%02X) = %v, want %v", tt.id, got, tt.reserved)
		}
	}
}
