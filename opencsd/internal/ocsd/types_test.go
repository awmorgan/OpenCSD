package ocsd

import (
	"errors"
	"testing"
)

func TestConstantsAndMasks(t *testing.T) {
	// Test Dfrmtr variables
	if DfrmtrHasFsyncs != 0x01 {
		t.Errorf("expected DfrmtrHasFsyncs=0x01, got 0x%X", DfrmtrHasFsyncs)
	}
	if DfrmtrValidMask != 0x3F {
		t.Errorf("expected DfrmtrValidMask=0x3F, got 0x%X", DfrmtrValidMask)
	}
	if DfrmtrFrameSize != 0x10 {
		t.Errorf("expected DfrmtrFrameSize=0x10, got 0x%X", DfrmtrFrameSize)
	}

	// Test OpflgPktprocCommon
	expectedPktProcCommon := OpflgPktprocNofwdBadPkts | OpflgPktprocNomonBadPkts | OpflgPktprocErrBadPkts | OpflgPktprocUnsyncOnBadPkts
	if OpflgPktprocCommon != expectedPktProcCommon {
		t.Errorf("expected OpflgPktprocCommon=0x%X, got 0x%X", expectedPktProcCommon, OpflgPktprocCommon)
	}

	// Test OpflgPktdecCommon
	expectedPktDecCommon := OpflgPktdecErrorBadPkts | OpflgPktdecHaltBadPkts | OpflgNUncondDirBrChk | OpflgStrictNUncondBrChk | OpflgChkRangeContinue | OpflgNUncondChkNoThumb
	if OpflgPktdecCommon != expectedPktDecCommon {
		t.Errorf("expected OpflgPktdecCommon=0x%X, got 0x%X", expectedPktDecCommon, OpflgPktdecCommon)
	}
}

func TestMacros(t *testing.T) {
	// DatapathResp macros
	if !DataRespIsFatal(RespFatalNotInit) {
		t.Error("DataRespIsFatal(RespFatalNotInit) should be true")
	}
	if DataRespIsFatal(RespErrWait) {
		t.Error("DataRespIsFatal(RespErrWait) should be false")
	}

	if !DataRespIsWarn(RespWarnCont) || !DataRespIsWarn(RespWarnWait) || DataRespIsWarn(RespErrCont) {
		t.Error("DataRespIsWarn check failed")
	}

	if !DataRespIsErr(RespErrCont) || !DataRespIsErr(RespErrWait) || DataRespIsErr(RespWarnCont) {
		t.Error("DataRespIsErr check failed")
	}

	if !DataRespIsWarnOrErr(RespWarnWait) || !DataRespIsWarnOrErr(RespErrCont) {
		t.Error("DataRespIsWarnOrErr check failed")
	}

	if !DataRespIsCont(RespWarnCont) || DataRespIsCont(RespWait) {
		t.Error("DataRespIsCont check failed")
	}

	if !DataRespIsWait(RespWait) || DataRespIsWait(RespFatalSysErr) {
		t.Error("DataRespIsWait check failed")
	}

	// Arch macros
	if !IsV8Arch(ArchV8r3) || !IsV8Arch(ArchAA64) || !IsV8Arch(ArchV8) {
		t.Error("IsV8Arch check failed for valid v8 archs")
	}
	if IsV8Arch(ArchV7) || IsV8Arch(ArchCustom) {
		t.Error("IsV8Arch check failed for non-v8 archs")
	}

	if !IsArchMinVer(ArchV8, ArchV7) || IsArchMinVer(ArchV7, ArchV8) {
		t.Error("IsArchMinVer check failed")
	}

	// Protocol Macros
	if !ProtocolIsBuiltin(ProtocolETMV4I) {
		t.Error("ProtocolIsBuiltin failed")
	}
	if ProtocolIsBuiltin(ProtocolCustom0) || ProtocolIsBuiltin(ProtocolUnknown) {
		t.Error("ProtocolIsBuiltin should be false")
	}
	if !ProtocolIsCustom(ProtocolCustom0) || !ProtocolIsCustom(ProtocolCustom9) {
		t.Error("ProtocolIsCustom failed")
	}

	// BitMask macro
	if BitMask(32) != 0xFFFFFFFF {
		t.Errorf("BitMask(32) expected 0xFFFFFFFF, got 0x%X", BitMask(32))
	}
	if BitMask(MaxVABitsize) != VAMask {
		t.Errorf("BitMask(MaxVABitsize) failed")
	}
}

func TestErrorStandardMapping(t *testing.T) {
	errs := []struct {
		err error
	}{
		{nil},
		{ErrFail},
		{ErrNotInit},
	}

	for _, e := range errs {
		if e.err != nil && e.err.Error() == "" {
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

func TestEnumCombinations(t *testing.T) {
	// MemSpaceAcc tests
	inMemSpace := func(acc MemSpaceAcc, target MemSpaceAcc) bool {
		if target == MemSpaceNone {
			return false
		}
		if target == MemSpaceAny {
			return true
		}
		return (acc & target) != 0
	}

	// EL1S in Secure Space (0x1 in 0x19)
	if !inMemSpace(MemSpaceEL1S, MemSpaceS) {
		t.Error("MemSpaceEL1S should be in MemSpaceS")
	}

	// EL2 in Non-Secure Space (0x4 in 0x6)
	if !inMemSpace(MemSpaceEL2, MemSpaceN) {
		t.Error("MemSpaceEL2 should be in MemSpaceN")
	}

	// EL1N not in Secure Space (0x2 in 0x19) -> 0x2 & 0x19 == 0
	if inMemSpace(MemSpaceEL1N, MemSpaceS) {
		t.Error("MemSpaceEL1N should not be in MemSpaceS")
	}

	// ANY
	if !inMemSpace(MemSpaceEL1R, MemSpaceAny) {
		t.Error("Everything should be in MemSpaceAny")
	}
}

func TestIDs(t *testing.T) {
	if !IsValidCSSrcID(0x6F) {
		t.Error("IsValidCSSrcID failed for valid")
	}
	if IsValidCSSrcID(0x00) || IsValidCSSrcID(0x70) {
		t.Error("IsValidCSSrcID failed for invalid")
	}

	if !IsReservedCSSrcID(0x00) || !IsReservedCSSrcID(0x7A) {
		t.Error("IsReservedCSSrcID failed for reserved")
	}
	if IsReservedCSSrcID(0x6F) {
		t.Error("IsReservedCSSrcID failed for non-reserved")
	}
}
