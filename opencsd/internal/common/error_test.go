package common

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestErrorStrings(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "Invalid SevNone",
			err:      NewError(ocsd.ErrSevNone, ocsd.OK),
			expected: "LIBRARY INTERNAL ERROR: Invalid Error Object",
		},
		{
			name:     "Invalid Sev Out of Bounds",
			err:      NewError(ocsd.ErrSeverity(99), ocsd.OK),
			expected: "LIBRARY INTERNAL ERROR: Invalid Error Object",
		},
		{
			name:     "Error Basic",
			err:      NewError(ocsd.ErrSevError, ocsd.ErrFail),
			expected: "ERROR:0x0001 (OCSD_ERR_FAIL) [General failure.]; ",
		},
		{
			name:     "Warning with index",
			err:      NewErrorWithIdx(ocsd.ErrSevWarn, ocsd.ErrMem, 12345),
			expected: "WARN :0x0002 (OCSD_ERR_MEM) [Internal memory allocation error.]; TrcIdx=12345; ",
		},
		{
			name:     "Info with index and chan",
			err:      NewErrorWithIdxChan(ocsd.ErrSevInfo, ocsd.ErrNotInit, 987, 0x1A),
			expected: "INFO :0x0003 (OCSD_ERR_NOT_INIT) [Component not initialised.]; TrcIdx=987; CS ID=1a; ",
		},
		{
			name:     "Error with msg",
			err:      NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidID, "Custom message here"),
			expected: "ERROR:0x0004 (OCSD_ERR_INVALID_ID) [Invalid CoreSight Trace Source ID.]; Custom message here",
		},
		{
			name:     "Error with Idx Msg",
			err:      NewErrorWithIdxMsg(ocsd.ErrSevError, ocsd.ErrBadHandle, 42, "Bad handle msg"),
			expected: "ERROR:0x0005 (OCSD_ERR_BAD_HANDLE) [Invalid handle passed to component.]; TrcIdx=42; Bad handle msg",
		},
		{
			name:     "Error with Idx Chan Msg",
			err:      NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, 10, 0x22, "Invalid param msg"),
			expected: "ERROR:0x0006 (OCSD_ERR_INVALID_PARAM_VAL) [Invalid value parameter passed to component.]; TrcIdx=10; CS ID=22; Invalid param msg",
		},
		{
			name:     "Unknown error code",
			err:      NewError(ocsd.ErrSevError, 9999),
			expected: "ERROR:0x270f (unknown); ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if got != tc.expected {
				t.Errorf("Expected string: %q, got: %q", tc.expected, got)
			}
		})
	}
}

func TestDataRespStr(t *testing.T) {
	tests := []struct {
		resp     ocsd.DatapathResp
		expected string
	}{
		{ocsd.RespCont, "OCSD_RESP_CONT: Continue processing."},
		{ocsd.RespWarnCont, "OCSD_RESP_WARN_CONT: Continue processing -> a component logged a warning."},
		{ocsd.RespErrCont, "OCSD_RESP_ERR_CONT: Continue processing -> a component logged an error."},
		{ocsd.RespWait, "OCSD_RESP_WAIT: Pause processing"},
		{ocsd.RespWarnWait, "OCSD_RESP_WARN_WAIT: Pause processing -> a component logged a warning."},
		{ocsd.RespErrWait, "OCSD_RESP_ERR_WAIT: Pause processing -> a component logged an error."},
		{ocsd.RespFatalNotInit, "OCSD_RESP_FATAL_NOT_INIT: Processing Fatal Error :  component unintialised."},
		{ocsd.RespFatalInvalidOp, "OCSD_RESP_FATAL_INVALID_OP: Processing Fatal Error :  invalid data path operation."},
		{ocsd.RespFatalInvalidParam, "OCSD_RESP_FATAL_INVALID_PARAM: Processing Fatal Error :  invalid parameter in datapath call."},
		{ocsd.RespFatalInvalidData, "OCSD_RESP_FATAL_INVALID_DATA: Processing Fatal Error :  invalid trace data."},
		{ocsd.RespFatalSysErr, "OCSD_RESP_FATAL_SYS_ERR: Processing Fatal Error :  internal system error."},
		{ocsd.DatapathResp(999), "Unknown OCSD_RESP type."},
	}

	for _, tc := range tests {
		got := DataRespStr(tc.resp)
		if got != tc.expected {
			t.Errorf("Expected func string: %q, got: %q", tc.expected, got)
		}
	}
}
