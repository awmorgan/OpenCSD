package common

import (
	"opencsd/internal/ocsd"
	"testing"
)

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
