package common

import "opencsd/internal/ocsd"

// DataRespStr returns a string representation for an ocsd.DatapathResp value.
// It matches the exact strings from ocsdDataRespStr::getStr() in C++.
func DataRespStr(resp ocsd.DatapathResp) string {
	switch resp {
	case ocsd.RespCont:
		return "OCSD_RESP_CONT: Continue processing."
	case ocsd.RespWarnCont:
		return "OCSD_RESP_WARN_CONT: Continue processing -> a component logged a warning."
	case ocsd.RespErrCont:
		return "OCSD_RESP_ERR_CONT: Continue processing -> a component logged an error."
	case ocsd.RespWait:
		return "OCSD_RESP_WAIT: Pause processing"
	case ocsd.RespWarnWait:
		return "OCSD_RESP_WARN_WAIT: Pause processing -> a component logged a warning."
	case ocsd.RespErrWait:
		return "OCSD_RESP_ERR_WAIT: Pause processing -> a component logged an error."
	case ocsd.RespFatalNotInit:
		return "OCSD_RESP_FATAL_NOT_INIT: Processing Fatal Error :  component unintialised."
	case ocsd.RespFatalInvalidOp:
		return "OCSD_RESP_FATAL_INVALID_OP: Processing Fatal Error :  invalid data path operation."
	case ocsd.RespFatalInvalidParam:
		return "OCSD_RESP_FATAL_INVALID_PARAM: Processing Fatal Error :  invalid parameter in datapath call."
	case ocsd.RespFatalInvalidData:
		return "OCSD_RESP_FATAL_INVALID_DATA: Processing Fatal Error :  invalid trace data."
	case ocsd.RespFatalSysErr:
		return "OCSD_RESP_FATAL_SYS_ERR: Processing Fatal Error :  internal system error."
	default:
		return "Unknown OCSD_RESP type."
	}
}

/*
Annotated Error Usage:

Caller packages should annotate base errors with context using fmt.Errorf and %w:

    if err := memacc.Read(addr, len, buf); err != nil {
        return fmt.Errorf("%w: at index %d, channel %02x", ocsd.ErrMemNacc, idx, chanID)
    }

This allows downstream components to use errors.Is(err, ocsd.ErrMemNacc) while
preserving the diagnostic context in the error string.
*/
