package common

import (
	"fmt"
	"strings"

	"opencsd/internal/ocsd"
)

// Error represents the library error object.
// It corresponds to the ocsdError class in the C++ library.
type Error struct {
	Code    ocsd.Err
	Sev     ocsd.ErrSeverity
	Idx     ocsd.TrcIndex
	ChanID  uint8
	Message string
}

func NewError(sev ocsd.ErrSeverity, code ocsd.Err) *Error {
	return &Error{
		Code:   code,
		Sev:    sev,
		Idx:    ocsd.BadTrcIndex,
		ChanID: ocsd.BadCSSrcID,
	}
}

func NewErrorWithIdx(sev ocsd.ErrSeverity, code ocsd.Err, idx ocsd.TrcIndex) *Error {
	return &Error{
		Code:   code,
		Sev:    sev,
		Idx:    idx,
		ChanID: ocsd.BadCSSrcID,
	}
}

func NewErrorWithIdxChan(sev ocsd.ErrSeverity, code ocsd.Err, idx ocsd.TrcIndex, chanID uint8) *Error {
	return &Error{
		Code:   code,
		Sev:    sev,
		Idx:    idx,
		ChanID: chanID,
	}
}

func NewErrorMsg(sev ocsd.ErrSeverity, code ocsd.Err, msg string) *Error {
	return &Error{
		Code:    code,
		Sev:     sev,
		Idx:     ocsd.BadTrcIndex,
		ChanID:  ocsd.BadCSSrcID,
		Message: msg,
	}
}

func NewErrorWithIdxMsg(sev ocsd.ErrSeverity, code ocsd.Err, idx ocsd.TrcIndex, msg string) *Error {
	return &Error{
		Code:    code,
		Sev:     sev,
		Idx:     idx,
		ChanID:  ocsd.BadCSSrcID,
		Message: msg,
	}
}

func NewErrorWithIdxChanMsg(sev ocsd.ErrSeverity, code ocsd.Err, idx ocsd.TrcIndex, chanID uint8, msg string) *Error {
	return &Error{
		Code:    code,
		Sev:     sev,
		Idx:     idx,
		ChanID:  chanID,
		Message: msg,
	}
}

// Error implements the standard error interface.
func (e *Error) Error() string {
	var sb strings.Builder

	switch e.Sev {
	case ocsd.ErrSevNone:
		return "LIBRARY INTERNAL ERROR: Invalid Error Object"
	case ocsd.ErrSevError:
		sb.WriteString("ERROR:")
	case ocsd.ErrSevWarn:
		sb.WriteString("WARN :")
	case ocsd.ErrSevInfo:
		sb.WriteString("INFO :")
	default:
		return "LIBRARY INTERNAL ERROR: Invalid Error Object"
	}

	sb.WriteString(fmt.Sprintf("0x%04x ", e.Code))

	if desc, ok := errorCodeDesc[e.Code]; ok {
		sb.WriteString(fmt.Sprintf("(%s) [%s]; ", desc.name, desc.msg))
	} else {
		sb.WriteString("(unknown); ")
	}

	if e.Idx != ocsd.BadTrcIndex {
		sb.WriteString(fmt.Sprintf("TrcIdx=%d; ", e.Idx))
	}

	if e.ChanID != ocsd.BadCSSrcID {
		sb.WriteString(fmt.Sprintf("CS ID=%02x; ", e.ChanID))
	}

	sb.WriteString(e.Message)
	return sb.String()
}

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

type errDesc struct {
	name string
	msg  string
}

// errorCodeDesc maps the C++ static const char *s_errorCodeDescs[][2] string pairs.
var errorCodeDesc = map[ocsd.Err]errDesc{
	ocsd.OK:                       {"OCSD_OK", "No Error."},
	ocsd.ErrFail:                  {"OCSD_ERR_FAIL", "General failure."},
	ocsd.ErrMem:                   {"OCSD_ERR_MEM", "Internal memory allocation error."},
	ocsd.ErrNotInit:               {"OCSD_ERR_NOT_INIT", "Component not initialised."},
	ocsd.ErrInvalidID:             {"OCSD_ERR_INVALID_ID", "Invalid CoreSight Trace Source ID."},
	ocsd.ErrBadHandle:             {"OCSD_ERR_BAD_HANDLE", "Invalid handle passed to component."},
	ocsd.ErrInvalidParamVal:       {"OCSD_ERR_INVALID_PARAM_VAL", "Invalid value parameter passed to component."},
	ocsd.ErrInvalidParamType:      {"OCSD_ERR_INVALID_PARAM_TYPE", "Type mismatch on abstract interface."},
	ocsd.ErrFileError:             {"OCSD_ERR_FILE_ERROR", "File access error"},
	ocsd.ErrNoProtocol:            {"OCSD_ERR_NO_PROTOCOL", "Trace protocol unsupported"},
	ocsd.ErrAttachTooMany:         {"OCSD_ERR_ATTACH_TOO_MANY", "Cannot attach - attach device limit reached."},
	ocsd.ErrAttachInvalidParam:    {"OCSD_ERR_ATTACH_INVALID_PARAM", " Cannot attach - invalid parameter."},
	ocsd.ErrAttachCompNotFound:    {"OCSD_ERR_ATTACH_COMP_NOT_FOUND", "Cannot detach - component not found."},
	ocsd.ErrRdrFileNotFound:       {"OCSD_ERR_RDR_FILE_NOT_FOUND", "source reader - file not found."},
	ocsd.ErrRdrInvalidInit:        {"OCSD_ERR_RDR_INVALID_INIT", "source reader - invalid initialisation parameter."},
	ocsd.ErrRdrNoDecoder:          {"OCSD_ERR_RDR_NO_DECODER", "source reader - not trace decoder set."},
	ocsd.ErrDataDecodeFatal:       {"OCSD_ERR_DATA_DECODE_FATAL", "A decoder in the data path has returned a fatal error."},
	ocsd.ErrDfrmtrNotconttrace:    {"OCSD_ERR_DFMTR_NOTCONTTRACE", "Trace input to deformatter none-continuous"},
	ocsd.ErrDfrmtrBadFhsync:       {"OCSD_ERR_DFMTR_BAD_FHSYNC", "Bad frame or half frame sync in trace deformatter"},
	ocsd.ErrBadPacketSeq:          {"OCSD_ERR_BAD_PACKET_SEQ", "Bad packet sequence"},
	ocsd.ErrInvalidPcktHdr:        {"OCSD_ERR_INVALID_PCKT_HDR", "Invalid packet header"},
	ocsd.ErrPktInterpFail:         {"OCSD_ERR_PKT_INTERP_FAIL", "Interpreter failed - cannot recover - bad data or sequence"},
	ocsd.ErrUnsupportedISA:        {"OCSD_ERR_UNSUPPORTED_ISA", "ISA not supported in decoder"},
	ocsd.ErrHWCfgUnsupp:           {"OCSD_ERR_HW_CFG_UNSUPP", "Programmed trace configuration not supported by decodUer."},
	ocsd.ErrUnsuppDecodePkt:       {"OCSD_ERR_UNSUPP_DECODE_PKT", "Packet not supported in decoder"},
	ocsd.ErrBadDecodePkt:          {"OCSD_ERR_BAD_DECODE_PKT", "Reserved or unknown packet in decoder."},
	ocsd.ErrCommitPktOverrun:      {"OCSD_ERR_COMMIT_PKT_OVERRUN", "Overrun in commit packet stack - tried to commit more than available"},
	ocsd.ErrMemNacc:               {"OCSD_ERR_MEM_NACC", "Unable to access required memory address."},
	ocsd.ErrRetStackOverflow:      {"OCSD_ERR_RET_STACK_OVERFLOW", "Internal return stack overflow checks failed - popped more than we pushed."},
	ocsd.ErrDcdtNoFormatter:       {"OCSD_ERR_DCDT_NO_FORMATTER", "No formatter in use - operation not valid."},
	ocsd.ErrMemAccOverlap:         {"OCSD_ERR_MEM_ACC_OVERLAP", "Attempted to set an overlapping range in memory access map."},
	ocsd.ErrMemAccFileNotFound:    {"OCSD_ERR_MEM_ACC_FILE_NOT_FOUND", "Memory access file could not be opened."},
	ocsd.ErrMemAccFileDiffRange:   {"OCSD_ERR_MEM_ACC_FILE_DIFF_RANGE", "Attempt to re-use the same memory access file for a different address range."},
	ocsd.ErrMemAccRangeInvalid:    {"OCSD_ERR_MEM_ACC_RANGE_INVALID", "Address range in accessor set to invalid values."},
	ocsd.ErrMemAccBadLen:          {"OCSD_ERR_MEM_ACC_BAD_LEN", "Memory accessor returned a bad read length value (larger than requested."},
	ocsd.ErrTestSnapshotParse:     {"OCSD_ERR_TEST_SNAPSHOT_PARSE", "Test snapshot file parse error"},
	ocsd.ErrTestSnapshotParseInfo: {"OCSD_ERR_TEST_SNAPSHOT_PARSE_INFO", "Test snapshot file parse information"},
	ocsd.ErrTestSnapshotRead:      {"OCSD_ERR_TEST_SNAPSHOT_READ", "test snapshot reader error"},
	ocsd.ErrTestSSToDecoder:       {"OCSD_ERR_TEST_SS_TO_DECODER", "test snapshot to decode tree conversion error"},
	ocsd.ErrDcdregNameRepeat:      {"OCSD_ERR_DCDREG_NAME_REPEAT", "Attempted to register a decoder with the same name as another one."},
	ocsd.ErrDcdregNameUnknown:     {"OCSD_ERR_DCDREG_NAME_UNKNOWN", "Attempted to find a decoder with a name that is not known in the library."},
	ocsd.ErrDcdregTypeUnknown:     {"OCSD_ERR_DCDREG_TYPE_UNKNOWN", "Attempted to find a decoder with a type that is not known in the library."},
	ocsd.ErrDcdregToomany:         {"OCSD_ERR_DCDREG_TOOMANY", "Attempted to register too many custom decoders"},
	ocsd.ErrDcdInterfaceUnused:    {"OCSD_ERR_DCD_INTERFACE_UNUSED", "Attempt to connect or use and interface not supported by this decoder."},
	ocsd.ErrInvalidOpcode:         {"OCSD_ERR_INVALID_OPCODE", "Illegal Opode found while decoding program memory."},
	ocsd.ErrIRangeLimitOverrun:    {"OCSD_ERR_I_RANGE_LIMIT_OVERRUN", "An optional limit on consecutive instructions in range during decode has been exceeded."},
	ocsd.ErrBadDecodeImage:        {"OCSD_ERR_BAD_DECODE_IMAGE", "Mismatch between trace packets and decode image."},
	ocsd.ErrLast:                  {"OCSD_ERR_LAST", "No error - error code end marker"},
}
