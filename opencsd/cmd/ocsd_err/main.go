// Package main implements ocsd_err - lists OCSD error codes and their descriptions.
// This is a Go port of the C++ perr.cpp utility.
package main

import (
	"fmt"
)

const errListPlaceholderMsg = "ocsd_err uses a hardcoded placeholder error list and is not wired to the core library.\n"

// ErrorInfo represents an OCSD error code and its description
type ErrorInfo struct {
	Code        int
	Description string
}

// The error codes are based on the C++ OCSD_ERR_* enums.
// These are placeholder values - they should match the actual OCSD library error codes.
var errorCodes = []ErrorInfo{
	{0, "OCSD_OK - No error"},
	{1, "OCSD_ERR_FAIL - General error"},
	{2, "OCSD_ERR_MEM - Memory allocation failure"},
	{3, "OCSD_ERR_NOT_INIT - Component not initialized"},
	{4, "OCSD_ERR_INVALID_PARAM_VAL - Invalid parameter value"},
	{5, "OCSD_ERR_INVALID_PARAM_TYPE - Invalid parameter type"},
	{6, "OCSD_ERR_UNSUPPORTED_ISA - Unsupported instruction set"},
	{7, "OCSD_ERR_UNSUPPORTED_ARCH - Unsupported architecture"},
	{8, "OCSD_ERR_UNSUPPORTED_CORE_PROFILE - Unsupported core profile"},
	{9, "OCSD_ERR_UNSUPPORTED_PROTOCOL - Unsupported protocol"},
	{10, "OCSD_ERR_UNSUPPORTED_OPCODE - Unsupported opcode"},
	{11, "OCSD_ERR_INVALID_INSTR_SIZE - Invalid instruction size"},
	{12, "OCSD_ERR_RESOURCE_NOT_AVAILABLE - Resource not available"},
	{13, "OCSD_ERR_INVALID_HANDLE - Invalid handle"},
	{14, "OCSD_ERR_HANDLE_TYPE_MISMATCH - Handle type mismatch"},
	{15, "OCSD_ERR_INVALID_ID - Invalid ID"},
	{16, "OCSD_ERR_ALL_HANDLED - All items handled"},
	{17, "OCSD_ERR_COND_NOT_MET - Condition not met"},
	{18, "OCSD_ERR_NO_PROTOCOL_DECODER - No protocol decoder"},
	{19, "OCSD_ERR_BAD_PACKET_SEQ - Bad packet sequence"},
	{20, "OCSD_ERR_INVALID_PACKET_TYPE - Invalid packet type"},
	{21, "OCSD_ERR_ELEM_UNDERFLOW - Element underflow"},
	{22, "OCSD_ERR_DATA_DECODE_FATAL - Data decode fatal"},
	{23, "OCSD_ERR_INSTR_DECODE_FAIL - Instruction decode fail"},
	{24, "OCSD_ERR_INVALID_ADDRESS - Invalid address"},
	{25, "OCSD_ERR_MEM_NOT_ACCESSIBLE - Memory not accessible"},
	{26, "OCSD_ERR_NOT_SUPPORTED - Not supported"},
	{27, "OCSD_ERR_HW_CFG_MISMATCH - Hardware configuration mismatch"},
	{28, "OCSD_ERR_BAD_TRACE_IF_VERSION - Bad trace interface version"},
	{29, "OCSD_ERR_FRAME_DEMUX_FATAL - Frame demux fatal"},
	{30, "OCSD_ERR_INVALID_FILE - Invalid file"},
	{31, "OCSD_ERR_FILE_NOT_FOUND - File not found"},
	{32, "OCSD_ERR_NO_MEMORY - No memory"},
	{33, "OCSD_ERR_BAD_FILE_FORMAT - Bad file format"},
}

func main() {
	fmt.Print(errListPlaceholderMsg)

	fmt.Println("OCSD Error Code List\n")

	for _, errInfo := range errorCodes {
		fmt.Printf("%d: %s\n", errInfo.Code, errInfo.Description)
	}
}
