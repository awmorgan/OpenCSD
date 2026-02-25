package printers

import (
	"fmt"
	"io"
	"strings"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// GenericElementPrinter translates the C++ TrcGenericElementPrinter class.
type GenericElementPrinter struct {
	ItemPrinter
	needWaitAck  bool
	collectStats bool
	packetCounts map[common.GenElemType]int
}

// NewGenericElementPrinter creates a new generic element printer.
func NewGenericElementPrinter(writer io.Writer) *GenericElementPrinter {
	return &GenericElementPrinter{
		ItemPrinter:  *NewItemPrinter(writer),
		packetCounts: make(map[common.GenElemType]int),
	}
}

// TraceElemIn implements the TrcGenElemIn interface.
func (p *GenericElementPrinter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *common.TraceElement) ocsd.DatapathResp {
	resp := ocsd.RespCont

	if p.collectStats {
		p.packetCounts[elem.ElemType]++
	}

	if p.IsMuted() {
		return resp
	}

	var sb strings.Builder
	if !p.IDPrintMuted() {
		sb.WriteString(fmt.Sprintf("Idx:%d; ID:%x; ", indexSOP, trcChanID))
	}

	// append trace element standard formatting
	sb.WriteString(elem.String())
	sb.WriteString("\n")

	p.ItemPrintLine(sb.String())

	// Functonality to test wait / flush mechanism
	if p.needWaitAck {
		p.ItemPrintLine("WARNING: Generic Element Printer; New element without previous _WAIT acknowledged\n")
		p.needWaitAck = false
	}

	if p.TestWaits() > 0 {
		resp = ocsd.RespWait
		p.DecTestWaits()
		p.needWaitAck = true
	}

	return resp
}

// AckWait acknowledges a wait signal.
func (p *GenericElementPrinter) AckWait() { p.needWaitAck = false }

// NeedAckWait returns whether the printer was waiting for acknowledgement.
func (p *GenericElementPrinter) NeedAckWait() bool { return p.needWaitAck }

// SetCollectStats turns on statistics collections.
func (p *GenericElementPrinter) SetCollectStats() { p.collectStats = true }

// PrintStats outputs statistics about the elements processed.
func (p *GenericElementPrinter) PrintStats() {
	var sb strings.Builder

	sb.WriteString("Generic Packets processed:-\n")
	for i := common.GenElemUnknown; i <= common.GenElemCustom; i++ {
		sb.WriteString(fmt.Sprintf("%s : %d\n", elemName(i), p.packetCounts[i]))
	}
	sb.WriteString("\n\n")

	p.ItemPrintLine(sb.String())
}

func elemName(t common.GenElemType) string {
	names := map[common.GenElemType]string{
		common.GenElemUnknown:         "OCSD_GEN_TRC_ELEM_UNKNOWN",
		common.GenElemNoSync:          "OCSD_GEN_TRC_ELEM_NO_SYNC",
		common.GenElemTraceOn:         "OCSD_GEN_TRC_ELEM_TRACE_ON",
		common.GenElemEOTrace:         "OCSD_GEN_TRC_ELEM_EO_TRACE",
		common.GenElemPeContext:       "OCSD_GEN_TRC_ELEM_PE_CONTEXT",
		common.GenElemInstrRange:      "OCSD_GEN_TRC_ELEM_INSTR_RANGE",
		common.GenElemIRangeNopath:    "OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH",
		common.GenElemAddrNacc:        "OCSD_GEN_TRC_ELEM_ADDR_NACC",
		common.GenElemAddrUnknown:     "OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN",
		common.GenElemException:       "OCSD_GEN_TRC_ELEM_EXCEPTION",
		common.GenElemExceptionRet:    "OCSD_GEN_TRC_ELEM_EXCEPTION_RET",
		common.GenElemTimestamp:       "OCSD_GEN_TRC_ELEM_TIMESTAMP",
		common.GenElemCycleCount:      "OCSD_GEN_TRC_ELEM_CYCLE_COUNT",
		common.GenElemEvent:           "OCSD_GEN_TRC_ELEM_EVENT",
		common.GenElemSWTrace:         "OCSD_GEN_TRC_ELEM_SWTRACE",
		common.GenElemSyncMarker:      "OCSD_GEN_TRC_ELEM_SYNC_MARKER",
		common.GenElemMemTrans:        "OCSD_GEN_TRC_ELEM_MEMTRANS",
		common.GenElemInstrumentation: "OCSD_GEN_TRC_ELEM_INSTRUMENTATION",
		common.GenElemITMTrace:        "OCSD_GEN_TRC_ELEM_ITMTRACE",
		common.GenElemCustom:          "OCSD_GEN_TRC_ELEM_CUSTOM",
	}

	if name, ok := names[t]; ok {
		return name
	}
	return "OCSD_GEN_TRC_ELEM_UNKNOWN"
}
