package printers

import (
	"fmt"
	"io"
	"strings"

	"opencsd/internal/ocsd"
)

const unackedWaitWarning = "WARNING: Generic Element Printer; New element without previous _WAIT acknowledged\n"

// WaitAcker provides an interface for test/output behavior that interacts with the datapath.
type WaitAcker interface {
	NeedAckWait() bool
	AckWait()
}

// GenericElementPrinter translates the C++ TrcGenericElementPrinter class.
type GenericElementPrinter struct {
	ItemPrinter
	needWaitAck  bool
	collectStats bool
	packetCounts map[ocsd.GenElemType]int
}

// NewGenericElementPrinter creates a new generic element printer.
func NewGenericElementPrinter(writer io.Writer) *GenericElementPrinter {
	return &GenericElementPrinter{
		ItemPrinter:  *NewItemPrinter(writer),
		packetCounts: make(map[ocsd.GenElemType]int),
	}
}

// PrintElement prints a single generic trace element.
func (p *GenericElementPrinter) PrintElement(elem *ocsd.TraceElement) error {
	if elem == nil {
		return nil
	}

	p.countElement(elem)
	if p.IsMuted() {
		return nil
	}

	p.printElementLine(elem)
	p.warnOnUnackedWait()
	return p.maybeWait()
}

func (p *GenericElementPrinter) countElement(elem *ocsd.TraceElement) {
	if p.collectStats {
		p.packetCounts[elem.ElemType]++
	}
}

func (p *GenericElementPrinter) printElementLine(elem *ocsd.TraceElement) {
	var sb strings.Builder
	if !p.IDPrintMuted() {
		fmt.Fprintf(&sb, "Idx:%d; ID:%x; ", elem.Index, elem.TraceID)
	}
	sb.WriteString(elem.String())
	sb.WriteByte('\n')
	p.ItemPrintLine(sb.String())
}

func (p *GenericElementPrinter) warnOnUnackedWait() {
	if !p.needWaitAck {
		return
	}
	p.ItemPrintLine(unackedWaitWarning)
	p.needWaitAck = false
}

func (p *GenericElementPrinter) maybeWait() error {
	if p.TestWaits() <= 0 {
		return nil
	}
	p.DecTestWaits()
	p.needWaitAck = true
	return ocsd.ErrWait
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
	for typ := ocsd.GenElemUnknown; typ <= ocsd.GenElemCustom; typ++ {
		fmt.Fprintf(&sb, "%s : %d\n", elemName(typ), p.packetCounts[typ])
	}
	sb.WriteString("\n\n")

	p.ItemPrintLine(sb.String())
}

var elemNames = [...]string{
	ocsd.GenElemUnknown:         "OCSD_GEN_TRC_ELEM_UNKNOWN",
	ocsd.GenElemNoSync:          "OCSD_GEN_TRC_ELEM_NO_SYNC",
	ocsd.GenElemTraceOn:         "OCSD_GEN_TRC_ELEM_TRACE_ON",
	ocsd.GenElemEOTrace:         "OCSD_GEN_TRC_ELEM_EO_TRACE",
	ocsd.GenElemPeContext:       "OCSD_GEN_TRC_ELEM_PE_CONTEXT",
	ocsd.GenElemInstrRange:      "OCSD_GEN_TRC_ELEM_INSTR_RANGE",
	ocsd.GenElemIRangeNopath:    "OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH",
	ocsd.GenElemAddrNacc:        "OCSD_GEN_TRC_ELEM_ADDR_NACC",
	ocsd.GenElemAddrUnknown:     "OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN",
	ocsd.GenElemException:       "OCSD_GEN_TRC_ELEM_EXCEPTION",
	ocsd.GenElemExceptionRet:    "OCSD_GEN_TRC_ELEM_EXCEPTION_RET",
	ocsd.GenElemTimestamp:       "OCSD_GEN_TRC_ELEM_TIMESTAMP",
	ocsd.GenElemCycleCount:      "OCSD_GEN_TRC_ELEM_CYCLE_COUNT",
	ocsd.GenElemEvent:           "OCSD_GEN_TRC_ELEM_EVENT",
	ocsd.GenElemSWTrace:         "OCSD_GEN_TRC_ELEM_SWTRACE",
	ocsd.GenElemSyncMarker:      "OCSD_GEN_TRC_ELEM_SYNC_MARKER",
	ocsd.GenElemMemTrans:        "OCSD_GEN_TRC_ELEM_MEMTRANS",
	ocsd.GenElemInstrumentation: "OCSD_GEN_TRC_ELEM_INSTRUMENTATION",
	ocsd.GenElemITMTrace:        "OCSD_GEN_TRC_ELEM_ITMTRACE",
	ocsd.GenElemCustom:          "OCSD_GEN_TRC_ELEM_CUSTOM",
}

func elemName(t ocsd.GenElemType) string {
	idx := int(t)
	if idx >= 0 && idx < len(elemNames) && elemNames[idx] != "" {
		return elemNames[idx]
	}
	return elemNames[ocsd.GenElemUnknown]
}
