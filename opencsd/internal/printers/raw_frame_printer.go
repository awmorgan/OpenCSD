package printers

import (
	"fmt"
	"io"
	"strings"

	"opencsd/internal/ocsd"
)

// RawFramePrinter translates the C++ RawFramePrinter class.
// It acts as a sink for raw trace dataframes, printing their content.
type RawFramePrinter struct {
	ItemPrinter
}

// NewRawFramePrinter creates a new printer for RawFrame elements.
func NewRawFramePrinter(writer io.Writer) *RawFramePrinter {
	return &RawFramePrinter{
		ItemPrinter: *NewItemPrinter(writer),
	}
}

// TraceRawFrameIn responds to the TrcRawFrameIn datapath interface.
func (p *RawFramePrinter) TraceRawFrameIn(op ocsd.DatapathOp, index ocsd.TrcIndex, frameElem ocsd.RawframeElem, data []byte, traceID uint8) ocsd.DatapathResp {
	if p.IsMuted() {
		return ocsd.RespCont
	}

	if op == ocsd.OpData { // only interested in actual frame data
		var sb strings.Builder

		sb.WriteString(fmt.Sprintf("Frame Data; Index%7d; ", index))

		switch frameElem {
		case ocsd.FrmPacked:
			sb.WriteString(fmt.Sprintf("%15s", "RAW_PACKED; "))
		case ocsd.FrmHsync:
			sb.WriteString(fmt.Sprintf("%15s", "HSYNC; "))
		case ocsd.FrmFsync:
			sb.WriteString(fmt.Sprintf("%15s", "FSYNC; "))
		case ocsd.FrmIDData:
			sb.WriteString(fmt.Sprintf("%10s", "ID_DATA["))
			if traceID == ocsd.BadCSSrcID {
				sb.WriteString("????")
			} else {
				sb.WriteString(fmt.Sprintf("0x%02x", traceID))
			}
			sb.WriteString("]; ")
		default:
			sb.WriteString(fmt.Sprintf("%15s", "UNKNOWN; "))
		}

		// Process byte data if available
		if len(data) > 0 {
			lineBytes := 0
			for i := range data {
				if lineBytes == 16 {
					sb.WriteString("\n")
					lineBytes = 0
				}
				sb.WriteString(fmt.Sprintf("%02x ", data[i]))
				lineBytes++
			}
		}
		sb.WriteString("\n")
		p.ItemPrintLine(sb.String())
	}

	return ocsd.RespCont
}
