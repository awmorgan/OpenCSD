package printers

import (
	"fmt"
	"io"
	"strings"

	"opencsd/internal/ocsd"
)

const rawFrameBytesPerLine = 16

// RawFramePrinter translates the C++ RawFramePrinter class.
// It acts as a sink for raw trace dataframes, printing their content.
type RawFramePrinter struct {
	ItemPrinter
}

// NewRawFramePrinter creates a new printer for RawFrame elements.
func NewRawFramePrinter(writer io.Writer) *RawFramePrinter {
	return &RawFramePrinter{ItemPrinter: *NewItemPrinter(writer)}
}

// WriteRawFrame responds to raw frame data callbacks.
func (p *RawFramePrinter) WriteRawFrame(index ocsd.TrcIndex, frameElem ocsd.RawframeElem, data []byte, traceID uint8) error {
	if p.IsMuted() {
		return nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Frame Data; Index%7d; %s", index, rawFrameElemLabel(frameElem, traceID))
	writeRawFrameBytes(&sb, data)
	sb.WriteByte('\n')

	p.ItemPrintLine(sb.String())
	return nil
}

func rawFrameElemLabel(frameElem ocsd.RawframeElem, traceID uint8) string {
	switch frameElem {
	case ocsd.FrmPacked:
		return fmt.Sprintf("%15s", "RAW_PACKED; ")
	case ocsd.FrmHsync:
		return fmt.Sprintf("%15s", "HSYNC; ")
	case ocsd.FrmFsync:
		return fmt.Sprintf("%15s", "FSYNC; ")
	case ocsd.FrmIDData:
		return rawFrameIDLabel(traceID)
	default:
		return fmt.Sprintf("%15s", "UNKNOWN; ")
	}
}

func rawFrameIDLabel(traceID uint8) string {
	id := "????"
	if traceID != ocsd.BadCSSrcID {
		id = fmt.Sprintf("0x%02x", traceID)
	}
	return fmt.Sprintf("%10s%s]; ", "ID_DATA[", id)
}

func writeRawFrameBytes(sb *strings.Builder, data []byte) {
	for i, b := range data {
		if i > 0 && i%rawFrameBytesPerLine == 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(sb, "%02x ", b)
	}
}

func (p *RawFramePrinter) FlushRawFrames() error {
	return nil
}

func (p *RawFramePrinter) ResetRawFrames() error {
	return nil
}

func (p *RawFramePrinter) CloseRawFrames() error {
	return nil
}
