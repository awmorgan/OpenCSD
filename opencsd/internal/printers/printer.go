package printers

import (
	"fmt"
	"io"
	"os"
	"strings"

	"opencsd/internal/common"
)

// PktPrinter mimics TrcGenericElementPrinter.
type PktPrinter struct {
	out io.Writer
}

func NewPktPrinter() *PktPrinter {
	return &PktPrinter{
		out: os.Stdout, // Default to stdout
	}
}

// SetOutput allows redirecting the printer output
func (p *PktPrinter) SetOutput(w io.Writer) {
	if w != nil {
		p.out = w
	}
}

func (p *PktPrinter) TraceElemIn(index int64, chanID uint8, elem *common.TraceElement) common.DataPathResp {
	// Print in the format similar to trc_pkt_lister
	// "Idx:<N>; ID:<id>; <Element String>"
	fmt.Fprintf(p.out, "Idx:%d; ID:%d; %s\n", index, chanID, elem.ToString())
	return common.RespCont
}

// PrintPacketRaw prints a raw packet line (hex bytes + packet description)
// Matches the C++ output used in the golden .ppl files.
func (p *PktPrinter) PrintPacketRaw(index int, chanID uint8, raw []byte, desc string) {
	var sb strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&sb, "0x%02x ", b)
	}
	fmt.Fprintf(p.out, "Idx:%d; ID:%d; [%s];\t%s\n", index, chanID, sb.String(), desc)
}
