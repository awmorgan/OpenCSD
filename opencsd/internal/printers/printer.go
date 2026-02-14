package printers

import (
	"fmt"
	"io"
	"os"

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
	fmt.Fprintf(p.out, "Idx:%d; ID:%x; %s\n", index, chanID, elem.ToString())
	return common.RespCont
}
