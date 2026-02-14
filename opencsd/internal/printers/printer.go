package printers

import (
	"fmt"
	"opencsd/internal/common"
)

// PktPrinter mimics TrcGenericElementPrinter.
type PktPrinter struct{}

func NewPktPrinter() *PktPrinter {
	return &PktPrinter{}
}

func (p *PktPrinter) TraceElemIn(index int64, chanID uint8, elem *common.TraceElement) common.DataPathResp {
	// Print in the format similar to trc_pkt_lister
	// "Idx:<N>; ID:<id>; <Element String>"
	fmt.Printf("Idx:%d; ID:%x; %s\n", index, chanID, elem.ToString())
	return common.RespCont
}
