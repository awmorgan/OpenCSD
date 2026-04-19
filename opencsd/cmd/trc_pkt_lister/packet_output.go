package main

import (
	"fmt"
	"io"
	"opencsd/internal/dcdtree"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"sort"
)

type filteredGenElemPrinter struct {
	printer      *printers.GenericElementPrinter
	allSourceIDs bool
	validIDs     [256]bool
}

func (g *filteredGenElemPrinter) PrintElement(elem *ocsd.TraceElement) error {
	if elem == nil {
		return nil
	}
	if !g.allSourceIDs {
		if !g.validIDs[elem.TraceID] {
			return nil
		}
	}
	return g.printer.PrintElement(elem)
}

type genericRawPrinter struct {
	writer       io.Writer
	id           uint8
	showRawBytes bool
}

func (p *genericRawPrinter) SetMute(bool) {}

func (p *genericRawPrinter) MonitorRawData(indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if len(rawData) == 0 {
		return
	}

	formattedPkt := pkt.String()
	if formattedPkt == "" {
		return
	}

	if p.showRawBytes {
		fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
		for _, b := range rawData {
			fmt.Fprintf(p.writer, "0x%02x ", b)
		}
		fmt.Fprintf(p.writer, "];\t%s\n", formattedPkt)
	} else {
		fmt.Fprintf(p.writer, "Idx:%d; ID:%x;\t%s\n", indexSOP, p.id, formattedPkt)
	}
}

func (p *genericRawPrinter) MonitorEOT() {
	fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
}

func (p *genericRawPrinter) MonitorReset(indexSOP ocsd.TrcIndex) {}

func configurePacketOutput(
	out io.Writer,
	tree *dcdtree.DecodeTree,
	opts options,
) packetOutput {
	genPrinter := printers.NewGenericElementPrinter(out)
	genAdapter := &filteredGenElemPrinter{
		printer:      genPrinter,
		allSourceIDs: opts.allSourceIDs,
		validIDs:     makeIDSet(opts.idList),
	}

	printersAttached := 0
	if !opts.decodeOnly {
		printersAttached = attachPacketPrinters(out, tree, opts)
	}

	return packetOutput{
		genPrinter:       genPrinter,
		genAdapter:       genAdapter,
		printersAttached: printersAttached,
	}
}

func attachPacketPrinters(out io.Writer, tree *dcdtree.DecodeTree, opts options) int {
	attached := 0
	idFilter := makeIDSet(opts.idList)
	showRawBytes := opts.decode || opts.pktMon

	type rawMonitorSetter interface {
		SetPktRawMonitor(ocsd.PacketMonitor)
	}

	type elemRef struct {
		id   uint8
		elem *dcdtree.DecodeTreeElement
	}
	elems := make([]elemRef, 0)

	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		elems = append(elems, elemRef{id: csID, elem: elem})
	})
	sort.Slice(elems, func(i, j int) bool { return elems[i].id < elems[j].id })

	for _, ref := range elems {
		csID := ref.id
		elem := ref.elem

		if !opts.allSourceIDs && !idFilter[csID] {
			continue
		}

		protocolName := elem.DecoderTypeName
		mon := &genericRawPrinter{
			writer:       out,
			id:           csID,
			showRawBytes: showRawBytes,
		}

		if setter, ok := elem.DataIn.(rawMonitorSetter); ok {
			setter.SetPktRawMonitor(mon)
			fmt.Fprintf(out, "Trace Packet Lister : Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
			attached++
		} else {
			fmt.Fprintf(out, "Trace Packet Lister : Failed to attach Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
		}
	}
	return attached
}

func makeIDSet(ids []uint8) [256]bool {
	var validIDs [256]bool
	for _, id := range ids {
		validIDs[id] = true
	}
	return validIDs
}
