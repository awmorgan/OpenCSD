package printers

import "io"

// ItemPrinter translates the C++ ItemPrinter class.
type ItemPrinter struct {
	writer      io.Writer
	testWaits   int
	muted       bool
	idPrintMute bool
}

// NewItemPrinter constructs an ItemPrinter using the given io.Writer.
func NewItemPrinter(writer io.Writer) *ItemPrinter {
	return &ItemPrinter{writer: writer}
}

// ItemPrintLine writes the given message to the writer.
func (p *ItemPrinter) ItemPrintLine(msg string) {
	if p.writer == nil {
		return
	}
	_, _ = io.WriteString(p.writer, msg)
}

// SetTestWaits configures the printer to simulate returning wait signals for a specified number of elements.
func (p *ItemPrinter) SetTestWaits(numWaits int) { p.testWaits = numWaits }

// TestWaits gets the remaining number of test wait signals to return.
func (p *ItemPrinter) TestWaits() int { return p.testWaits }

// DecTestWaits decrements the number of test wait signals remaining.
func (p *ItemPrinter) DecTestWaits() { p.testWaits-- }

// SetMute sets the trace printer to mute (avoids output).
func (p *ItemPrinter) SetMute(mute bool) { p.muted = mute }

// IsMuted returns true if the trace printer is muted.
func (p *ItemPrinter) IsMuted() bool { return p.muted }

// MuteIDPrint mutes or unmutes printing the trace ID in the output lines.
func (p *ItemPrinter) MuteIDPrint(mute bool) { p.idPrintMute = mute }

// IDPrintMuted returns whether trace ID printing is muted.
func (p *ItemPrinter) IDPrintMuted() bool { return p.idPrintMute }
