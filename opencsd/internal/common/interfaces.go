package common

import "fmt"

// DataPathOp represents ocsd_datapath_op_t
// Directs the component on how to handle the incoming data.
type DataPathOp int

const (
	OpData  DataPathOp = 0 // Process the data provided
	OpEOT   DataPathOp = 1 // End of Trace - flush and finish
	OpFlush DataPathOp = 2 // Flush internal buffers
	OpReset DataPathOp = 3 // Reset state
)

// DataPathResp represents ocsd_datapath_resp_t
// The response from a component after processing data.
type DataPathResp int

const (
	RespCont      DataPathResp = 0 // Continue processing
	RespWait      DataPathResp = 1 // Pause processing (backpressure)
	RespFatal     DataPathResp = 2 // Fatal error, stop pipeline
	RespMarkedVal DataPathResp = 3 // (Internal marker, rarely used directly)
)

// IsCont returns true if the response indicates processing should continue.
func (r DataPathResp) IsCont() bool { return r == RespCont }

// IsFatal returns true if the response indicates a fatal error.
func (r DataPathResp) IsFatal() bool { return r >= RespFatal }

// TrcDataIn mimics ITrcDataIn.
// This is the primary interface for raw byte processing (e.g., File -> Tree, Tree -> PTM).
type TrcDataIn interface {
	// TraceDataIn pushes raw bytes into the component.
	// Returns the response, number of bytes processed, and potentially an error.
	TraceDataIn(op DataPathOp, index int64, data []byte) (DataPathResp, int, error)
}

// PacketProcessor defines a component that accepts raw data and outputs packets.
// (This creates a standard interface for PTM, ETMv4, etc.)
type PacketProcessor interface {
	TrcDataIn
	// GetPacketName returns the name of the protocol (e.g., "PTM", "ETMv4")
	GetPacketName() string
}

// GenElemIn mimics ITrcGenElemIn.
// This is the interface for the final stage: Decoder -> Sink (Printer/Analysis).
type GenElemIn interface {
	// TraceElemIn pushes a fully decoded generic element to the next stage.
	TraceElemIn(index int64, chanID uint8, elem *TraceElement) DataPathResp
}

// Error definitions
var (
	ErrFatal = fmt.Errorf("fatal processing error")
)
