package etmv4

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type ProcessState int

const (
	ProcHdr ProcessState = iota
	ProcData
	SendPkt
	SendUnsynced
	ProcErr
)

// TInfoSect are flags to indicate processing progress for these sections is complete.
type TInfoSect uint8

const (
	TInfoInfoSect TInfoSect = 0x01
	TInfoKeySect  TInfoSect = 0x02
	TInfoSpecSect TInfoSect = 0x04
	TInfoCyctSect TInfoSect = 0x08
	TInfoWndwSect TInfoSect = 0x10
	TInfoCtrl     TInfoSect = 0x20
	TInfoAllSect  TInfoSect = 0x1F
	TInfoAll      TInfoSect = 0x3F
)

type TInfoPktProg struct {
	SectFlags uint8
	CtrlBytes uint8
}

// Processor parses byte streams for ETMv4 packets.
// Converted from TrcPktProcEtmV4I
type Processor struct {
	config Config

	// interfaces
	callbacks interfaces.PktDataIn[*TracePacket]

	processState ProcessState

	// packet data
	currPacketData   []byte
	currPktIdx       int
	currPacket       *TracePacket
	packetIndex      ocsd.TrcIndex
	blockIndex       ocsd.TrcIndex
	updateOnUnsyncPktIdx ocsd.TrcIndex

	// syncing
	isSync             bool
	firstTraceInfo     bool
	sentNotsyncPacket  bool
	dumpUnsyncedBytes  uint

	isInit bool // initialized

	// internal state
	tinfoSections TInfoPktProg

	// address and context packets
	addrBytes     int
	addrIS        uint8
	bAddr64bit    bool
	vmidBytes     int
	ctxtidBytes   int
	bCtxtInfoDone bool
	addrDone      bool

	// timestamp
	ccountDone bool // done or not needed
	tsDone     bool
	tsBytes    int

	// exception
	excepSize int
	excepDone bool

	// cycles
	ccountBytes int

	// context
	contextDone bool

	// cond inst / res
	condInstrDone bool
	condResDone   bool

	// Q packet
	qDone      bool
	hasAddr    bool
	hasCount   bool
	countBytes int

	// ETE Extended
	eteIteDone bool
}

// Ensure the struct satisfies PktDataInCB
var _ interfaces.TrcDataIn = (*Processor)(nil)

func NewProcessor(config *Config) *Processor {
	return &Processor{
		config:           *config,
		processState:     ProcHdr,
		currPacket:       &TracePacket{},
		tinfoSections:    TInfoPktProg{},
	}
}

// SetPktOutCB attach the packet processor output.
func (p *Processor) SetPktOutCB(cb interfaces.PktDataIn[*TracePacket]) {
	p.callbacks = cb
}

func (p *Processor) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
	if p.callbacks == nil {
		return 0, ocsd.RespFatalNotInit
	}

	numBytesProcessed := uint32(0)
	resp := ocsd.RespCont
	dataBlockSize := uint32(len(dataBlock))

	for numBytesProcessed < dataBlockSize && resp == ocsd.RespCont {
		switch p.processState {
		case ProcHdr:
			panic("Not yet implemented")
		case ProcData:
			panic("Not yet implemented")
		case SendPkt:
			panic("Not yet implemented")
		case SendUnsynced:
			panic("Not yet implemented")
		case ProcErr:
			panic("Not yet implemented")
		}
	}

	return numBytesProcessed, resp
}

func (p *Processor) OnEOT() ocsd.DatapathResp {
	panic("Not yet implemented")
}

func (p *Processor) OnReset() ocsd.DatapathResp {
	panic("Not yet implemented")
}

func (p *Processor) OnFlush() ocsd.DatapathResp {
	panic("Not yet implemented")
}

func (p *Processor) OnWait() ocsd.DatapathResp {
	panic("Not yet implemented")
}