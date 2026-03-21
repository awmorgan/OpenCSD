package common

import (
	"opencsd/internal/ocsd"
	"testing"
)

type dummyPkt struct{ val int }
type dummyPt struct{}
type dummyPc struct{}

type myTrcGenElemIn struct {
	lastIndex ocsd.TrcIndex
	lastID    uint8
}

func (m *myTrcGenElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	m.lastIndex = indexSOP
	m.lastID = trcChanID
	return ocsd.RespCont
}

func TestPktDecodeBase(t *testing.T) {
	pb := &PktDecodeBase[dummyPkt, dummyPc]{}
	pb.ConfigurePktDecodeBase("testDecode")

	elemIn := &myTrcGenElemIn{}
	pb.TraceElemOut.Attach(elemIn)
	pb.ConfigInitOK = true
	pb.SetNeedsMemAccess(false)
	pb.SetNeedsInstructionDecode(false)

	elem := ocsd.NewTraceElement()
	resp := pb.OutputTraceElement(123, elem)
	if resp != ocsd.RespCont || elemIn.lastIndex != 0 {
		t.Errorf("OutputTraceElement failed")
	}

	pb.SetNeedsMemAccess(true)
	if !pb.NeedsMemAccess() {
		t.Errorf("NeedsMemAccess failed")
	}
	pb.SetNeedsInstructionDecode(true)
	if !pb.NeedsInstructionDecode() {
		t.Errorf("NeedsInstructionDecode failed")
	}

	pb.OutputTraceElementIdx(123, 123, elem)
	if elemIn.lastIndex != 123 {
		t.Errorf("OutputTraceElementIdx failed")
	}

	var instr ocsd.InstrInfo
	pb.InstrDecodeCall(&instr)
	pb.AccessMemory(0x1000, 123, ocsd.MemSpaceAny, 4)
	pb.InvalidateMemAccCache(123)
}

type myPktDataIn struct{ lastOp ocsd.DatapathOp }

func (p *myPktDataIn) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *dummyPkt) ocsd.DatapathResp {
	p.lastOp = op
	return ocsd.RespWait
}

func TestPktProcBase(t *testing.T) {
	pb := &PktProcBase[dummyPkt, dummyPt, dummyPc]{}
	pb.ConfigurePktProcBase("testProc")

	outI := &myPktDataIn{}
	pb.PktOutI.Attach(outI)

	pb.ResetStats()
	pb.StatsAddTotalCount(100)
	pb.StatsInit()

	stats, errCode := pb.StatsBlock()
	if errCode != ocsd.OK || stats.ChannelTotal != 100 {
		t.Errorf("Stats failed")
	}

	pb.OutputDecodedPacket(0, &dummyPkt{})
	if outI.lastOp != ocsd.OpData {
		t.Errorf("OutputDecodedPacket should forward packet")
	}

	pb.OutputRawPacketToMonitor(0, &dummyPkt{}, []byte{1, 2})
	pb.IndexPacket(0, dummyPt{})
	pb.OutputOnAllInterfaces(0, &dummyPkt{}, dummyPt{}, []byte{1})
	pb.StatsAddUnsyncCount(1)
	pb.StatsAddBadSeqCount(1)
	pb.StatsAddBadHdrCount(1)
}
