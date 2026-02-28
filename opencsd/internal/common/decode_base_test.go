package common

import (
	"testing"

	"opencsd/internal/ocsd"
)

type dummyPkt struct {
	val int
}

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
	pb.InitPktDecodeBase("testDecode")

	var pktProcessed bool
	pb.FnProcessPacket = func() ocsd.DatapathResp {
		pktProcessed = true
		return ocsd.RespCont
	}
	pb.FnGetTraceID = func() uint8 { return 42 }

	// Test uninit
	resp := pb.PacketDataIn(ocsd.OpData, 0, &dummyPkt{1})
	if resp != ocsd.RespFatalNotInit {
		t.Errorf("Expected NotInit, got %v", resp)
	}

	elemIn := &myTrcGenElemIn{}
	pb.TraceElemOut.Attach(elemIn)
	pb.configInitOK = true
	pb.SetUsesMemAccess(false)
	pb.SetUsesIDecode(false)

	resp = pb.PacketDataIn(ocsd.OpData, 10, &dummyPkt{2})
	if resp != ocsd.RespCont || !pktProcessed {
		t.Errorf("Packet not processed correctly")
	}

	elem := ocsd.NewTraceElement()
	resp = pb.OutputTraceElement(elem)
	if resp != ocsd.RespCont || elemIn.lastIndex != 10 {
		t.Errorf("OutputTraceElement failed")
	}

	err := pb.SetProtocolConfig(nil)
	if err != ocsd.ErrInvalidParamVal {
		t.Errorf("Expected invalid param for nil config")
	}

	pb.FnOnEOT = func() ocsd.DatapathResp { return ocsd.RespWarnCont }
	resp = pb.PacketDataIn(ocsd.OpEOT, 0, nil)
	if resp != ocsd.RespWarnCont {
		t.Errorf("EOT propagation failed")
	}

	// Test 0% coverage functions
	pb.SetUsesMemAccess(true)
	if !pb.GetUsesMemAccess() {
		t.Errorf("GetUsesMemAccess failed")
	}
	pb.SetUsesIDecode(true)
	if !pb.GetUsesIDecode() {
		t.Errorf("GetUsesIDecode failed")
	}

	pb.OutputTraceElementIdx(123, elem)
	if elemIn.lastIndex != 123 {
		t.Errorf("OutputTraceElementIdx failed")
	}

	var instr ocsd.InstrInfo
	pb.InstrDecodeCall(&instr)
	pb.AccessMemory(0x1000, ocsd.MemSpaceAny, 4)
	pb.InvalidateMemAccCache()
}

type myPktDataIn struct {
	lastOp ocsd.DatapathOp
}

func (p *myPktDataIn) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *dummyPkt) ocsd.DatapathResp {
	p.lastOp = op
	return ocsd.RespWait
}

func TestPktProcBase(t *testing.T) {
	pb := &PktProcBase[dummyPkt, dummyPt, dummyPc]{}
	pb.InitPktProcBase("testProc")

	var dataProcessed bool
	pb.FnProcessData = func(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
		dataProcessed = true
		return uint32(len(dataBlock)), ocsd.RespCont
	}

	_, resp := pb.TraceDataIn(ocsd.OpData, 0, []byte{1, 2, 3})
	if resp != ocsd.RespCont || !dataProcessed {
		t.Errorf("TraceDataIn data processing failed")
	}

	outI := &myPktDataIn{}
	pb.PktOutI.Attach(outI)

	_, resp = pb.TraceDataIn(ocsd.OpEOT, 0, nil)
	if outI.lastOp != ocsd.OpEOT {
		t.Errorf("EOT not passed downstream")
	}

	_, resp = pb.TraceDataIn(ocsd.OpReset, 0, nil)
	if outI.lastOp != ocsd.OpReset {
		t.Errorf("Reset not passed downstream")
	}

	pb.SetProtocolConfig(&dummyPc{})
	if !pb.CheckInit() {
		t.Errorf("PktProc should be initialized")
	}

	pb.ResetStats()
	pb.StatsAddTotalCount(100)
	pb.StatsInit()

	stats, err := pb.GetStatsBlock()
	if err != ocsd.OK || stats.ChannelTotal != 100 {
		t.Errorf("Stats failed")
	}

	pb.FnIsBadPacket = func() bool { return true }
	pb.SetComponentOpMode(ocsd.OpflgPktprocNofwdBadPkts)

	outI.lastOp = ocsd.OpData // reset
	pb.OutputDecodedPacket(0, &dummyPkt{})
	if outI.lastOp != ocsd.OpData {
		t.Errorf("OutputDecodedPacket should not forward bad packet")
	}

	// Test 0% coverage functions
	pb.Flush()
	pb.OutputRawPacketToMonitor(0, &dummyPkt{}, []byte{1, 2})
	pb.IndexPacket(0, dummyPt{})
	pb.OutputOnAllInterfaces(0, &dummyPkt{}, dummyPt{}, []byte{1})
	pb.StatsAddUnsyncCount(1)
	pb.StatsAddBadSeqCount(1)
	pb.StatsAddBadHdrCount(1)
}
