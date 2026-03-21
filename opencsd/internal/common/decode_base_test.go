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

type testDecodeStrategy struct {
	pktProcessed *bool
}

func (s *testDecodeStrategy) ProcessPacket() ocsd.DatapathResp {
	*s.pktProcessed = true
	return ocsd.RespCont
}

func (s *testDecodeStrategy) OnEOT() ocsd.DatapathResp { return ocsd.RespWarnCont }
func (s *testDecodeStrategy) TraceID() uint8        { return 42 }

func (m *myTrcGenElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	m.lastIndex = indexSOP
	m.lastID = trcChanID
	return ocsd.RespCont
}

func TestPktDecodeBase(t *testing.T) {
	pb := &PktDecodeBase[dummyPkt, dummyPc]{}
	pb.InitPktDecodeBase("testDecode")

	var pktProcessed bool
	pb.SetStrategy(&testDecodeStrategy{pktProcessed: &pktProcessed})

	// Test uninit
	resp := pb.PacketDataIn(ocsd.OpData, 0, &dummyPkt{1})
	if resp != ocsd.RespFatalNotInit {
		t.Errorf("Expected NotInit, got %v", resp)
	}

	elemIn := &myTrcGenElemIn{}
	pb.TraceElemOut.Attach(elemIn)
	pb.ConfigInitOK = true
	pb.SetUsesMemAccess(false)
	pb.SetUsesIDecode(false)

	resp = pb.PacketDataIn(ocsd.OpData, 10, &dummyPkt{2})
	if resp != ocsd.RespCont || !pktProcessed {
		t.Errorf("Packet not processed correctly")
	}

	pb.TraceElemOut.DetachAll()
	resp = pb.PacketDataIn(ocsd.OpData, 11, &dummyPkt{3})
	if resp != ocsd.RespFatalNotInit {
		t.Errorf("Expected NotInit after detaching trace output, got %v", resp)
	}
	pb.TraceElemOut.Attach(elemIn)

	elem := ocsd.NewTraceElement()
	resp = pb.OutputTraceElement(123, elem)
	if resp != ocsd.RespCont || elemIn.lastIndex != 10 {
		t.Errorf("OutputTraceElement failed")
	}

	err := pb.SetProtocolConfig(nil)
	if err != ocsd.ErrInvalidParamVal {
		t.Errorf("Expected invalid param for nil config")
	}

	resp = pb.PacketDataIn(ocsd.OpEOT, 0, nil)
	if resp != ocsd.RespWarnCont {
		t.Errorf("EOT propagation failed")
	}

	// Test 0% coverage functions
	pb.SetUsesMemAccess(true)
	if !pb.UsesMemAccess() {
		t.Errorf("UsesMemAccess failed")
	}
	pb.SetUsesIDecode(true)
	if !pb.UsesIDecode() {
		t.Errorf("UsesIDecode failed")
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

type myPktDataIn struct {
	lastOp ocsd.DatapathOp
}

type testProcStrategy struct {
	dataProcessed *bool
	badPacket     bool
}

func (s *testProcStrategy) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	*s.dataProcessed = true
	return uint32(len(dataBlock)), ocsd.RespCont, nil
}

func (s *testProcStrategy) IsBadPacket() bool { return s.badPacket }

func (p *myPktDataIn) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *dummyPkt) ocsd.DatapathResp {
	p.lastOp = op
	return ocsd.RespWait
}

func TestPktProcBase(t *testing.T) {
	pb := &PktProcBase[dummyPkt, dummyPt, dummyPc]{}
	pb.InitPktProcBase("testProc")

	var dataProcessed bool
	strategy := &testProcStrategy{dataProcessed: &dataProcessed}
	pb.SetStrategy(strategy)

	_, resp, err := pb.TraceDataIn(ocsd.OpData, 0, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp != ocsd.RespCont || !dataProcessed {
		t.Errorf("TraceDataIn data processing failed")
	}

	outI := &myPktDataIn{}
	pb.PktOutI.Attach(outI)

	_, resp, err = pb.TraceDataIn(ocsd.OpEOT, 0, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if outI.lastOp != ocsd.OpEOT {
		t.Errorf("EOT not passed downstream")
	}

	_, resp, err = pb.TraceDataIn(ocsd.OpReset, 0, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if outI.lastOp != ocsd.OpReset {
		t.Errorf("Reset not passed downstream")
	}

	pb.SetProtocolConfig(&dummyPc{})
	if pb.Config == nil {
		t.Errorf("PktProc should retain protocol config")
	}

	pb.ResetStats()
	pb.StatsAddTotalCount(100)
	pb.StatsInit()

	stats, errCode := pb.StatsBlock()
	if errCode != ocsd.OK || stats.ChannelTotal != 100 {
		t.Errorf("Stats failed")
	}

	strategy.badPacket = true
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
