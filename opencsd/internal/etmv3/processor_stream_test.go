package etmv3

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestProcStreamComplete(t *testing.T) {
	newProc := func() *PktProc {
		config := &Config{}
		config.RegCtrl = ctrlCycleAcc | ctrlVmidEna | ctrlTsEna | ctrlDataVal | ctrlDataAddr | (2 << 14) // ctxtid=2
		config.RegCCER = ccerHasTs
		manager := NewDecoderManager()
		proc := manager.CreatePktProc(0, config).(*PktProc)
		proc.PktOutI.Attach(&noopPktSink{})
		proc.PktOutI.Attach(&noopPktSink{})
		return proc
	}

	t.Run("ControlAndContextPackets", func(t *testing.T) {
		proc := newProc()
		data := []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
			0x04, 0x01, // CycleCount
			0x70, 0x01, 0x22, 0x33, 0x44, 0x00, 0x01, 0xaa, 0xbb, // ISYNC Cycle
			0x08, 0x01, 0x22, 0x33, 0x44, 0x00, 0xaa, 0xbb, // ISYNC
			0x80,       // Atom P-Hdr Fmt
			0x01, 0x00, // Branch
			0x0C,       // Trigger
			0x3C, 0x11, // VMID
			0x42, 0x01, 0x02, // Timestamp
			0x76, // Exception Return
			0x66, // Reserved
		}
		processed, _ := proc.TraceDataIn(ocsd.OpData, 0, data)
		if processed == 0 {
			t.Fatalf("expected control/context stream to consume input bytes")
		}
	})

	t.Run("DataAndAddressPackets", func(t *testing.T) {
		proc := newProc()
		data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80} // ASYNC
		data = append(data, 0x50)                          // StoreFail
		data = append(data, 0x20)                          // OOO size0
		data = append(data, 0x24, 0x11)                    // OOO size1
		data = append(data, 0x28, 0x11, 0x22)              // OOO size2
		data = append(data, 0x2C, 0x11, 0x22, 0x33, 0x44)  // OOO size4
		data = append(data, 0x54)                          // OOO addr placeholder
		data = append(data, 0x74)                          // addr trace active
		data = append(data, 0x80, 0x00)                    // address bytes
		data = append(data, 0x5C)
		data = append(data, 0x02)             // normal size0
		data = append(data, 0x06, 0x11)       // normal size1
		data = append(data, 0x0A, 0x11, 0x22) // normal size2
		data = append(data, 0x22)             // normal size0 expect addr
		data = append(data, 0x80, 0x00)       // addr bytes
		processed, _ := proc.TraceDataIn(ocsd.OpData, 0, data)
		if processed == 0 {
			t.Fatalf("expected data/address stream to consume input bytes")
		}
	})

	t.Run("ExceptionBranchAndFlush", func(t *testing.T) {
		proc := newProc()
		data := []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
			0x01, 0x40, 0x00, // Branch with exception data
		}
		processed, _ := proc.TraceDataIn(ocsd.OpData, 0, data)
		if processed == 0 {
			t.Fatalf("expected exception stream to consume input bytes")
		}
		processed, _ = proc.TraceDataIn(ocsd.OpFlush, 0, nil)
		if processed != 0 {
			t.Fatalf("expected flush to report zero consumed bytes, got %d", processed)
		}
	})
}

func TestProcStreamBadTraceMode(t *testing.T) {
	config := &Config{}
	// No data trace flags set
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x20, // OOO Data
		0x50, // StoreFail
		0x54, // OOO Addr
		0x02, // Normal Data
		0x66, // Reserved
	}

	processed, _ := proc.TraceDataIn(ocsd.OpData, 0, data)
	if processed == 0 {
		t.Fatalf("expected processor to consume bytes in bad-trace-mode stream")
	}
}

func TestProcStreamMalformed(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	// Inject malformed packets (wrong size / early EOT)
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x06, // Normal Data size 1, but we EOT here
	}
	proc.TraceDataIn(ocsd.OpData, 0, data)
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(data)), nil)
}

func TestProcStreamComplexPackets(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc | (2 << 14) // ctxtid=2
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		// Context ID
		0x6e, 0x11, 0x22,
		// Cycle count multibyte
		0x04, 0x41, 0x42, 0x03,
		// ISync multi-LSiP
		0x08, 0x01, 0x22, 0x33, 0x44, 0x00, 0xaa, 0xbb,
	}

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcStreamPartPacket(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	// ASYNC
	_, resp := proc.TraceDataIn(ocsd.OpData, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80})
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response for sync sequence: %v", resp)
	}

	// ISYNC but split across chunks
	part1 := []byte{0x08, 0x01, 0x22}
	part2 := []byte{0x33, 0x44, 0x00, 0xaa, 0xbb}

	_, resp = proc.TraceDataIn(ocsd.OpData, 0, part1)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response for first part packet: %v", resp)
	}
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, part2)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response for second part packet: %v", resp)
	}
}

func TestProcStreamExceptionData(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80})

	// Exception Data (Branch header bit0=1)
	// byte0 = 0x41 (bit6=1 excep followed, bit7=0 no more addr)
	// byte1 = 0x80 (excep byte1: bit7=1 continue)
	// byte2 = 0x02 (excep byte2: bit7=0 end)
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x80, 0x02})

	// Add missing coverage branches
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x00}) // short exception
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x01})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x02})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x03})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x08})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x10})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x0B})

	// Exception Data (malformed)
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x41, 0x80})
	proc.TraceDataIn(ocsd.OpEOT, 0, nil)
}

func TestProcessorPartialPacketAndMalformedState(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)

	proc.currPacketData = []byte{1, 2, 3}
	proc.setBytesPartPkt(1, waitSync, PktASync)
	if !proc.bSendPartPkt || len(proc.partPktData) != 1 || proc.partPktData[0] != 1 {
		t.Fatalf("setBytesPartPkt did not preserve expected partial packet state")
	}
	if len(proc.currPacketData) != 2 || proc.currPacketData[0] != 2 || proc.currPacketData[1] != 3 {
		t.Fatalf("setBytesPartPkt did not consume expected bytes")
	}
	if proc.postPartPktState != waitSync || proc.postPartPktType != PktASync {
		t.Fatalf("setBytesPartPkt did not set post-partial state")
	}

	proc.throwMalformedPacketErr("test")
	if proc.processState != procErr {
		t.Fatalf("throwMalformedPacketErr should set process state to procErr")
	}
}

func TestProcStreamDataValues(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlDataAddr | ctrlDataVal | ctrlDataOnly

	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80})

	// Normal Data (0x02=size0) + Value + Address
	// format: header, addr bytes (if any), value bytes
	// 0x2A = 0010 1010 => size2 (+1 = 3 expected). wait, 0x2A & 0xD3 = 0x02.
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x2A, 0x80, 0x00, 0x11, 0x22, 0x33})

	// OOO Data with address
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x74, 0x80, 0x80, 0x00}) // Address placeholder
}

func TestProcStreamPartPacket2(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})

	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x81})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x82})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x03}) // end of branch addr
}

func TestProcStreamMalformedHeaders(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	proc.PktOutI.Attach(&noopPktSink{})
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80})

	// Malformed branch address (missing bytes)
	proc.TraceDataIn(ocsd.OpData, 0, []byte{0x81, 0x82})
	proc.TraceDataIn(ocsd.OpEOT, 0, nil)
}

type noopPktSink struct{}

func (n *noopPktSink) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	return ocsd.RespCont
}
