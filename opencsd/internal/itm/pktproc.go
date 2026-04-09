package itm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"

	"opencsd/internal/ocsd"
)

type processState int

const (
	procWaitSync processState = iota
	procHdr
	procData
	procSendPkt
)

type packetDecodeState int

const (
	decodeNone packetDecodeState = iota
	decodeData
	decodeAsync
	decodeLocalTS
	decodeExtension
	decodeGlobalTS1
	decodeGlobalTS2
)

type procStateFn func(ocsd.TrcIndex) (error, bool)

var errDecodeNotImplemented = errors.New("decodeNextPacket: packet type not implemented")

type packetEvent struct {
	index       ocsd.TrcIndex
	pkt         Packet
	data        []byte
	emitRaw     bool
	emitDecoded bool
}

var itmPacketDataPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64)
		return &b
	},
}

// PktProc converts incoming byte stream into ITM packets
type PktProc struct {
	Name            string
	Stats           ocsd.DecodeStats
	statsInit       bool
	Config          *Config
	pktOut          ocsd.PacketProcessor[Packet]
	PktRawMonI      ocsd.PacketMonitor
	errBadPkts      bool
	unsyncOnBadPkts bool

	procState processState

	currPacket  Packet
	streamSync  bool
	dataIn      []byte
	dataInSize  uint32
	dataInUsed  uint32
	blockReader *bytes.Reader
	dataReader  *bufio.Reader
	packetIndex ocsd.TrcIndex

	headerByte        uint8
	packetData        []uint8
	packetDataRef     *[]byte
	sentNotSyncPacket bool
	syncStart         bool
	dumpUnsyncedBytes int
	pendingPackets    []packetEvent
	collectPackets    bool

	decodeState packetDecodeState
}

func (p *PktProc) ApplyFlags(flags uint32) error {
	if (flags & ocsd.OpflgPktprocErrBadPkts) != 0 {
		p.errBadPkts = true
	}
	if (flags & ocsd.OpflgPktprocUnsyncOnBadPkts) != 0 {
		p.unsyncOnBadPkts = true
	}
	return nil
}

// NewPktProc creates a new ITM packet processor.
func NewPktProc(cfg *Config) *PktProc {
	instID := 0
	if cfg != nil {
		instID = int(cfg.TraceID())
	}
	p := &PktProc{
		Name: fmt.Sprintf("PKTP_ITM_%d", instID),
	}
	p.packetDataRef = itmGetPacketBufRef()
	p.packetData = (*p.packetDataRef)[:0]
	p.ResetStats()
	p.resetProcessorState()
	if cfg != nil {
		_ = p.SetProtocolConfig(cfg)
	}
	return p
}

// SetPktOut attaches the downstream packet decoder.
func (p *PktProc) SetPktOut(out ocsd.PacketProcessor[Packet]) { p.pktOut = out }

// PktOut returns the downstream packet decoder.
func (p *PktProc) PktOut() ocsd.PacketProcessor[Packet] { return p.pktOut }

// SetPktRawMonitor attaches a raw packet monitor.
func (p *PktProc) SetPktRawMonitor(mon ocsd.PacketMonitor) { p.PktRawMonI = mon }

// HasRawMon reports whether a raw packet monitor is attached.
func (p *PktProc) HasRawMon() bool { return p.PktRawMonI != nil }

// StatsBlock returns the decode statistics, or ErrNotInit if not initialized.
func (p *PktProc) StatsBlock() (*ocsd.DecodeStats, error) {
	if !p.statsInit {
		return &p.Stats, ocsd.ErrNotInit
	}
	return &p.Stats, nil
}

// StatsInit marks the statistics block as initialized.
func (p *PktProc) StatsInit() { p.statsInit = true }

// ResetStats zeroes all decode statistics fields.
func (p *PktProc) ResetStats() {
	p.Stats.Version = ocsd.VerNum
	p.Stats.Revision = ocsd.StatsRevision
	p.Stats.ChannelTotal = 0
	p.Stats.ChannelUnsynced = 0
	p.Stats.BadHeaderErrs = 0
	p.Stats.BadSequenceErrs = 0
	p.Stats.Demux.FrameBytes = 0
	p.Stats.Demux.NoIDBytes = 0
	p.Stats.Demux.ValidIDBytes = 0
}

// StatsAddTotalCount adds to the total channel bytes counter.
func (p *PktProc) StatsAddTotalCount(count uint64) { p.Stats.ChannelTotal += count }

// StatsAddUnsyncCount adds to the unsynced channel bytes counter.
func (p *PktProc) StatsAddUnsyncCount(count uint64) { p.Stats.ChannelUnsynced += count }

// StatsAddBadSeqCount adds to the bad-sequence-error counter.
func (p *PktProc) StatsAddBadSeqCount(count uint32) { p.Stats.BadSequenceErrs += count }

// StatsAddBadHdrCount adds to the bad-header-error counter.
func (p *PktProc) StatsAddBadHdrCount(count uint32) { p.Stats.BadHeaderErrs += count }

func (p *PktProc) outputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *Packet) error {
	if p.collectPackets {
		p.pendingPackets = append(p.pendingPackets, packetEvent{index: indexSOP, pkt: *pkt, emitDecoded: true})
		return nil
	}
	if p.pktOut != nil {
		return p.pktOut.TracePacketData(indexSOP, pkt)
	}
	return nil
}

func (p *PktProc) outputRawPacketToMonitor(indexSOP ocsd.TrcIndex, pkt *Packet, pData []byte) {
	if p.collectPackets {
		dataCopy := append([]byte(nil), pData...)
		p.pendingPackets = append(p.pendingPackets, packetEvent{index: indexSOP, pkt: *pkt, data: dataCopy, emitRaw: true})
		return
	}
	if p.PktRawMonI != nil && len(pData) > 0 {
		p.PktRawMonI.MonitorRawData(indexSOP, pkt, pData)
	}
}

func (p *PktProc) outputOnAllInterfaces(indexSOP ocsd.TrcIndex, pkt *Packet, pktData []byte) error {
	if p.collectPackets {
		dataCopy := append([]byte(nil), pktData...)
		p.pendingPackets = append(p.pendingPackets, packetEvent{index: indexSOP, pkt: *pkt, data: dataCopy, emitRaw: len(pktData) > 0, emitDecoded: true})
		return nil
	}
	if len(pktData) > 0 {
		p.outputRawPacketToMonitor(indexSOP, pkt, pktData)
	}
	return p.outputDecodedPacket(indexSOP, pkt)
}

// NextPacket returns the next queued packet event for pull-style consumption.
func (p *PktProc) NextPacket() (packetEvent, error) {
	if len(p.pendingPackets) == 0 {
		return packetEvent{}, io.EOF
	}
	e := p.pendingPackets[0]
	p.pendingPackets = p.pendingPackets[1:]
	return e, nil
}

func (p *PktProc) putBackPacket(e packetEvent) {
	p.pendingPackets = append([]packetEvent{e}, p.pendingPackets...)
}

// TraceData is the explicit data-path entrypoint used by split interfaces.
func (p *PktProc) TraceData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	if len(dataBlock) == 0 {
		return 0, fmt.Errorf("%w: packet processor: zero length data block", ocsd.ErrInvalidParamVal)
	}
	p.collectPackets = true
	processed, err := p.ProcessData(index, dataBlock)
	p.collectPackets = false
	if err != nil && !errors.Is(err, ocsd.ErrWait) {
		return processed, err
	}
	for {
		e, nextErr := p.NextPacket()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return processed, nextErr
		}
		if e.emitRaw && len(e.data) > 0 {
			p.outputRawPacketToMonitor(e.index, &e.pkt, e.data)
		}
		if e.emitDecoded {
			if outErr := p.outputDecodedPacket(e.index, &e.pkt); outErr != nil {
				if errors.Is(outErr, ocsd.ErrWait) {
					p.putBackPacket(e)
				}
				return processed, outErr
			}
		}
	}
	return processed, nil
}

// TraceDataEOT handles end-of-trace control.
func (p *PktProc) TraceDataEOT() error {
	if err := p.OnEOT(); err != nil {
		return err
	}
	if p.pktOut != nil {
		if err := p.pktOut.TracePacketEOT(); err != nil && !errors.Is(err, ocsd.ErrWait) {
			return err
		}
	}
	if rawMon := p.PktRawMonI; rawMon != nil {
		rawMon.MonitorEOT()
	}
	return nil
}

// TraceDataFlush handles flush control.
func (p *PktProc) TraceDataFlush() error {
	if p.pktOut != nil {
		if err := p.pktOut.TracePacketFlush(); err != nil && !errors.Is(err, ocsd.ErrWait) {
			return err
		}
	}
	return nil
}

// TraceDataReset handles reset control.
func (p *PktProc) TraceDataReset(index ocsd.TrcIndex) error {
	if p.pktOut != nil {
		if err := p.pktOut.TracePacketReset(index); err != nil && !errors.Is(err, ocsd.ErrWait) {
			return err
		}
	}
	p.OnReset()
	if rawMon := p.PktRawMonI; rawMon != nil {
		rawMon.MonitorReset(index)
	}
	return nil
}

func (p *PktProc) SetProtocolConfig(config *Config) error {
	if config != nil {
		p.Config = config
		return nil
	}
	return ocsd.ErrInvalidParamVal
}

func (p *PktProc) resetProcessorState() {
	p.setProcUnsynced()
	p.resetNextPacket()
	p.sentNotSyncPacket = false
	p.syncStart = false
	p.dumpUnsyncedBytes = 0
	p.pendingPackets = p.pendingPackets[:0]
	p.collectPackets = false
}

func (p *PktProc) resetNextPacket() {
	if p.packetData == nil {
		p.packetDataRef = itmGetPacketBufRef()
		p.packetData = (*p.packetDataRef)[:0]
	}
	p.packetData = p.packetData[:0] // clear
	p.currPacket.Reset()
	p.decodeState = decodeNone
}

func (p *PktProc) setProcUnsynced() {
	p.procState = procWaitSync
	p.streamSync = false
}

func (p *PktProc) dataToProcess() bool {
	if p.procState == procSendPkt {
		return true
	}
	return p.dataReader != nil && (p.dataReader.Buffered() > 0 || (p.blockReader != nil && p.blockReader.Len() > 0))
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	var err error
	p.dataIn = dataBlock
	p.dataInSize = uint32(len(dataBlock))
	p.dataInUsed = 0
	p.blockReader = bytes.NewReader(dataBlock)
	p.dataReader = bufio.NewReaderSize(p.blockReader, 4096)

	for p.dataToProcess() && err == nil {
		loopErr, handled := p.processStateLoop(index)
		if handled {
			err = loopErr
		}
	}

	return p.dataInUsed, err
}

func (p *PktProc) processStateLoop(index ocsd.TrcIndex) (err error, handled bool) {
	fn := p.currentProcStateFn()
	if fn == nil {
		return nil, false
	}
	return fn(index)
}

func (p *PktProc) currentProcStateFn() procStateFn {
	switch p.procState {
	case procWaitSync:
		return p.stateWaitSync
	case procHdr:
		return p.stateHdr
	case procData:
		return p.stateData
	case procSendPkt:
		return p.stateSendPkt
	default:
		return nil
	}
}

func (p *PktProc) stateWaitSync(index ocsd.TrcIndex) (error, bool) {
	err := p.waitForSync(index)
	return err, true
}

func (p *PktProc) stateHdr(index ocsd.TrcIndex) (error, bool) {
	p.packetIndex = index + ocsd.TrcIndex(p.dataInUsed)

	if p.streamSync {
		pkt, consumed, err := decodeNextPacket(p.dataIn, int(p.dataInUsed))
		switch {
		case err == nil:
			for range consumed {
				if _, ok := p.readByte(); !ok {
					return io.ErrUnexpectedEOF, true
				}
			}
			if pkt.Type == PktTSGlobal1 && consumed == 5 && len(p.packetData) >= 5 {
				// Keep compatibility with legacy decode path, which masks src bits in the
				// final continuation byte before raw packet monitoring/output.
				p.packetData[4] &= 0x1F
			}
			p.currPacket = pkt
			p.procState = procSendPkt
			return p.stateSendPkt(index)
		case errors.Is(err, errDecodeNotImplemented),
			errors.Is(err, ocsd.ErrBadPacketSeq),
			errors.Is(err, ocsd.ErrInvalidPcktHdr):
			// Fall back to the legacy state machine while migration is in progress.
			// The legacy path owns byte consumption for error cases; handling them here
			// would retry the same header indefinitely when the stateless decoder fails
			// before consuming input.
		default:
			return err, true
		}
	}
	if err := p.ProcessHdr(); err != nil {
		if loopErr, errHandled := p.handleProcError(err); errHandled {
			return loopErr, true
		}
	}
	if !p.streamSync {
		p.procState = procWaitSync
		return p.stateWaitSync(index)
	}
	if p.procState == procSendPkt {
		return p.stateSendPkt(index)
	}
	return p.stateData(index)
}

func (p *PktProc) stateData(index ocsd.TrcIndex) (error, bool) {
	err := p.runDataDecodeState()
	if loopErr, errHandled := p.handleProcError(err); errHandled {
		return loopErr, true
	}
	if p.procState == procSendPkt {
		return p.stateSendPkt(index)
	}
	return nil, false
}

func (p *PktProc) stateSendPkt(_ ocsd.TrcIndex) (error, bool) {
	err := p.outputPacket()
	return err, true
}

func (p *PktProc) handleProcError(err error) (outErr error, handled bool) {
	if err == nil {
		return nil, false
	}

	if (errors.Is(err, ocsd.ErrBadPacketSeq) || errors.Is(err, ocsd.ErrInvalidPcktHdr)) &&
		!p.errBadPkts {
		outErr = p.outputPacket()
		if p.unsyncOnBadPkts {
			p.procState = procWaitSync
		}
		if outErr != nil {
			return outErr, true
		}
		return nil, true
	}
	return err, true
}

func (p *PktProc) OnEOT() error {
	if p.procState == procData {
		p.currPacket.Type = PktIncompleteEOT
		return p.outputPacket()
	}
	return nil
}

func (p *PktProc) OnReset() {
	p.resetProcessorState()
}

func (p *PktProc) OnFlush() error {
	return nil
}

func (p *PktProc) IsBadPacket() bool {
	return p.currPacket.IsBadPacket()
}

func (p *PktProc) outputPacket() error {
	pktData := p.packetData
	err := p.outputOnAllInterfaces(p.packetIndex, &p.currPacket, pktData)
	itmPutPacketBufRef(p.packetDataRef, pktData)
	p.packetDataRef = itmGetPacketBufRef()
	p.packetData = (*p.packetDataRef)[:0]
	p.resetNextPacket()
	if p.streamSync {
		p.procState = procHdr
	} else {
		p.procState = procWaitSync
	}
	return err
}

// setBadSequenceError records a bad-sequence error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setBadSequenceError(msg string) error {
	p.currPacket.Type = PktBadSequence
	return fmt.Errorf("%w: %s", ocsd.ErrBadPacketSeq, msg)
}

// setReservedHdrError records a reserved-header error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setReservedHdrError(msg string) error {
	p.currPacket.Type = PktReserved
	return fmt.Errorf("%w: %s", ocsd.ErrInvalidPcktHdr, msg)
}

func (p *PktProc) savePacketByte(val byte) {
	p.packetData = append(p.packetData, val)
}

func (p *PktProc) readByte() (byte, bool) {
	if p.dataReader != nil {
		b, err := p.dataReader.ReadByte()
		if err == nil {
			p.refreshDataUsed()
			p.savePacketByte(b)
			return b, true
		}
	}
	return 0, false
}

func (p *PktProc) refreshDataUsed() {
	if p.blockReader == nil || p.dataReader == nil {
		return
	}
	remaining := p.blockReader.Len() + p.dataReader.Buffered()
	p.dataInUsed = p.dataInSize - uint32(remaining)
}

func (p *PktProc) ProcessHdr() error {
	b, ok := p.readByte()
	if !ok {
		return nil
	}
	p.headerByte = b

	if (b & 0x03) != 0x00 { // Stimulus packets
		if (b & 0x4) != 0 {
			p.currPacket.Type = PktDWT
		} else {
			p.currPacket.Type = PktSWIT
		}
		p.decodeState = decodeData
		p.procState = procData
	} else if (b & 0x0F) == 0x00 {
		switch b & 0xF0 {
		case 0x00:
			p.currPacket.Type = PktAsync
			p.decodeState = decodeAsync
			p.procState = procData
		case 0x70:
			p.currPacket.Type = PktOverflow
			p.procState = procSendPkt
		default:
			p.currPacket.Type = PktTSLocal
			p.decodeState = decodeLocalTS
			p.procState = procData
		}
	} else if (b & 0x0B) == 0x08 {
		p.currPacket.Type = PktExtension
		p.decodeState = decodeExtension
		p.procState = procData
	} else if (b & 0xDF) == 0x94 {
		if (b & 0x20) == 0x00 {
			p.currPacket.Type = PktTSGlobal1
			p.decodeState = decodeGlobalTS1
		} else {
			p.currPacket.Type = PktTSGlobal2
			p.decodeState = decodeGlobalTS2
		}
		p.procState = procData
	} else {
		return p.setReservedHdrError("")
	}
	return nil
}

func (p *PktProc) runDataDecodeState() error {
	switch p.decodeState {
	case decodeData:
		return p.PktData()
	case decodeAsync:
		return p.PktAsync()
	case decodeLocalTS:
		return p.PktLocalTS()
	case decodeExtension:
		return p.PktExtension()
	case decodeGlobalTS1:
		return p.PktGlobalTS1()
	case decodeGlobalTS2:
		return p.PktGlobalTS2()
	default:
		return p.setBadSequenceError("ITM packet decode state not set")
	}
}

func (p *PktProc) PktData() error {
	payloadBytesReq := int(p.headerByte & 0x3)
	payloadBytesGot := len(p.packetData) - 1

	if payloadBytesReq == 3 {
		payloadBytesReq = 4
	}

	if len(p.packetData) == 1 {
		p.currPacket.SrcID = (p.headerByte >> 3) & 0x1F
	}

	if payloadBytesGot < payloadBytesReq {
		remaining := payloadBytesReq - payloadBytesGot
		start := len(p.packetData)
		p.packetData = append(p.packetData, make([]byte, remaining)...)
		n, err := io.ReadFull(p.dataReader, p.packetData[start:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				p.packetData = p.packetData[:start+n]
				p.refreshDataUsed()
				return nil
			}
			return err
		}
		p.refreshDataUsed()
		payloadBytesGot += n
	}

	if payloadBytesGot == payloadBytesReq {
		var value uint32 = uint32(p.packetData[1])
		if payloadBytesReq >= 2 {
			value |= (uint32(p.packetData[2]) << 8)
		}
		if payloadBytesReq == 4 {
			value |= (uint32(p.packetData[3]) << 16)
			value |= (uint32(p.packetData[4]) << 24)
		}
		p.currPacket.SetValue(value, uint8(payloadBytesReq))
		p.procState = procSendPkt
	}
	return nil
}

func (p *PktProc) readContBytes(limit int) bool {
	bDone := false
	for !bDone && len(p.packetData) < limit {
		b, ok := p.readByte()
		if !ok {
			break
		}
		bDone = ((b & 0x80) == 0x00)
	}
	return bDone
}

// decodeNextPacket decodes one ITM packet at offset without reading or mutating PktProc state.
// During migration this handles overflow-only packets and falls back via sentinel for other types.
func decodeNextPacket(data []byte, offset int) (Packet, int, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, 0, fmt.Errorf("offset %d out of range", offset)
	}
	header := data[offset]
	if header == 0x00 {
		if offset+6 > len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}
		for i := offset + 1; i < offset+5; i++ {
			if data[i] != 0x00 {
				return Packet{}, 0, fmt.Errorf("%w: Async Packet: unexpected none zero value", ocsd.ErrBadPacketSeq)
			}
		}
		for i := offset + 5; i < len(data); i++ {
			if data[i] == 0x80 {
				return Packet{Type: PktAsync}, i - offset + 1, nil
			}
			if data[i] != 0x00 {
				return Packet{}, 0, fmt.Errorf("%w: Async Packet: unexpected none zero value", ocsd.ErrBadPacketSeq)
			}
		}
		return Packet{}, 0, errDecodeNotImplemented
	}
	if header == 0x70 {
		return Packet{Type: PktOverflow}, 1, nil
	}
	if (header & 0xDF) == 0x94 {
		if (header & 0x20) == 0x00 {
			return decodeGlobalTS1Packet(data, offset)
		}
		return decodeGlobalTS2Packet(data, offset)
	}
	if (header & 0x0B) == 0x08 {
		return decodeExtensionPacket(data, offset)
	}
	if (header&0x0F) == 0x00 && (header&0xF0) != 0x00 && (header&0xF0) != 0x70 {
		pkt := Packet{Type: PktTSLocal}
		if (header & 0x80) == 0 {
			pkt.SrcID = 0
			pkt.SetValue(uint32((header>>4)&0x7), 1)
			return pkt, 1, nil
		}

		pkt.SrcID = (header >> 4) & 0x3
		value, n, ok := decodeContField32NoOverflow(data, offset+1, 4)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		pkt.SetValue(value, uint8(n))
		return pkt, 1 + n, nil
	}
	if (header & 0x03) != 0x00 {
		payloadBytes := int(header & 0x3)
		if payloadBytes == 3 {
			payloadBytes = 4
		}
		if offset+1+payloadBytes > len(data) {
			return Packet{}, 0, errDecodeNotImplemented
		}

		value := uint32(data[offset+1])
		if payloadBytes >= 2 {
			value |= uint32(data[offset+2]) << 8
		}
		if payloadBytes == 4 {
			value |= uint32(data[offset+3]) << 16
			value |= uint32(data[offset+4]) << 24
		}

		pktType := PktSWIT
		if (header & 0x4) != 0 {
			pktType = PktDWT
		}
		pkt := Packet{Type: pktType, SrcID: (header >> 3) & 0x1F}
		pkt.SetValue(value, uint8(payloadBytes))
		return pkt, 1 + payloadBytes, nil
	}
	return Packet{}, 0, fmt.Errorf("%w: reserved packet header", ocsd.ErrInvalidPcktHdr)
}

func decodeContField32NoOverflow(data []byte, start int, limit int) (uint32, int, bool) {
	if start < 0 || start >= len(data) || limit <= 0 {
		return 0, 0, false
	}

	var value uint32
	for i := range limit {
		idx := start + i
		if idx >= len(data) {
			return 0, 0, false
		}
		b := data[idx]
		shift := i * 7
		if shift >= 32 {
			return 0, 0, false
		}
		part := uint32(b & 0x7F)
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				return 0, 0, false
			}
		}
		value |= part << shift
		if (b & 0x80) == 0 {
			return value, i + 1, true
		}
	}

	return 0, 0, false
}

func decodeContField64NoOverflow(data []byte, start int, limit int) (uint64, int, bool) {
	if start < 0 || start >= len(data) || limit <= 0 {
		return 0, 0, false
	}

	var value uint64
	for i := range limit {
		idx := start + i
		if idx >= len(data) {
			return 0, 0, false
		}
		b := data[idx]
		shift := i * 7
		if shift >= 64 {
			return 0, 0, false
		}
		part := uint64(b & 0x7F)
		if shift > 57 {
			maxPart := (uint64(1) << uint(64-shift)) - 1
			if part > maxPart {
				return 0, 0, false
			}
		}
		value |= part << shift
		if (b & 0x80) == 0 {
			return value, i + 1, true
		}
	}

	return 0, 0, false
}

func decodeGlobalTS1Packet(data []byte, offset int) (Packet, int, error) {
	value, n, ok := decodeContField32NoOverflow(data, offset+1, 4)
	if !ok {
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: PktTSGlobal1}
	if n == 4 {
		last := data[offset+4]
		pkt.SrcID = (last >> 5) & 0x3
		masked := make([]byte, n)
		copy(masked, data[offset+1:offset+1+n])
		masked[n-1] &= 0x1F
		value, _, ok = decodeContField32NoOverflow(masked, 0, n)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
	}
	pkt.SetValue(value, uint8(n))
	return pkt, 1 + n, nil
}

func decodeGlobalTS2Packet(data []byte, offset int) (Packet, int, error) {
	v64, n, ok := decodeContField64NoOverflow(data, offset+1, 6)
	if !ok {
		return Packet{}, 0, errDecodeNotImplemented
	}

	pkt := Packet{Type: PktTSGlobal2}
	if n <= 4 {
		pkt.SetValue(uint32(v64), uint8(n))
	} else {
		pkt.SetExtValue(v64)
	}
	return pkt, 1 + n, nil
}

func decodeExtensionPacket(data []byte, offset int) (Packet, int, error) {
	header := data[offset]
	pkt := Packet{Type: PktExtension}

	payloadLen := 0
	value := uint32((header >> 4) & 0x7)
	if (header & 0x80) != 0 {
		contValue, n, ok := decodeContField32NoOverflow(data, offset+1, 4)
		if !ok {
			return Packet{}, 0, errDecodeNotImplemented
		}
		payloadLen = n
		value |= contValue << 3
	}

	bitLength := []uint8{2, 9, 16, 23, 31}
	pkt.SrcID = bitLength[payloadLen]
	if (header & 0x4) != 0 {
		pkt.SrcID |= 0x80
	}
	pkt.SetValue(value, 4)
	return pkt, 1 + payloadLen, nil
}

func itmGetPacketBufRef() *[]byte {
	return itmPacketDataPool.Get().(*[]byte)
}

func itmPutPacketBufRef(bufRef *[]byte, buf []byte) {
	if bufRef == nil {
		return
	}
	*bufRef = buf[:0]
	itmPacketDataPool.Put(bufRef)
}

func (p *PktProc) extractContVal32() (uint32, error) {
	if len(p.packetData) == 0 {
		return 0, nil
	}
	var value uint32 = 0
	shift := 0
	idxMax := len(p.packetData) - 1

	for idx := 1; idx <= idxMax; idx++ {
		part := uint32(p.packetData[idx] & 0x7F)
		if shift >= 32 {
			return 0, p.setBadSequenceError("Continuation value exceeds 32-bit width")
		}
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				return 0, p.setBadSequenceError("Continuation value overflows 32-bit width")
			}
		}
		value |= (part << shift)
		shift += 7
	}
	return value, nil
}

func (p *PktProc) extractContVal64() (uint64, error) {
	if len(p.packetData) == 0 {
		return 0, nil
	}
	var value uint64 = 0
	shift := 0
	idxMax := len(p.packetData) - 1

	for idx := 1; idx <= idxMax; idx++ {
		part := uint64(p.packetData[idx] & 0x7F)
		if shift >= 64 {
			return 0, p.setBadSequenceError("Continuation value exceeds 64-bit width")
		}
		if shift > 57 {
			maxPart := (uint64(1) << uint(64-shift)) - 1
			if part > maxPart {
				return 0, p.setBadSequenceError("Continuation value overflows 64-bit width")
			}
		}
		value |= (part << shift)
		shift += 7
	}
	return value, nil
}

func (p *PktProc) PktLocalTS() error {
	const pktSizeLimit = 5
	bGotContVal := false

	if len(p.packetData) == 1 {
		if (p.headerByte & 0x80) != 0 {
			p.currPacket.SrcID = (p.headerByte >> 4) & 0x3
		} else {
			p.currPacket.SrcID = 0
			p.currPacket.SetValue(uint32((p.headerByte>>4)&0x7), 1)
			p.procState = procSendPkt
			return nil
		}
	}

	bGotContVal = p.readContBytes(pktSizeLimit)

	if bGotContVal {
		v, err := p.extractContVal32()
		if err != nil {
			return err
		}
		p.currPacket.SetValue(v, uint8(len(p.packetData)-1))
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("Local TS packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) PktGlobalTS1() error {
	const pktSizeLimit = 5
	bGotContVal := p.readContBytes(pktSizeLimit)

	if bGotContVal {
		if len(p.packetData) == 5 {
			b := p.packetData[4]
			p.currPacket.SrcID = (b >> 5) & 0x3
			p.packetData[4] = b & 0x1F
		}
		v, err := p.extractContVal32()
		if err != nil {
			return err
		}
		p.currPacket.SetValue(v, uint8(len(p.packetData)-1))
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("GTS1 packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) PktGlobalTS2() error {
	const pktSizeLimit = 7
	bGotContVal := p.readContBytes(pktSizeLimit)

	if bGotContVal {
		if len(p.packetData) <= 5 {
			v, err := p.extractContVal32()
			if err != nil {
				return err
			}
			p.currPacket.SetValue(v, uint8(len(p.packetData)-1))
		} else {
			v, err := p.extractContVal64()
			if err != nil {
				return err
			}
			p.currPacket.SetExtValue(v)
		}
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("GTS2 packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) PktExtension() error {
	const pktSizeLimit = 5
	bitLength := []uint8{2, 9, 16, 23, 31}
	bGotContVal := false

	if (p.headerByte & 0x80) == 0 {
		bGotContVal = true
	} else {
		bGotContVal = p.readContBytes(pktSizeLimit)
	}

	if bGotContVal {
		srcIdVal := bitLength[len(p.packetData)-1]
		if (p.headerByte & 0x4) != 0 {
			srcIdVal |= 0x80
		}
		p.currPacket.SrcID = srcIdVal

		value := uint32(0)
		if len(p.packetData) > 1 {
			var err error
			value, err = p.extractContVal32()
			if err != nil {
				return err
			}
			value <<= 3
		}
		value |= uint32((p.headerByte >> 4) & 0x7)
		p.currPacket.SetValue(value, 4)
		p.procState = procSendPkt
	} else if len(p.packetData) == pktSizeLimit {
		return p.setBadSequenceError("Extension packet: Payload continuation value too long")
	}
	return nil
}

func (p *PktProc) readAsyncSeq() (bFoundAsync bool, bError bool) {
	bError = false
	bFoundAsync = false

	for len(p.packetData) < 5 && !bError {
		b, ok := p.readByte()
		if !ok {
			break
		}
		if b != 0x00 {
			bError = true
		}
	}

	for !bFoundAsync && !bError {
		b, ok := p.readByte()
		if !ok {
			break
		}
		if b == 0x80 {
			bFoundAsync = true
		} else if b != 0x00 {
			bError = true
		}
	}
	return bFoundAsync, bError
}

func (p *PktProc) PktAsync() error {
	bFoundAsync, bError := p.readAsyncSeq()
	if bFoundAsync {
		p.procState = procSendPkt
	} else if bError {
		return p.setBadSequenceError("Async Packet: unexpected none zero value")
	}
	return nil
}

func (p *PktProc) flushUnsyncedBytes() error {
	p.outputRawPacketToMonitor(p.packetIndex, &p.currPacket, p.packetData[:p.dumpUnsyncedBytes])

	var err error
	if !p.sentNotSyncPacket {
		err = p.outputDecodedPacket(p.packetIndex, &p.currPacket)
		p.sentNotSyncPacket = true
	}

	if len(p.packetData) <= p.dumpUnsyncedBytes {
		p.packetData = p.packetData[:0]
	} else {
		// remove dumped bytes
		p.packetData = p.packetData[p.dumpUnsyncedBytes:]
	}
	p.dumpUnsyncedBytes = 0

	return err
}

func (p *PktProc) waitForSync(blkStIndex ocsd.TrcIndex) error {
	var outErr error
	p.currPacket.Type = PktNotSync
	p.dumpUnsyncedBytes = 0

	if !p.syncStart {
		p.packetIndex = blkStIndex + ocsd.TrcIndex(p.dataInUsed)
	}

	for !p.streamSync && p.dataToProcess() && outErr == nil {
		if p.syncStart {
			bFoundAsync, bAsyncErr := p.readAsyncSeq()
			p.streamSync = bFoundAsync
			if p.streamSync {
				p.currPacket.Type = PktAsync
				p.procState = procSendPkt
			} else if bAsyncErr {
				p.dumpUnsyncedBytes = len(p.packetData)
				p.syncStart = false
			}
		}

		if !p.syncStart {
			b, ok := p.readByte()
			if !ok {
				break
			}

			if b == 0x00 {
				p.syncStart = true
				outErr = p.flushUnsyncedBytes()
				p.packetIndex = blkStIndex + ocsd.TrcIndex(p.dataInUsed) - 1
			} else {
				p.dumpUnsyncedBytes++
				if p.dumpUnsyncedBytes >= 8 {
					outErr = p.flushUnsyncedBytes()
				}
			}
		}
	}

	if !p.streamSync && !p.syncStart && p.dumpUnsyncedBytes > 0 {
		outErr = p.flushUnsyncedBytes()
	}

	return outErr
}
