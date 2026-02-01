package ptm

import (
	"opencsd/common"
)

// UnsyncReason represents why the decoder lost synchronization
type UnsyncReason string

const (
	UnsyncInitDecoder  UnsyncReason = "init-decoder"
	UnsyncResetDecoder UnsyncReason = "reset"
	UnsyncEOT          UnsyncReason = "eot"
	UnsyncLossOfSync   UnsyncReason = "loss-of-sync"
)

// Processor wraps a PTM Decoder with unsync scanning and loss-of-sync handling.
type Processor struct {
	decoder *Decoder

	// Loss-of-sync tracking
	unsyncReason   UnsyncReason // Reason for loss of sync
	inSyncState    bool         // True if currently in valid sync state
	unSyncedBufLen int          // Accumulated unsynced bytes
	unSyncedBuf    []byte       // Buffer for unsynced data
}

// NewProcessor creates a new PTM packet processor for the given trace ID.
func NewProcessor(traceID uint8) *Processor {
	return &Processor{
		decoder:      NewDecoder(traceID),
		unsyncReason: UnsyncInitDecoder,
		inSyncState:  false,
		unSyncedBuf:  make([]byte, 0, 256),
	}
}

// NewProcessorWithLogger creates a new PTM processor with a custom logger.
func NewProcessorWithLogger(traceID uint8, logger common.Logger) *Processor {
	return &Processor{
		decoder:      NewDecoderWithLogger(traceID, logger),
		unsyncReason: UnsyncInitDecoder,
		inSyncState:  false,
		unSyncedBuf:  make([]byte, 0, 256),
	}
}

// SetMemoryAccessor sets the memory accessor for the underlying decoder.
func (p *Processor) SetMemoryAccessor(memAcc common.MemoryAccessor) {
	p.decoder.SetMemoryAccessor(memAcc)
}

// Apply applies device configuration to the decoder.
func (p *Processor) Apply(cfg PTMDeviceConfig) {
	p.decoder.Apply(cfg)
}

// ConfigureFromSnapshot configures the decoder from a snapshot directory.
func (p *Processor) ConfigureFromSnapshot(snapshotDir string) (string, error) {
	return p.decoder.ConfigureFromSnapshot(snapshotDir)
}

// ProcessRaw processes raw PTM trace data, handling unsync scanning and packet emission.
func (p *Processor) ProcessRaw(raw []byte) ([]Packet, []common.GenericTraceElement, error) {
	var packets []Packet
	var elements []common.GenericTraceElement

	if len(raw) == 0 {
		return packets, elements, nil
	}

	offset := 0
	p.unSyncedBufLen = 0
	p.unSyncedBuf = p.unSyncedBuf[:0]

	// Scan for ASYNC packet (0x00 0x00 0x00 0x00 0x00 0x80)
	asyncPattern := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
	asyncOffset := -1

	maxUnSyncSearch := len(raw)
	if maxUnSyncSearch > 256 {
		maxUnSyncSearch = 256
	}

	for i := 0; i+6 <= maxUnSyncSearch; i++ {
		if matchBytes(raw[i:i+6], asyncPattern) {
			asyncOffset = i
			break
		}
	}

	if asyncOffset > 0 {
		p.unSyncedBufLen = asyncOffset
		p.unSyncedBuf = append(p.unSyncedBuf, raw[0:asyncOffset]...)
		offset = asyncOffset
		p.unsyncReason = UnsyncInitDecoder
	} else if asyncOffset == 0 {
		offset = 0
	} else {
		if maxUnSyncSearch <= len(raw) {
			p.unSyncedBufLen = maxUnSyncSearch
			p.unSyncedBuf = append(p.unSyncedBuf, raw[0:maxUnSyncSearch]...)
			offset = maxUnSyncSearch
		}
	}

	if p.unSyncedBufLen > 0 {
		elem := common.GenericTraceElement{
			Type: common.ElemTypeNoSync,
		}
		elements = append(elements, elem)
		p.inSyncState = false
	}

	syncedData := raw[offset:]
	parsedPackets, err := p.decoder.Parse(syncedData)
	if err != nil {
		return packets, elements, err
	}

	for _, pkt := range parsedPackets {
		packets = append(packets, pkt)

		elems, err := p.decoder.ProcessPacket(pkt)
		if err != nil {
			p.decoder.Log.Logf(common.SeverityWarning, "ProcessPacket error: %v", err)
			continue
		}

		elements = append(elements, elems...)

		if pkt.Type == PacketTypeASYNC || pkt.Type == PacketTypeISYNC {
			p.inSyncState = true
		}
	}

	return packets, elements, nil
}

// ProcessPacket processes a single decoded packet.
func (p *Processor) ProcessPacket(pkt Packet) ([]common.GenericTraceElement, error) {
	return p.decoder.ProcessPacket(pkt)
}

// Reset resets the processor and decoder state.
func (p *Processor) Reset() {
	p.decoder.Reset()
	p.unsyncReason = UnsyncResetDecoder
	p.inSyncState = false
	p.unSyncedBufLen = 0
	p.unSyncedBuf = p.unSyncedBuf[:0]
}

// IsSynchronized returns true if synchronized.
func (p *Processor) IsSynchronized() bool {
	return p.inSyncState && p.decoder.IsSynchronized()
}

// UnsyncReason returns the current loss-of-sync reason.
func (p *Processor) UnsyncReason() UnsyncReason {
	return p.unsyncReason
}

// Decoder returns the underlying PTM decoder.
func (p *Processor) Decoder() *Decoder {
	return p.decoder
}

// Helper function to match bytes
func matchBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
