package common

import (
	"errors"
	"opencsd/internal/idec"
	"opencsd/internal/ocsd"
	"testing"
)

type mockMemAccess struct {
	addrRequested ocsd.VAddr
	bytesReq      uint32
	dataToReturn  []byte
	errToReturn   error
}

func (m *mockMemAccess) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	m.addrRequested = address
	m.bytesReq = reqBytes
	if m.errToReturn != nil {
		return 0, nil, m.errToReturn
	}
	return uint32(len(m.dataToReturn)), m.dataToReturn, nil
}

func (m *mockMemAccess) InvalidateMemAccCache(csTraceID uint8) {}

func TestCodeFollower(t *testing.T) {
	mockMem := &mockMemAccess{
		dataToReturn: []byte{0x00, 0x00, 0x00, 0x00},
		errToReturn:  nil,
	}

	realID := idec.NewDecoder()

	cf := NewCodeFollower()

	// Test without valid
	_, err := cf.FollowSingleAtom(0x1000, ocsd.AtomN)
	if !errors.Is(err, ocsd.ErrNotInit) {
		t.Errorf("Expected NotInit error")
	}

	cf = NewCodeFollowerWithInterfaces(mockMem, realID)

	cf.Arch = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	cf.InstrInfo.PeType = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	cf.Isa = ocsd.ISAAArch64
	cf.InstrInfo.ISA = ocsd.ISAAArch64
	cf.TraceID = 0x12
	cf.MemSpace = ocsd.MemSpaceAny

	res, err := cf.FollowSingleAtom(0x1000, ocsd.AtomE)
	if err != nil || !res.HasNext {
		t.Errorf("FollowSingleAtom failed")
	}
	if !res.HasRange() {
		t.Errorf("Expected valid range after successful follow")
	}

	if res.NumInstr != 1 {
		t.Errorf("Expected 1 instruction")
	}

	if res.NextAddr != 0x1004 {
		t.Errorf("Expected next addr 0x1004, got 0x%X", res.NextAddr)
	}

	// Test branch
	mockMem.dataToReturn = []byte{0xFF, 0x03, 0x00, 0x14} // A64 B 0x2000 from 0x1004 (offset 0xFFC)
	res, err = cf.FollowSingleAtom(0x1004, ocsd.AtomE)
	if err != nil || res.NextAddr != 0x2000 {
		t.Errorf("Branch target not followed")
	}

	// Test Thumb 32-bit decode requirement
	cf.Isa = ocsd.ISAThumb2
	cf.InstrInfo.ISA = ocsd.ISAThumb2
	mockMem.dataToReturn = []byte{0x00, 0xF0, 0x01, 0x02} // Provide full 4 bytes so DecodeSingleOpCode succeeds
	_, err = cf.FollowSingleAtom(0x1008, ocsd.AtomN)
	if err != nil {
		t.Errorf("Thumb 32-bit fetch failed")
	}

	// Test MemNacc
	mockMem.errToReturn = ocsd.ErrMemNacc
	mockMem.dataToReturn = nil
	res, err = cf.FollowSingleAtom(0x2000, ocsd.AtomN)
	if !errors.Is(err, ocsd.ErrMemNacc) || !res.HasNacc {
		t.Errorf("MemNacc error not tracked properly")
	}
	if res.NaccAddr != 0x2000 {
		t.Errorf("Expected nacc addr 0x2000, got 0x%X", res.NaccAddr)
	}
	if cf.MemSpace != ocsd.MemSpaceAny {
		t.Errorf("Expected memory space to be preserved")
	}

	cf.SetDSBDMBasWP()
	if cf.InstrInfo.DsbDmbWaypoints != 1 {
		t.Errorf("Expected DSB/DMB waypoint mode to be enabled")
	}
}
