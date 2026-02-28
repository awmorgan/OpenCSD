package common

import (
	"opencsd/internal/idec"
	"opencsd/internal/ocsd"
	"testing"
)

type mockMemAccess struct {
	addrRequested ocsd.VAddr
	bytesReq      uint32
	dataToReturn  []byte
	errToReturn   ocsd.Err
}

func (m *mockMemAccess) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	m.addrRequested = address
	m.bytesReq = reqBytes
	if m.errToReturn != ocsd.OK {
		return 0, nil, m.errToReturn
	}
	return uint32(len(m.dataToReturn)), m.dataToReturn, ocsd.OK
}

func (m *mockMemAccess) InvalidateMemAccCache(csTraceID uint8) {}

func TestCodeFollower(t *testing.T) {
	cf := NewCodeFollower()

	memAtt := NewAttachPt[TargetMemAccess]()
	mockMem := &mockMemAccess{
		dataToReturn: []byte{0x00, 0x00, 0x00, 0x00},
		errToReturn:  ocsd.OK,
	}
	memAtt.Attach(mockMem)

	idAtt := NewAttachPt[InstrDecode]()
	realID := idec.NewDecoder()
	idAtt.Attach(realID)

	// Test without valid
	err := cf.FollowSingleAtom(0x1000, ocsd.AtomN)
	if err != ocsd.ErrNotInit {
		t.Errorf("Expected NotInit error")
	}

	cf.InitInterfaces(memAtt, idAtt)
	cf.SetArchProfile(ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA})
	cf.SetISA(ocsd.ISAAArch64)
	cf.SetTraceID(0x12)
	cf.SetMemSpace(ocsd.MemSpaceAny)

	err = cf.FollowSingleAtom(0x1000, ocsd.AtomE)
	if err != ocsd.OK || !cf.HasNextAddr() {
		t.Errorf("FollowSingleAtom failed")
	}

	if cf.GetNumInstructs() != 1 {
		t.Errorf("Expected 1 instruction")
	}

	if cf.GetNextAddr() != 0x1004 {
		t.Errorf("Expected next addr 0x1004, got 0x%X", cf.GetNextAddr())
	}

	// Test branch
	mockMem.dataToReturn = []byte{0xFF, 0x03, 0x00, 0x14} // A64 B 0x2000 from 0x1004 (offset 0xFFC)
	err = cf.FollowSingleAtom(0x1004, ocsd.AtomE)
	if err != ocsd.OK || cf.GetNextAddr() != 0x2000 {
		t.Errorf("Branch target not followed")
	}

	// Test Thumb 32-bit decode requirement
	cf.SetISA(ocsd.ISAThumb2)
	mockMem.dataToReturn = []byte{0x00, 0xF0, 0x01, 0x02} // Provide full 4 bytes so DecodeSingleOpCode succeeds
	err = cf.FollowSingleAtom(0x1008, ocsd.AtomN)
	if err != ocsd.OK {
		t.Errorf("Thumb 32-bit fetch failed")
	}

	// Test MemNacc
	mockMem.errToReturn = ocsd.ErrMemNacc
	mockMem.dataToReturn = nil
	err = cf.FollowSingleAtom(0x2000, ocsd.AtomN)
	if err != ocsd.ErrMemNacc || !cf.IsNaccErr() || !cf.HasError() {
		t.Errorf("MemNacc error not tracked properly")
	}
	cf.ClearError()
	if cf.HasError() {
		t.Errorf("ClearError failed")
	}
}
