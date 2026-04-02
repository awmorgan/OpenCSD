package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
)

// CodeFollower follows the execution path by decoding instructions.
// It interfaces with memory access and instruction decode.
type CodeFollower struct {
	InstrInfo ocsd.InstrInfo
	MemAccess TargetMemAccess
	IdDecode  InstrDecode
	MemSpace  ocsd.MemSpaceAcc
	TraceID   uint8
	Arch      ocsd.ArchProfile
	Isa       ocsd.ISA
}

// FollowResult contains the decoded single-atom follow outcome.
type FollowResult struct {
	HasNext   bool
	HasNacc   bool
	NaccAddr  ocsd.VAddr
	NumInstr  uint32
	RangeSt   ocsd.VAddr
	RangeEn   ocsd.VAddr
	NextAddr  ocsd.VAddr
	InstrInfo ocsd.InstrInfo
}

func (r FollowResult) HasRange() bool {
	return r.RangeSt < r.RangeEn
}

// NewCodeFollowerWithInterfaces creates a CodeFollower and attaches required decoder interfaces.

// Both memAccess and idDecode must be non-nil.
func NewCodeFollowerWithInterfaces(memAccess TargetMemAccess, idDecode InstrDecode) (*CodeFollower, error) {
	if memAccess == nil {
		return nil, fmt.Errorf("%w: code follower mem access cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if idDecode == nil {
		return nil, fmt.Errorf("%w: code follower instruction decoder cannot be nil", ocsd.ErrInvalidParamVal)
	}

	cf := &CodeFollower{
		MemAccess: memAccess,
		IdDecode:  idDecode,
	}
	return cf, nil
}

// SetInterfaces updates the active memory and instruction decode interfaces.
func (cf *CodeFollower) SetInterfaces(memAccess TargetMemAccess, idDecode InstrDecode) error {
	if memAccess == nil {
		return fmt.Errorf("%w: code follower mem access cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if idDecode == nil {
		return fmt.Errorf("%w: code follower instruction decoder cannot be nil", ocsd.ErrInvalidParamVal)
	}
	cf.MemAccess = memAccess
	cf.IdDecode = idDecode
	return nil
}

func (cf *CodeFollower) SetDSBDMBasWP() {
	cf.InstrInfo.DsbDmbWaypoints = 1
}

// DecodeSingleOpCode decodes a single opcode at instrInfo.InstrAddr.
func (cf *CodeFollower) DecodeSingleOpCode(instrInfo *ocsd.InstrInfo, traceID uint8, memSpace ocsd.MemSpaceAcc) error {
	const bytesReq uint32 = 4

	// Read memory location for opcode
	readBytes, pData, err := cf.MemAccess.ReadTargetMemory(instrInfo.InstrAddr, traceID, memSpace, bytesReq)

	// Treat no-access and incomplete opcode reads as memory unavailable.
	if errors.Is(err, memacc.ErrNoAccessor) || (err == nil && (readBytes != bytesReq || len(pData) < int(bytesReq))) {
		return ocsd.ErrMemNacc
	}

	if err != nil {
		return err
	}

	instrInfo.Opcode = binary.LittleEndian.Uint32(pData[:4])

	err = cf.IdDecode.DecodeInstruction(instrInfo)
	return err
}

// FollowSingleAtom decodes an instruction and returns the result snapshot by value.
func (cf *CodeFollower) FollowSingleAtom(addrStart ocsd.VAddr, atom ocsd.AtmVal) (FollowResult, error) {
	instrInfo := cf.InstrInfo
	instrInfo.InstrAddr = addrStart

	res := FollowResult{
		HasNext:   false,
		HasNacc:   false,
		NaccAddr:  addrStart,
		NumInstr:  0,
		RangeSt:   addrStart,
		RangeEn:   addrStart,
		NextAddr:  addrStart,
		InstrInfo: instrInfo,
	}

	err := cf.DecodeSingleOpCode(&instrInfo, cf.TraceID, cf.MemSpace)
	if err != nil {
		if errors.Is(err, ocsd.ErrMemNacc) {
			res.HasNacc = true
		}
		return res, err
	}

	res.InstrInfo = instrInfo
	res.RangeEn = instrInfo.InstrAddr + ocsd.VAddr(instrInfo.InstrSize)
	res.NumInstr = 1
	res.NextAddr = res.RangeEn
	res.HasNext = true

	// Next address differs for taken direct and indirect branches.
	switch instrInfo.Type {
	case ocsd.InstrBr:
		if atom == ocsd.AtomE {
			res.NextAddr = instrInfo.BranchAddr
		}
	case ocsd.InstrBrIndirect:
		if atom == ocsd.AtomE {
			res.HasNext = false
		}
	}

	return res, nil
}
