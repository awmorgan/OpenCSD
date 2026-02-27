package ocsd

// AtmVal represents atom evaluation
type AtmVal int

const (
	AtomN AtmVal = 0
	AtomE AtmVal = 1
)

// PktAtom represents an instruction atom packet.
type PktAtom struct {
	EnBits uint32 // Bit sequence: ls bit = oldest atom, 1'b1 = E, 1'b0 = N
	Num    uint8  // number of atoms
}

// ISyncReason represents the reason for an Instruction Synchronization packet
type ISyncReason int

const (
	ISyncPeriodic                  ISyncReason = 0
	ISyncTraceEnable               ISyncReason = 1
	ISyncTraceRestartAfterOverflow ISyncReason = 2
	ISyncDebugExit                 ISyncReason = 3
)

// ArmV7Exception represents an ARMv7 Exception type
type ArmV7Exception int

const (
	ExcpReserved         ArmV7Exception = 0
	ExcpNoException      ArmV7Exception = 1
	ExcpReset            ArmV7Exception = 2
	ExcpIRQ              ArmV7Exception = 3
	ExcpFIQ              ArmV7Exception = 4
	ExcpAsyncDAbort      ArmV7Exception = 5
	ExcpDebugHalt        ArmV7Exception = 6
	ExcpJazelle          ArmV7Exception = 7
	ExcpSVC              ArmV7Exception = 8
	ExcpSMC              ArmV7Exception = 9
	ExcpHyp              ArmV7Exception = 10
	ExcpUndef            ArmV7Exception = 11
	ExcpPrefAbort        ArmV7Exception = 12
	ExcpGeneric          ArmV7Exception = 13
	ExcpSyncDataAbort    ArmV7Exception = 14
	ExcpCMUsageFault     ArmV7Exception = 15
	ExcpCMNMI            ArmV7Exception = 16
	ExcpCMDebugMonitor   ArmV7Exception = 17
	ExcpCMMemManage      ArmV7Exception = 18
	ExcpCMPendSV         ArmV7Exception = 19
	ExcpCMSysTick        ArmV7Exception = 20
	ExcpCMBusFault       ArmV7Exception = 21
	ExcpCMHardFault      ArmV7Exception = 22
	ExcpCMIRQn           ArmV7Exception = 23
	ExcpThumbEECheckFail ArmV7Exception = 24
)
