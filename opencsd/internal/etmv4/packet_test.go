package etmv4

import (
	"testing"
)

// ensure Stringer is working
func TestPktTypeString(t *testing.T) {
	tests := []struct {
		name string
		pkt  PktType
		want string
	}{
		{"PktNotSync", PktNotSync, "I_NOT_SYNC"},
		{"PktIncompleteEOT", PktIncompleteEOT, "I_INCOMPLETE_EOT"},
		{"PktNoErrType", PktNoErrType, "I_NO_ERR_TYPE"},
		{"PktBadSequence", PktBadSequence, "I_BAD_SEQUENCE"},
		{"PktBadTraceMode", PktBadTraceMode, "I_BAD_TRACEMODE"},
		{"PktReserved", PktReserved, "I_RESERVED"},
		{"PktReservedCfg", PktReservedCfg, "I_RESERVED_CFG"},
		{"PktExtension", PktExtension, "I_EXTENSION"},
		{"PktTraceInfo", PktTraceInfo, "I_TRACE_INFO"},
		{"PktTimestamp", PktTimestamp, "I_TIMESTAMP"},
		{"PktTraceOn", PktTraceOn, "I_TRACE_ON"},
		{"PktFuncRet", PktFuncRet, "I_FUNC_RET"},
		{"PktExcept", PktExcept, "I_EXCEPT"},
		{"PktExceptRtn", PktExceptRtn, "I_EXCEPT_RTN"},
		{"ETE_PktITE", ETE_PktITE, "I_ETE_ITE"},
		{"ETE_PktTransSt", ETE_PktTransSt, "I_ETE_TRANS_ST"},
		{"ETE_PktTransCommit", ETE_PktTransCommit, "I_ETE_TRANS_COMMIT"},
		{"PktCcntF2", PktCcntF2, "I_CCNT_F2"},
		{"PktCcntF1", PktCcntF1, "I_CCNT_F1"},
		{"PktCcntF3", PktCcntF3, "I_CCNT_F3"},
		{"PktNumDsMkr", PktNumDsMkr, "I_NUM_DS_MKR"},
		{"PktUnnumDsMkr", PktUnnumDsMkr, "I_UNNUM_DS_MKR"},
		{"PktCommit", PktCommit, "I_COMMIT"},
		{"PktCancelF1", PktCancelF1, "I_CANCEL_F1"},
		{"PktMispredict", PktMispredict, "I_MISPREDICT"},
		{"PktCancelF2", PktCancelF2, "I_CANCEL_F2"},
		{"PktCancelF3", PktCancelF3, "I_CANCEL_F3"},
		{"PktCtxtF1", PktCtxtF1, "I_CTXT_F1"},
		{"PktCtxtF2", PktCtxtF2, "I_CTXT_F2"},
		{"PktCtxtF3", PktCtxtF3, "I_CTXT_F3"},
		{"PktCtxtF4", PktCtxtF4, "I_CTXT_F4"},
		{"PktAddrCtxtF1", PktAddrCtxtF1, "I_ADDR_CTXT_F1"},
		{"PktAddrCtxtF2", PktAddrCtxtF2, "I_ADDR_CTXT_F2"},
		{"PktAddrCtxtF3", PktAddrCtxtF3, "I_ADDR_CTXT_F3"},
		{"PktAddrCtxtF4", PktAddrCtxtF4, "I_ADDR_CTXT_F4"},
		{"PktAddrCtxtF5", PktAddrCtxtF5, "I_ADDR_CTXT_F5"},
		{"PktAddrCtxtF6", PktAddrCtxtF6, "I_ADDR_CTXT_F6"},
		{"PktAddrMatch", PktAddrMatch, "I_ADDR_MATCH"},
		{"PktAddrCtxtF3_6", PktAddrCtxtF3_6, "I_ADDR_CTXT_F3_6"},
		{"PktAddrMatch_IS0", PktAddrMatch_IS0, "I_ADDR_MATCH_IS0"},
		{"PktAddrMatch_IS1", PktAddrMatch_IS1, "I_ADDR_MATCH_IS1"},
		{"PktShortAddrCtxt", PktShortAddrCtxt, "I_SHORT_ADDR_CTXT"},
		{"PktShortAddr", PktShortAddr, "I_SHORT_ADDR"},
		{"PktAddrF1", PktAddrF1, "I_ADDR_F1"},
		{"PktAddrF2", PktAddrF2, "I_ADDR_F2"},
		{"PktAddrF3", PktAddrF3, "I_ADDR_F3"},
		{"PktAddrF4", PktAddrF4, "I_ADDR_F4"},
		{"PktAddrF5", PktAddrF5, "I_ADDR_F5"},
		{"PktAddrF6", PktAddrF6, "I_ADDR_F6"},
		{"PktQ", PktQ, "I_Q"},
		{"PktCondResF1", PktCondResF1, "I_COND_RES_F1"},
		{"PktCondResF2", PktCondResF2, "I_COND_RES_F2"},
		{"PktCondResF3", PktCondResF3, "I_COND_RES_F3"},
		{"PktCondResF4", PktCondResF4, "I_COND_RES_F4"},
		{"PktCondInstrF1", PktCondInstrF1, "I_COND_INSTR_F1"},
		{"PktCondInstrF2", PktCondInstrF2, "I_COND_INSTR_F2"},
		{"PktCondInstrF3", PktCondInstrF3, "I_COND_INSTR_F3"},
		{"PktEvent", PktEvent, "I_EVENT"},
		{"PktRes0", PktRes0, "I_RES_0"},
		{"PktAtomF6", PktAtomF6, "I_ATOM_F6"},
		{"PktAtomF5", PktAtomF5, "I_ATOM_F5"},
		{"PktAtomF2", PktAtomF2, "I_ATOM_F2"},
		{"PktAtomF4", PktAtomF4, "I_ATOM_F4"},
		{"PktAtomF1", PktAtomF1, "I_ATOM_F1"},
		{"PktAtomF3", PktAtomF3, "I_ATOM_F3"},
		{"PktAsync", PktAsync, "I_ASYNC"},
		{"PktDiscard", PktDiscard, "I_DISCARD"},
		{"PktOverflow", PktOverflow, "I_OVERFLOW"},
		{"ETE_PktPeReset", ETE_PktPeReset, "I_ETE_PE_RESET"},
		{"ETE_PktTransFail", ETE_PktTransFail, "I_ETE_TRANS_FAIL"},
		{"Unknown", PktType(0x500), "I_UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pkt.String(); got != tt.want {
				t.Errorf("PktType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}