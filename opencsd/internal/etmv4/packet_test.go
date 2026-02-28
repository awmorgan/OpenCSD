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
		{"PktCancelF1Mispred", PktCancelF1Mispred, "I_CANCEL_F1_MISPRED"},
		{"PktCancelF2", PktCancelF2, "I_CANCEL_F2"},
		{"PktCancelF3", PktCancelF3, "I_CANCEL_F3"},
		{"PktCtxt", PktCtxt, "I_CTXT"},
		{"PktAddrCtxtL_32IS0", PktAddrCtxtL_32IS0, "I_ADDR_CTXT_L_32IS0"},
		{"PktAddrCtxtL_32IS1", PktAddrCtxtL_32IS1, "I_ADDR_CTXT_L_32IS1"},
		{"PktAddrCtxtL_64IS0", PktAddrCtxtL_64IS0, "I_ADDR_CTXT_L_64IS0"},
		{"PktAddrCtxtL_64IS1", PktAddrCtxtL_64IS1, "I_ADDR_CTXT_L_64IS1"},
		{"PktAddrMatch", PktAddrMatch, "I_ADDR_MATCH"},
		{"ETE_PktTSMarker", ETE_PktTSMarker, "I_TS_MARKER"},
		{"PktAddrS_IS0", PktAddrS_IS0, "I_ADDR_S_IS0"},
		{"PktAddrS_IS1", PktAddrS_IS1, "I_ADDR_S_IS1"},
		{"PktAddrL_32IS0", PktAddrL_32IS0, "I_ADDR_L_32IS0"},
		{"PktAddrL_32IS1", PktAddrL_32IS1, "I_ADDR_L_32IS1"},
		{"PktAddrL_64IS0", PktAddrL_64IS0, "I_ADDR_L_64IS0"},
		{"PktAddrL_64IS1", PktAddrL_64IS1, "I_ADDR_L_64IS1"},
		{"PktQ", PktQ, "I_Q"},
		{"ETE_PktSrcAddrMatch", ETE_PktSrcAddrMatch, "ETE_PKT_I_SRC_ADDR_MATCH"},
		{"ETE_PktSrcAddrS_IS0", ETE_PktSrcAddrS_IS0, "ETE_PKT_I_SRC_ADDR_S_IS0"},
		{"ETE_PktSrcAddrS_IS1", ETE_PktSrcAddrS_IS1, "ETE_PKT_I_SRC_ADDR_S_IS1"},
		{"ETE_PktSrcAddrL_32IS0", ETE_PktSrcAddrL_32IS0, "ETE_PKT_I_SRC_ADDR_L_32IS0"},
		{"ETE_PktSrcAddrL_32IS1", ETE_PktSrcAddrL_32IS1, "ETE_PKT_I_SRC_ADDR_L_32IS1"},
		{"ETE_PktSrcAddrL_64IS0", ETE_PktSrcAddrL_64IS0, "ETE_PKT_I_SRC_ADDR_L_64IS0"},
		{"ETE_PktSrcAddrL_64IS1", ETE_PktSrcAddrL_64IS1, "ETE_PKT_I_SRC_ADDR_L_64IS1"},
		{"PktCondIF2", PktCondIF2, "I_COND_I_F2"},
		{"PktCondFlush", PktCondFlush, "I_COND_FLUSH"},
		{"PktCondResF4", PktCondResF4, "I_COND_RES_F4"},
		{"PktCondResF2", PktCondResF2, "I_COND_RES_F2"},
		{"PktCondResF3", PktCondResF3, "I_COND_RES_F3"},
		{"PktCondResF1", PktCondResF1, "I_COND_RES_F1"},
		{"PktCondIF1", PktCondIF1, "I_COND_I_F1"},
		{"PktCondIF3", PktCondIF3, "I_COND_I_F3"},
		{"PktIgnore", PktIgnore, "I_IGNORE"},
		{"PktEvent", PktEvent, "I_EVENT"},
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
