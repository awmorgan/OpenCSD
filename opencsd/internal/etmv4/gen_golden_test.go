package etmv4_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden is set via -update flag: go test ./internal/etmv4/... -run TestUpdateGolden -args -update
var updateGolden = flag.Bool("update", false, "update golden PPL files from Go decoder output")

// TestUpdateGolden regenerates all golden PPL files from the current Go decoder
// output. Run with: go test ./internal/etmv4/... -run TestUpdateGolden -args -update
func TestUpdateGolden(t *testing.T) {
	if !*updateGolden {
		t.Skip("pass -update to regenerate goldens")
	}

	cases := []struct {
		name       string
		sourceName string
	}{
		{name: "juno_r1_1", sourceName: "ETB_0"},
		{name: "a57_single_step", sourceName: "CSTMC_TRACE_FIFO"},
		{name: "armv8_1m_branches", sourceName: "etr_0"},
		{name: "juno-uname-001", sourceName: "ETB_0"},
		{name: "juno-uname-002", sourceName: "ETB_0"},
		{name: "juno-ret-stck", sourceName: "ETB_0"},
		{name: "test-file-mem-offsets", sourceName: "ETB_0"},
		{name: "init-short-addr", sourceName: "CSTMC_TRACE_FIFO"},
		{name: "bugfix-exact-match", sourceName: "etr_0"},
	}

	for _, tc := range cases {
		snapshotDir := filepath.Join("testdata", tc.name)
		if _, err := os.Stat(snapshotDir); os.IsNotExist(err) {
			t.Logf("skip %s: snapshot dir not found", tc.name)
			continue
		}
		goldenPath := filepath.Join("testdata", tc.name+".ppl")
		out, err := runSnapshotDecode(snapshotDir, tc.sourceName)
		if err != nil {
			t.Errorf("runSnapshotDecode(%s): %v", tc.name, err)
			continue
		}
		if err := os.WriteFile(goldenPath, out, 0644); err != nil {
			t.Errorf("write golden %s: %v", goldenPath, err)
			continue
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(out))
	}
}
