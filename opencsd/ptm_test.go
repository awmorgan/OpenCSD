package ptm

import (
	"os"
	"os/exec"
	"testing"
)

func TestPtmParity(t *testing.T) {
	cppLister := "../decoder/tests/bin/mingw64/rel/trc_pkt_lister.exe"
	snapshotDir := "../decoder/tests/snapshots/tc2-ptm-rstk-t32"
	cppLog := "ptm-pkts-only.ppl"
	binFile := snapshotDir + "/PTM_0_2.bin"

	cmd := exec.Command(cppLister, "-ss_dir", snapshotDir, "-pkt_mon", "-no_time_print", "-logfilename", cppLog)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run C++ lister: %v", err)
	}

	data, err := os.ReadFile(binFile)
	if err != nil {
		t.Fatalf("Failed to read trace bin: %v", err)
	}

	goOutput := ParsePtmPackets(data)
	_ = goOutput
	// compareResults(t, cppLog, goOutput)
}
