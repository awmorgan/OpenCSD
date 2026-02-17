package opencsd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"opencsd/internal/lister"

	"github.com/google/go-cmp/cmp"
)

// normalizeOutput prepares test output for comparison by removing environment-specific artifacts
func normalizeOutput(output string) string {
	// 1. Unify line endings (just in case)
	output = strings.ReplaceAll(output, "\r\n", "\n")

	// 2. Standardize paths: Convert Windows backslashes to forward slashes
	output = strings.ReplaceAll(output, "\\", "/")

	// 3. Strip the header (everything before the first "real" logic line)
	// Based on the output, "Trace Packet Lister : reading snapshot" is the first stable line
	if idx := strings.Index(output, "Trace Packet Lister : reading snapshot"); idx != -1 {
		output = output[idx:]
	}

	// 4. Relativize paths: normalize internal/snapshot/testdata to ./snapshots/
	re := regexp.MustCompile(`internal/snapshot/testdata/`)
	output = re.ReplaceAllString(output, "./snapshots/")

	return output
}

// This test ensures Go output matches the C++ "Golden" output (.ppl files)
func TestIntegrationComparison(t *testing.T) {
	// Root directory where your test snapshots live
	testDataRoot := "internal/snapshot/testdata"

	// Define specific tests or walk the directory
	tests := []struct {
		name    string
		dirName string
		pplFile string // The C++ output file to compare against
	}{
		{
			name:    "TC2 PTM RSTK T32",
			dirName: "tc2-ptm-rstk-t32",
			pplFile: "tc2-ptm-rstk-t32.ppl",
		},
		{
			name:    "Snowball PTM",
			dirName: "Snowball",
			pplFile: "Snowball.ppl",
		},
		{
			name:    "Trace Cov A15 PTM",
			dirName: "trace_cov_a15",
			pplFile: "trace_cov_a15.ppl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshotPath := filepath.Join(testDataRoot, tc.dirName)
			goldenPath := filepath.Join(testDataRoot, tc.pplFile)

			expectedBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("Could not read golden file %s: %v", goldenPath, err)
			}
			expectedStr := normalizeOutput(string(expectedBytes))

			var actualBuf bytes.Buffer
			cfg := lister.Config{
				SnapshotDir:  snapshotPath,
				Decode:       true,
				NoTimePrint:  true,
				OutputWriter: &actualBuf,
			}

			err = lister.Run(cfg)
			if err != nil {
				t.Fatalf("Lister.Run failed: %v", err)
			}

			actualStr := normalizeOutput(actualBuf.String())

			if diff := cmp.Diff(expectedStr, actualStr); diff != "" {
				t.Errorf("Output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
