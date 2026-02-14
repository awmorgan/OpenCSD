package opencsd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/internal/lister"
)

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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshotPath := filepath.Join(testDataRoot, tc.dirName)
			goldenPath := filepath.Join(testDataRoot, tc.pplFile)

			// 1. Read Expected C++ Output
			expectedBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("Could not read golden file %s: %v", goldenPath, err)
			}
			expected := string(expectedBytes)

			// 2. Run Go Implementation
			var actualBuf bytes.Buffer
			cfg := lister.Config{
				SnapshotDir:  snapshotPath,
				Decode:       true, // Usually true for these tests
				NoTimePrint:  true, // Crucial for diff stability!
				OutputWriter: &actualBuf,
			}

			err = lister.Run(cfg)
			if err != nil {
				t.Fatalf("Lister.Run failed: %v", err)
			}

			// 3. Compare
			// Normalize line endings to handle Windows/Linux differences
			actualStr := strings.ReplaceAll(actualBuf.String(), "\r\n", "\n")
			expectedStr := strings.ReplaceAll(expected, "\r\n", "\n")

			// Simple check (you might want a diff library like go-cmp later)
			if actualStr != expectedStr {
				// Write actual output to file for debugging
				debugFile := filepath.Join(testDataRoot, tc.dirName+"_debug_actual.txt")
				_ = os.WriteFile(debugFile, []byte(actualStr), 0644)

				t.Errorf("Output did not match golden file.\nLength Expected: %d\nLength Actual: %d\nSee %s for details.",
					len(expectedStr), len(actualStr), debugFile)
			}
		})
	}
}
