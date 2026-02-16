package opencsd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
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
			// Normalize to handle Windows/Linux differences and path separators
			normalize := func(s string) string {
				s = strings.ReplaceAll(s, "\r\n", "\n")
				s = strings.ReplaceAll(s, "\\", "/")

				// Replace absolute paths containing internal/snapshot/testdata with ./snapshots
				re := regexp.MustCompile(`[A-Za-z]:/[^ \t\n\r]*internal/snapshot/testdata`)
				s = re.ReplaceAllString(s, "./snapshots")
				// Also handle relative ones
				s = strings.ReplaceAll(s, "internal/snapshot/testdata", "./snapshots")

				// Trim trailing spaces on each line and trailing newlines
				lines := strings.Split(s, "\n")
				for i := range lines {
					lines[i] = strings.TrimRight(lines[i], " \t")
				}
				return strings.TrimRight(strings.Join(lines, "\n"), "\n")
			}

			actualStr := normalize(actualBuf.String())
			expectedStr := normalize(expected)

			// Simple check (you might want a diff library like go-cmp later)
			if actualStr != expectedStr {
				// Write actual output to the system temp directory for debugging.
				// This avoids creating untracked files in the repository.
				debugFile := filepath.Join(os.TempDir(), "opencsd-test-"+tc.dirName+"-actual.txt")
				_ = os.WriteFile(debugFile, []byte(actualStr), 0644)

				debugExpectedFile := filepath.Join(os.TempDir(), "opencsd-test-"+tc.dirName+"-expected.txt")
				_ = os.WriteFile(debugExpectedFile, []byte(expectedStr), 0644)

				t.Errorf("Output did not match golden file.\nLength Expected: %d\nLength Actual: %d\nSee %s for details.",
					len(expectedStr), len(actualStr), debugFile)
			}
		})
	}
}
