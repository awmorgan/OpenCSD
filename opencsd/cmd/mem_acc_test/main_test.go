package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMemAccOutputMatchesCpp(t *testing.T) {
	// Run Go version
	goCmd := exec.Command("go", "run", ".")
	var goOut bytes.Buffer
	var goErr bytes.Buffer
	goCmd.Stdout = &goOut
	goCmd.Stderr = &goErr
	
	if err := goCmd.Run(); err != nil {
		t.Fatalf("Go mem_acc_test failed: %v\nStderr: %s", err, goErr.String())
	}

	// Find C++ executable
	_, filename, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	cppExe := filepath.Join(repoRoot, "decoder", "tests", "bin", "builddir", "mem-acc-test")
	if runtime.GOOS == "windows" {
		cppExe += ".exe"
	}

	// Run C++ version
	cppCmd := exec.Command(cppExe)
	var cppOut bytes.Buffer
	var cppErr bytes.Buffer
	cppCmd.Stdout = &cppOut
	cppCmd.Stderr = &cppErr
	
	if err := cppCmd.Run(); err != nil {
		t.Fatalf("C++ mem-acc-test failed: %v\nStderr: %s", err, cppErr.String())
	}

	// Normalize outputs for comparison (handle line ending differences)
	goOutput := normalizeOutput(goOut.String())
	cppOutput := normalizeOutput(cppOut.String())

	// Compare key metrics
	goLines := strings.Split(goOutput, "\n")
	cppLines := strings.Split(cppOutput, "\n")

	// Extract and compare summary lines
	goSummary := extractSummary(goLines)
	cppSummary := extractSummary(cppLines)

	if goSummary["total"] != cppSummary["total"] {
		t.Errorf("Total test count mismatch: Go=%s, C++=%s", goSummary["total"], cppSummary["total"])
	}
	if goSummary["passed"] != cppSummary["passed"] {
		t.Errorf("Passed test count mismatch: Go=%s, C++=%s", goSummary["passed"], cppSummary["passed"])
	}
	if goSummary["failed"] != cppSummary["failed"] {
		t.Errorf("Failed test count mismatch: Go=%s, C++=%s", goSummary["failed"], cppSummary["failed"])
	}

	// Verify both have zero failures
	if goSummary["failed"] != "0" {
		t.Errorf("Go version has failures: %s", goSummary["failed"])
	}
	if cppSummary["failed"] != "0" {
		t.Errorf("C++ version has failures: %s", cppSummary["failed"])
	}

	// Verify test breakdown matches
	goTestBreakdown := extractTestBreakdown(goLines)
	cppTestBreakdown := extractTestBreakdown(cppLines)

	for testName, goCounts := range goTestBreakdown {
		cppCounts, exists := cppTestBreakdown[testName]
		if !exists {
			t.Errorf("Test %s exists in Go but not in C++", testName)
			continue
		}
		if goCounts != cppCounts {
			t.Errorf("Test %s: Go=%s, C++=%s", testName, goCounts, cppCounts)
		}
	}

	t.Logf("✓ Go and C++ outputs match: %s passed, %s failed", goSummary["passed"], goSummary["failed"])
}

func normalizeOutput(s string) string {
	// Normalize line endings
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// Remove trailing whitespace from lines
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

func extractSummary(lines []string) map[string]string {
	result := map[string]string{
		"passed": "0",
		"failed": "0",
		"total":  "0",
	}

	for _, line := range lines {
		// Look for "Passed: 81; Failed: 0"
		if strings.HasPrefix(line, "Passed:") {
			parts := strings.Split(line, ";")
			if len(parts) >= 2 {
				// Extract passed count
				passedPart := strings.TrimSpace(parts[0])
				passedPart = strings.TrimPrefix(passedPart, "Passed:")
				result["passed"] = strings.TrimSpace(passedPart)

				// Extract failed count
				failedPart := strings.TrimSpace(parts[1])
				failedPart = strings.TrimPrefix(failedPart, "Failed:")
				result["failed"] = strings.TrimSpace(failedPart)
			}
		}
	}

	return result
}

func extractTestBreakdown(lines []string) map[string]string {
	result := make(map[string]string)

	for _, line := range lines {
		// Look for "*** Test test_name complete. (Pass: 5; Fail:0)"
		if strings.HasPrefix(line, "*** Test ") && strings.Contains(line, "complete.") {
			parts := strings.Split(line, " ")
			if len(parts) >= 4 {
				testName := parts[2]
				// Extract the (Pass: X; Fail:Y) part
				startIdx := strings.Index(line, "(Pass:")
				endIdx := strings.Index(line, ")")
				if startIdx != -1 && endIdx != -1 {
					counts := line[startIdx : endIdx+1]
					result[testName] = counts
				}
			}
		}
	}

	return result
}
