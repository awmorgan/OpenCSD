package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshotDir(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "decoder", "tests", "snapshots", name)
	if _, err := os.Stat(filepath.Join(path, "snapshot.ini")); err != nil {
		t.Skipf("snapshot.ini not found for %s: %v", name, err)
	}
	return path
}

func TestParseSnapshotIni_TraceCovA15(t *testing.T) {
	dir := snapshotDir(t, "trace_cov_a15")
	cfg, err := ParseSnapshotIni(dir)
	if err != nil {
		t.Fatalf("ParseSnapshotIni error: %v", err)
	}
	if cfg.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %q", cfg.Version)
	}
	if cfg.TraceMetadata != "trace.ini" {
		t.Fatalf("expected trace metadata trace.ini, got %q", cfg.TraceMetadata)
	}
	if len(cfg.DeviceList) != 6 {
		t.Fatalf("expected 6 devices, got %d", len(cfg.DeviceList))
	}
}

func TestParseSnapshotIni_TC2(t *testing.T) {
	dir := snapshotDir(t, "TC2")
	cfg, err := ParseSnapshotIni(dir)
	if err != nil {
		t.Fatalf("ParseSnapshotIni error: %v", err)
	}
	if cfg.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %q", cfg.Version)
	}
	if cfg.TraceMetadata != "trace.ini" {
		t.Fatalf("expected trace metadata trace.ini, got %q", cfg.TraceMetadata)
	}
	if len(cfg.DeviceList) != 11 {
		t.Fatalf("expected 11 devices, got %d", len(cfg.DeviceList))
	}
}

func TestParseSnapshotIni_Clusters(t *testing.T) {
	dir := snapshotDir(t, "bugfix-exact-match")
	cfg, err := ParseSnapshotIni(dir)
	if err != nil {
		t.Fatalf("ParseSnapshotIni error: %v", err)
	}
	if len(cfg.Clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(cfg.Clusters))
	}
	cluster0 := cfg.Clusters["Cluster 0"]
	cluster1 := cfg.Clusters["Cluster 1"]
	if len(cluster0) != 2 {
		t.Fatalf("expected 2 devices in Cluster 0, got %d", len(cluster0))
	}
	if len(cluster1) != 4 {
		t.Fatalf("expected 4 devices in Cluster 1, got %d", len(cluster1))
	}
}

func TestParseSnapshotIni_InvalidVersion(t *testing.T) {
	root := t.TempDir()
	ini := strings.Join([]string{
		"[snapshot]",
		"version=0.9",
		"",
		"[device_list]",
		"device0=device0.ini",
		"",
		"[trace]",
		"metadata=trace.ini",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "snapshot.ini"), []byte(ini), 0o644); err != nil {
		t.Fatalf("write snapshot.ini: %v", err)
	}
	_, err := ParseSnapshotIni(root)
	if err == nil {
		t.Fatalf("expected version error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported snapshot.ini version") {
		t.Fatalf("unexpected error: %v", err)
	}
}
