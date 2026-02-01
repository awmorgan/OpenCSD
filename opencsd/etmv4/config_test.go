package etmv4

import (
	"os"
	"path/filepath"
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

func TestLoadConfig_ETM4(t *testing.T) {
	snapshot := snapshotDir(t, "juno-ret-stck")
	deviceIni := filepath.Join(snapshot, "device_9.ini")

	cfg, err := LoadConfig(deviceIni)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.RegTRACEIDR != 0x13 {
		t.Fatalf("expected trace ID 0x13, got 0x%X", cfg.RegTRACEIDR)
	}
	if cfg.RegCONFIGR != 0x000010C1 {
		t.Fatalf("expected CONFIGR 0x000010C1, got 0x%X", cfg.RegCONFIGR)
	}
	if cfg.RegIDR0 != 0x28000EA1 {
		t.Fatalf("expected IDR0 0x28000EA1, got 0x%X", cfg.RegIDR0)
	}
}

func TestFindDeviceIniByTraceID(t *testing.T) {
	snapshot := snapshotDir(t, "juno-ret-stck")
	path, cfg, err := FindDeviceIniByTraceID(snapshot, 0x13)
	if err != nil {
		t.Fatalf("FindDeviceIniByTraceID error: %v", err)
	}
	if filepath.Base(path) != "device_9.ini" {
		t.Fatalf("expected device_9.ini, got %s", filepath.Base(path))
	}
	if cfg.RegTRACEIDR != 0x13 {
		t.Fatalf("expected trace ID 0x13, got 0x%X", cfg.RegTRACEIDR)
	}
}
