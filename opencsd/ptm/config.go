package ptm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	etmcrCycleAccBit = 12
	etmcrRetStackBit = 29
)

// PTMDeviceConfig captures the subset of PTM configuration we need for decoding.
type PTMDeviceConfig struct {
	TraceID uint8
	ETMCR   uint32
}

// Apply applies the device configuration to the decoder.
func (d *Decoder) Apply(cfg PTMDeviceConfig) {
	if cfg.TraceID != 0 {
		d.TraceID = cfg.TraceID
	}
	d.CycleAccEnable = (cfg.ETMCR&(1<<etmcrCycleAccBit) != 0)
	d.RetStackEnable = (cfg.ETMCR&(1<<etmcrRetStackBit) != 0)
}

// ConfigureFromDeviceIni reads a PTM device ini file and applies settings to the decoder.
func (d *Decoder) ConfigureFromDeviceIni(deviceIniPath string) error {
	cfg, err := LoadPTMDeviceConfig(deviceIniPath)
	if err != nil {
		return err
	}
	d.Apply(cfg)
	return nil
}

// ConfigureFromSnapshot looks up the PTM device ini by TraceID and applies its config.
// The decoder TraceID must already be set.
func (d *Decoder) ConfigureFromSnapshot(snapshotDir string) (string, error) {
	if d.TraceID == 0 {
		return "", fmt.Errorf("decoder TraceID is 0; set TraceID before loading snapshot")
	}
	deviceIniPath, cfg, err := FindPTMDeviceIniByTraceID(snapshotDir, d.TraceID)
	if err != nil {
		return "", err
	}
	d.Apply(cfg)
	return deviceIniPath, nil
}

// LoadPTMDeviceConfig parses a PTM device ini file for ETMCR and ETMTRACEIDR values.
func LoadPTMDeviceConfig(deviceIniPath string) (PTMDeviceConfig, error) {
	data, err := os.ReadFile(deviceIniPath)
	if err != nil {
		return PTMDeviceConfig{}, fmt.Errorf("read device ini: %w", err)
	}

	cfg := PTMDeviceConfig{}
	section := ""
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		key, value, ok := splitIniKV(line)
		if !ok {
			continue
		}

		switch section {
		case "regs":
			regName := normalizeRegName(key)
			switch regName {
			case "ETMCR":
				if v, parseErr := parseHexUint32(value); parseErr == nil {
					cfg.ETMCR = v
				}
			case "ETMTRACEIDR":
				if v, parseErr := parseHexUint32(value); parseErr == nil {
					cfg.TraceID = uint8(v & 0xFF)
				}
			}
		}
	}

	if cfg.ETMCR == 0 {
		return PTMDeviceConfig{}, fmt.Errorf("ETMCR not found in %s", deviceIniPath)
	}
	return cfg, nil
}

// FindPTMDeviceIniByTraceID scans snapshot.ini and device ini files for matching trace ID.
func FindPTMDeviceIniByTraceID(snapshotDir string, traceID uint8) (string, PTMDeviceConfig, error) {
	deviceList, err := loadSnapshotDeviceList(snapshotDir)
	if err != nil {
		return "", PTMDeviceConfig{}, err
	}
	for _, deviceIni := range deviceList {
		path := filepath.Join(snapshotDir, deviceIni)
		cfg, err := LoadPTMDeviceConfig(path)
		if err != nil {
			continue
		}
		if cfg.TraceID == traceID {
			return path, cfg, nil
		}
	}
	return "", PTMDeviceConfig{}, fmt.Errorf("no PTM device ini found for trace ID 0x%02X in %s", traceID, snapshotDir)
}

func loadSnapshotDeviceList(snapshotDir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(snapshotDir, "snapshot.ini"))
	if err != nil {
		return nil, fmt.Errorf("read snapshot.ini: %w", err)
	}
	section := ""
	var devices []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		if section != "device_list" {
			continue
		}
		_, value, ok := splitIniKV(line)
		if !ok {
			continue
		}
		devices = append(devices, value)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no devices found in snapshot.ini")
	}
	return devices, nil
}

func splitIniKV(line string) (string, string, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func normalizeRegName(key string) string {
	if idx := strings.Index(key, "("); idx >= 0 {
		key = key[:idx]
	}
	return strings.TrimSpace(key)
}

func parseHexUint32(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return 0, fmt.Errorf("empty value")
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}
