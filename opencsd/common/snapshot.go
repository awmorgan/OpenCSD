package common

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SnapshotConfig represents the parsed snapshot.ini contents.
type SnapshotConfig struct {
	Version       string
	Description   string
	DeviceList    []string
	TraceMetadata string
	Clusters      map[string][]string
}

// ParseSnapshotIni parses snapshot.ini from a snapshot directory.
// It follows the ARM Debug and Trace Snapshot File Format v0.2 specification.
func ParseSnapshotIni(snapshotDir string) (SnapshotConfig, error) {
	path := filepath.Join(snapshotDir, "snapshot.ini")
	file, err := os.Open(path)
	if err != nil {
		return SnapshotConfig{}, fmt.Errorf("read snapshot.ini: %w", err)
	}
	defer file.Close()

	cfg := SnapshotConfig{Clusters: map[string][]string{}}
	section := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := stripIniComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.Trim(line, "[]")))
			continue
		}

		key, value, ok := splitIniKV(line)
		if !ok {
			continue
		}

		switch section {
		case "snapshot":
			switch strings.ToLower(key) {
			case "version":
				cfg.Version = value
			case "description":
				cfg.Description = value
			}
		case "device_list":
			cfg.DeviceList = append(cfg.DeviceList, value)
		case "clusters":
			cfg.Clusters[key] = splitCommaList(value)
		case "trace":
			if strings.EqualFold(key, "metadata") {
				cfg.TraceMetadata = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return SnapshotConfig{}, fmt.Errorf("read snapshot.ini: %w", err)
	}

	if cfg.Version == "" {
		return SnapshotConfig{}, fmt.Errorf("snapshot.ini missing [snapshot]/version")
	}
	if cfg.Version != "1.0" {
		return SnapshotConfig{}, fmt.Errorf("unsupported snapshot.ini version %q", cfg.Version)
	}
	if len(cfg.DeviceList) == 0 {
		return SnapshotConfig{}, fmt.Errorf("no devices found in snapshot.ini")
	}
	return cfg, nil
}

func splitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
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

func stripIniComment(line string) string {
	// Comments start with ';' or '#' anywhere on the line.
	if idx := strings.IndexAny(line, ";#"); idx >= 0 {
		return line[:idx]
	}
	return line
}
