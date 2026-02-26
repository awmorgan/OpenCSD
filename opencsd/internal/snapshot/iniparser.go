package snapshot

import (
	"bufio"
	"io"
	"strings"
)

// IniFile represents a parsed INI file.
// It maps section names to a map of key-value pairs.
// Global properties (before any section) are stored in the "" (empty string) section.
type IniFile struct {
	Sections map[string]map[string]string
}

// NewIniFile creates a new empty IniFile
func NewIniFile() *IniFile {
	return &IniFile{
		Sections: make(map[string]map[string]string),
	}
}

// ParseIni reads an INI file from an io.Reader and returns an IniFile.
func ParseIni(r io.Reader) *IniFile {
	ini := NewIniFile()
	scanner := bufio.NewScanner(r)
	currentSection := ""
	ini.Sections[currentSection] = make(map[string]string)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Ignore empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sectionName := strings.TrimSpace(line[1 : len(line)-1])
			// Some section names might have extra spaces, so we trim them
			// Section names are kept case-sensitive, although typically lowercase in OpenCSD
			currentSection = sectionName
			if _, exists := ini.Sections[currentSection]; !exists {
				ini.Sections[currentSection] = make(map[string]string)
			}
			continue
		}

		// Check for key-value pair
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// OpenCSD C++ trims trailing comments? The original code splits by `=` then trims.
			// Values might have inline comments? Usually no inline comments in OpenCSD snapshot ini.
			// However let's just strip surrounding quotes if any exist (though OpenCSD usually doesn't need it).

			ini.Sections[currentSection][key] = val
		}
	}

	return ini
}

// GetSection returns the key-value map for a given section, or nil if not found
func (ini *IniFile) GetSection(sectionName string) map[string]string {
	return ini.Sections[sectionName]
}
