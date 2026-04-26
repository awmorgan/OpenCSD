package snapshot

import (
	"bufio"
	"io"
	"strings"
	"unicode"
)

type IniFile struct {
	Sections     map[string]map[string]string
	SectionVals  map[string]map[string][]string
	SectionOrder []string
}

func NewIniFile() *IniFile {
	return &IniFile{
		Sections:     make(map[string]map[string]string),
		SectionVals:  make(map[string]map[string][]string),
		SectionOrder: []string{},
	}
}

func (ini *IniFile) Section(sectionName string) map[string]string {
	return ini.Sections[sectionName]
}

func ParseIni(r io.Reader) *IniFile {
	ini := NewIniFile()
	scanner := bufio.NewScanner(r)
	section := ""

	ini.Sections[section] = make(map[string]string)
	ini.SectionVals[section] = make(map[string][]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, exists := ini.Sections[section]; !exists {
				ini.Sections[section] = make(map[string]string)
				ini.SectionVals[section] = make(map[string][]string)
				ini.SectionOrder = append(ini.SectionOrder, section)
			}
			continue
		}

		if key, val, found := strings.Cut(line, "="); found {
			k := strings.TrimSpace(key)
			v := strings.TrimSpace(stripInlineComment(val))

			ini.SectionVals[section][k] = append(ini.SectionVals[section][k], v)
			ini.Sections[section][k] = strings.Join(ini.SectionVals[section][k], ",")
		}
	}
	return ini
}

func stripInlineComment(value string) string {
	chars := []rune(value)
	inSingleQuote := false
	inDoubleQuote := false

	for i, ch := range chars {
		switch ch {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case ';', '#':
			if inSingleQuote || inDoubleQuote {
				continue
			}
			if i == 0 {
				return ""
			}
			prev := chars[i-1]
			if unicode.IsSpace(prev) {
				return string(chars[:i])
			}
		}
	}
	return value
}
