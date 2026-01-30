package helpers

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// PPLElement represents a single decoded element from a PPL file
type PPLElement struct {
	Index   string // The file offset index string (e.g., "0", "26571")
	ID      string // The trace ID string
	Type    string // The element type (e.g., "OCSD_GEN_TRC_ELEM_PE_CONTEXT")
	Content string // The full text content of the element description
}

// LoadPPLoadExpectedElements parses a .ppl file and returns a slice of expect elements
func LoadExpectedElements(path string) ([]PPLElement, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var elements []PPLElement
	scanner := bufio.NewScanner(file)

	// Regex to match element lines
	// Example: Idx:6; ID:2; OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=A32) S; 32-bit; )
	re := regexp.MustCompile(`^Idx:(\d+); ID:(\d+); (OCSD_GEN_TRC_ELEM_\w+)\((.*)\)\s*$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := re.FindStringSubmatch(line)
		if len(matches) == 5 {
			elem := PPLElement{
				Index:   matches[1],
				ID:      matches[2],
				Type:    matches[3],
				Content: matches[4],
			}
			elements = append(elements, elem)
		}
	}

	return elements, scanner.Err()
}
