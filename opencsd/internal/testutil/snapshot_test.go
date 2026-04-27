package testutil

import (
	"reflect"
	"strings"
	"testing"
)

func ParseHexOrDecTB(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := parseHexOrDecErr(s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return v
}

func TestParseHexOrDec(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want uint64
	}{
		{name: "empty", in: "", want: 0},
		{name: "decimal", in: "42", want: 42},
		{name: "hex", in: "0x2a", want: 42},
		{name: "spaces", in: " 0x10 ", want: 16},
		{name: "invalid", in: "nope", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseHexOrDec(tt.in); got != tt.want {
				t.Fatalf("ParseHexOrDec(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseHexOrDecTB(t *testing.T) {
	if got := ParseHexOrDecTB(t, "0x2a"); got != 42 {
		t.Fatalf("ParseHexOrDecTB = %d, want 42", got)
	}
}

func TestSanitizePPLSortsFiltersAndNormalizes(t *testing.T) {
	input := strings.Join([]string{
		"snapshot preamble",
		"Idx:2; ID:b;\tFOO: detail Idx:1; ID:a; OCSD_GEN_TRC_ELEM_TRACE_ON()",
		"Idx:1; ID:b;\tBAR: detail",
	}, "\r\n")

	wantAll := strings.Join([]string{
		"Idx:1; ID:a; OCSD_GEN_TRC_ELEM_TRACE_ON()",
		"Idx:1; ID:b;\tBAR",
		"Idx:2; ID:b;\tFOO",
	}, "\n")
	if got := SanitizePPL(input, nil); got != wantAll {
		t.Fatalf("SanitizePPL all mismatch\ngot:  %q\nwant: %q", got, wantAll)
	}

	wantB := strings.Join([]string{
		"Idx:1; ID:b;\tBAR",
		"Idx:2; ID:b;\tFOO",
	}, "\n")
	if got := SanitizePPL(input, []string{" B "}); got != wantB {
		t.Fatalf("SanitizePPL filtered mismatch\ngot:  %q\nwant: %q", got, wantB)
	}
}

func TestSplitIdxRecords(t *testing.T) {
	got := SplitIdxRecords("prefix Idx:2; ID:b; data Idx:1; ID:a; data")
	want := []string{"Idx:2; ID:b; data", "Idx:1; ID:a; data"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitIdxRecords = %#v, want %#v", got, want)
	}

	if got := SplitIdxRecords("no records"); got != nil {
		t.Fatalf("SplitIdxRecords without records = %#v, want nil", got)
	}
}

func TestNormalizeSnapshotLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "generic element", in: "Idx:1; ID:a; OCSD_GEN_TRC_ELEM_TRACE_ON()", want: "Idx:1; ID:a; OCSD_GEN_TRC_ELEM_TRACE_ON()"},
		{name: "packet", in: "Idx:1; ID:a;\tETM_PACKET: payload", want: "Idx:1; ID:a;\tETM_PACKET"},
		{name: "missing tab", in: "Idx:1; ID:a; ETM_PACKET: payload", want: ""},
		{name: "missing packet type", in: "Idx:1; ID:a;\tpayload", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeSnapshotLine(tt.in); got != tt.want {
				t.Fatalf("NormalizeSnapshotLine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExtractLineFields(t *testing.T) {
	line := "Idx:123; ID:Ab; data"
	if got, ok := ExtractLineID(line); !ok || got != "ab" {
		t.Fatalf("ExtractLineID = %q, %v; want ab, true", got, ok)
	}
	if got, ok := ExtractLineIdx(line); !ok || got != 123 {
		t.Fatalf("ExtractLineIdx = %d, %v; want 123, true", got, ok)
	}

	if _, ok := ExtractLineIdx("Idx:not-int; ID:a;"); ok {
		t.Fatal("ExtractLineIdx should reject non-integer index")
	}
}

func TestFirstDiff(t *testing.T) {
	line, got, want := FirstDiff([]string{"same", "got"}, []string{"same", "want"})
	if line != 2 || got != "got" || want != "want" {
		t.Fatalf("FirstDiff = (%d, %q, %q), want (2, got, want)", line, got, want)
	}

	line, got, want = FirstDiff([]string{"same"}, []string{"same", "extra"})
	if line != 2 || got != "" || want != "extra" {
		t.Fatalf("FirstDiff length mismatch = (%d, %q, %q), want (2, empty, extra)", line, got, want)
	}

	line, got, want = FirstDiff([]string{"same"}, []string{"same"})
	if line != 0 || got != "" || want != "" {
		t.Fatalf("FirstDiff equal = (%d, %q, %q), want zero values", line, got, want)
	}
}
