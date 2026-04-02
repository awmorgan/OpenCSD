package testutil

import "testing"

func ParseHexOrDecTB(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := parseHexOrDecErr(s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return v
}
