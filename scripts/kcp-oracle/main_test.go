package main

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestScriptScannerReportsAnOversizedLine(t *testing.T) {
	for _, delim := range []string{"\n", "\r\n"} {
		sc := scriptScanner(strings.NewReader(strings.Repeat("a", scriptLimit+1) + delim))
		if sc.Scan() {
			t.Fatalf("scanned an oversized line ending in %q", delim)
		}
		if !errors.Is(sc.Err(), bufio.ErrTooLong) {
			t.Fatalf("oversized line ending in %q: error = %v, want %v", delim, sc.Err(), bufio.ErrTooLong)
		}
	}
}

func TestScriptScannerReadsALineAtTheLimit(t *testing.T) {
	line := strings.Repeat("a", scriptLimit)
	for _, delim := range []string{"\n", "\r\n"} {
		sc := scriptScanner(strings.NewReader(line + delim))
		if !sc.Scan() {
			t.Fatalf("a line at the limit ending in %q failed: %v", delim, sc.Err())
		}
		if sc.Text() != line {
			t.Fatalf("the line ending in %q changed", delim)
		}
	}
}
