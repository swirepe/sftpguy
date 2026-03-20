package main

import (
	"bufio"
	"io"
)

const longLineScannerMaxTokenSize = 16 * 1024 * 1024

// newLongLineScanner keeps line-oriented reads but tolerates long operator-managed inputs.
func newLongLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), longLineScannerMaxTokenSize)
	return scanner
}
