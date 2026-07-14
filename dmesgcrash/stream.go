// SPDX-License-Identifier: MIT

package dmesgcrash

import (
	"bufio"
	"io"
	"strings"
	"unsafe"
)

// lookbackLines is the streaming window: the 60-line keyword walk-back
// plus the 2 region lines kept above the crash report, matching Parse.
const lookbackLines = 62

// ParseReader parses a kernel log line by line with bounded memory: a
// 62-line ring buffer plus the bounded ~202-line crash region, instead
// of holding the whole log. Peak memory stays constant regardless of
// input size (measured: <1 MB under TinyGo for a 32 MiB log, vs. input
// size + ~1 MB for Parse/ParseBytes), at the cost of streaming I/O.
//
// The result is identical to Parse on the same bytes; the
// TestParseReaderMatchesParse equivalence suite enforces this.
//
// It returns an error only when reading fails (or a line exceeds 1 MiB,
// which no kernel emits); callers in fail-open contexts should treat
// that like any unreadable input.
func ParseReader(r io.Reader) (*Crash, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	c := &Crash{}
	var (
		ring     [lookbackLines]string // cloned stripped lines, ring[n%62]
		lineNo   int
		kwLines  []int    // line numbers of recent keyword sightings
		capFirst = -1     // "first" anchor line of the active capture
		capStart = -1     // line number of capLines[0]
		capLines []string // cloned stripped region lines
		sawCrash bool
	)

	for sc.Scan() {
		b := sc.Bytes()
		// Zero-copy view for inspection; only cloned strings are kept
		// past this iteration, and the scanner reuses its buffer.
		raw := unsafe.String(unsafe.SliceData(b), len(b))
		stripped := StripPrefix(raw)

		if c.Banner == "" && strings.HasPrefix(stripped, "Linux version ") {
			c.Banner = strings.Clone(stripped)
		}
		if c.Cmdline == "" && strings.HasPrefix(stripped, "Kernel command line: ") {
			c.Cmdline = strings.Clone(strings.TrimPrefix(stripped, "Kernel command line: "))
		}

		var clone string // lazily cloned; shared by capture + ring
		cloned := func() string {
			if clone == "" && stripped != "" {
				clone = strings.Clone(stripped)
			}
			return clone
		}

		if hasCrashKeyword(stripped) {
			sawCrash = true
			// Mirror Parse: the report is anchored on the *last* keyword
			// in the log, then walks back to the earliest keyword within
			// the preceding 60 lines. Streaming equivalent: recompute
			// the anchor at every sighting; the final one wins.
			kwLines = append(kwLines, lineNo)
			first := lineNo
			for _, k := range kwLines {
				if k >= lineNo-60 && k < first {
					first = k
				}
			}
			// Sightings older than the walk-back window cannot matter
			// for any future keyword either.
			for len(kwLines) > 0 && kwLines[0] < lineNo-60 {
				kwLines = kwLines[1:]
			}
			if first != capFirst {
				// (Re)start the capture, seeding lines first-2..lineNo-1
				// from the ring. All are within the 62-line window.
				capFirst = first
				capStart = first - 2
				if capStart < 0 {
					capStart = 0
				}
				capLines = capLines[:0]
				for ln := capStart; ln < lineNo; ln++ {
					capLines = append(capLines, ring[ln%lookbackLines])
				}
			}
		}

		// The region spans capStart..capFirst+200 (exclusive), exactly
		// like Parse; the contiguity check stops the capture once full.
		if capFirst >= 0 && lineNo < capFirst+200 && len(capLines) == lineNo-capStart {
			capLines = append(capLines, cloned())
		}

		ring[lineNo%lookbackLines] = cloned()
		lineNo++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if !sawCrash {
		if c.Banner == "" && c.Cmdline == "" {
			return nil, nil
		}
		return c, nil
	}

	c.PanicMessage = buildPanicMessage(capLines)
	c.Modules = parseModules(capLines)
	c.StackTrace = parseBacktrace(capLines)
	return c, nil
}
