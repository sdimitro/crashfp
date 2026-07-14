// SPDX-License-Identifier: MIT

package dmesgcrash

import (
	"regexp"
	"strings"
	"unsafe"

	"github.com/sdimitro/crashfp/fingerprint"
)

// Crash holds crash details recovered from the kernel printk ring buffer.
// The kernel symbolizes its own backtrace via kallsyms when it panics, so
// none of these fields require DWARF debug symbols.
type Crash struct {
	PanicMessage string
	StackTrace   []string // kernel backtrace frames, fault frame first
	Modules      []string
	Banner       string
	Cmdline      string
}

// crashKeywords mark the start of a kernel crash report in the log,
// including the arm64-specific "Unable to handle kernel …" /
// "Internal error: Oops …" spellings.
var crashKeywords = []string{
	"BUG: soft lockup",
	"BUG: kernel NULL pointer",
	"BUG: unable to handle",
	"Unable to handle kernel",
	"general protection fault",
	"Internal error: Oops",
	"Oops:",
	"kernel BUG at",
	"Kernel panic",
	"watchdog: BUG:",
}

var (
	// prefixPattern strips the leading "[ 1234.5] [ T99] " timestamp
	// and caller-id brackets that makedumpfile --dump-dmesg emits.
	prefixPattern = regexp.MustCompile(`^(?:\s*\[[^\]]*\])+\s*`)

	// faultPCPattern captures the faulting instruction's symbol frame from
	// the register dump: arm64 "pc : <sym>+0x.." or x86 "RIP: 0010:<sym>+0x..".
	faultPCPattern = regexp.MustCompile(
		`^(?:RIP:\s*\S+:\s*|pc\s*:\s*)([A-Za-z_][A-Za-z0-9_.]*\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?(?:\s*\[[^\]]+\])?)`,
	)
	// faultLRPattern is used as a fallback for arm64 indirect-call crashes
	// where the PC is an unsymbolizable address such as "pc : 0x0". The LR
	// still names the caller that invoked the bad function pointer.
	faultLRPattern = regexp.MustCompile(
		`^lr\s*:\s*([A-Za-z_][A-Za-z0-9_.]*\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?(?:\s*\[[^\]]+\])?)`,
	)
	addressOnlyFramePattern = regexp.MustCompile(`^0x[0-9a-fA-F]+(?:\s+\([^)]*\))?$`)

	// headerFieldPattern matches the "Key:" lines that follow a Modules
	// line in an Oops report, used to bound the (wrapped) module list.
	headerFieldPattern = regexp.MustCompile(`^(CPU|Hardware name|Tainted|pstate|RIP|Code|pc|lr|sp)\b`)
)

// ParseBytes is Parse for callers that read the log into a []byte (e.g.
// os.ReadFile). It avoids the string conversion copy — for a
// multi-megabyte log that copy is the single largest allocation after
// the read itself. The caller must not modify b afterwards.
func ParseBytes(b []byte) *Crash {
	return Parse(unsafe.String(unsafe.SliceData(b), len(b)))
}

// Parse parses kernel log text recovered from a vmcore (or captured live)
// into a crash report. It returns nil if the log contains neither a crash
// report nor a kernel banner/command line worth surfacing.
//
// Memory: the log is scanned by byte offset without splitting it into a
// full line slice, and only the bounded crash region (~200 lines) is
// materialized, so peak usage stays at the input plus a small constant —
// this runs in a crash kernel where every megabyte of RAM counts.
func Parse(raw string) *Crash {
	c := &Crash{}

	// Banner and command line appear near the top of the boot log.
	// Allocation-free top-down scan, stopping once both are found.
	for off := 0; off < len(raw); {
		line, next := nextLine(raw, off)
		l := StripPrefix(line)
		if c.Banner == "" && strings.HasPrefix(l, "Linux version ") {
			c.Banner = l
		}
		if c.Cmdline == "" && strings.HasPrefix(l, "Kernel command line: ") {
			c.Cmdline = strings.TrimPrefix(l, "Kernel command line: ")
		}
		if c.Banner != "" && c.Cmdline != "" {
			break
		}
		off = next
	}

	// Anchor on the last crash report in the log: bottom-up scan for the
	// byte offset of the last line containing a crash keyword. (Keywords
	// cannot occur inside the "[ts] [Tn]" prefix, so matching the raw
	// line is equivalent to matching the stripped line.)
	last := -1
	for end := len(raw); end >= 0; {
		start := strings.LastIndexByte(raw[:max(end, 0)], '\n') + 1
		if hasCrashKeyword(raw[start:max(end, 0)]) {
			last = start
			break
		}
		end = start - 1
	}
	if last < 0 {
		if c.Banner == "" && c.Cmdline == "" {
			return nil
		}
		return c
	}

	// Walk back to the earliest keyword in the preceding 60-line window
	// so multi-line reports (e.g. "Unable to handle…" followed by
	// "Internal error: Oops…") start at the top.
	first := last
	for i, start := 0, last; i < 60 && start > 0; i++ {
		prev := strings.LastIndexByte(raw[:start-1], '\n') + 1
		if hasCrashKeyword(raw[prev : start-1]) {
			first = prev
		}
		start = prev
	}

	// The region spans from 2 lines above the report to 200 lines below
	// it. Split only the tail from the region start — for a crash at the
	// end of a large log (the kdump case) this materializes a couple
	// hundred line headers instead of the whole log's worth.
	regionStart := first
	firstIdx := 0
	for i := 0; i < 2 && regionStart > 0; i++ {
		regionStart = strings.LastIndexByte(raw[:regionStart-1], '\n') + 1
		firstIdx++
	}
	lines := strings.Split(raw[regionStart:], "\n")
	end := firstIdx + 200
	if end > len(lines) {
		end = len(lines)
	}
	region := lines[:end]
	for i, l := range region {
		region[i] = StripPrefix(l)
	}

	c.PanicMessage = buildPanicMessage(region)
	c.Modules = parseModules(region)
	c.StackTrace = parseBacktrace(region)

	return c.cloned()
}

// nextLine returns the line starting at off (newline excluded) and the
// offset of the following line.
func nextLine(raw string, off int) (line string, next int) {
	if i := strings.IndexByte(raw[off:], '\n'); i >= 0 {
		return raw[off : off+i], off + i + 1
	}
	return raw[off:], len(raw)
}

// cloned copies every retained string out of the raw log's backing
// array. Parsing works on zero-copy substrings of the (possibly huge)
// input; without this, the small returned Crash would pin the entire
// log in memory for as long as the caller holds it.
func (c *Crash) cloned() *Crash {
	c.Banner = strings.Clone(c.Banner)
	c.Cmdline = strings.Clone(c.Cmdline)
	// strings.Join of a single element returns it uncopied, so even the
	// joined panic message can alias the input.
	c.PanicMessage = strings.Clone(c.PanicMessage)
	for i, f := range c.StackTrace {
		c.StackTrace[i] = strings.Clone(f)
	}
	for i, m := range c.Modules {
		c.Modules[i] = strings.Clone(m)
	}
	return c
}

// StripPrefix removes the leading kernel-log timestamp/caller-id
// brackets, e.g. "[ 2855.21] [ T131119] Internal error" → "Internal error".
//
// It returns a substring of line rather than a copy: the pattern is
// ^-anchored, so slicing off the single match is equivalent to
// ReplaceAllString but allocation-free — this dominates peak memory when
// parsing multi-megabyte logs, where every line goes through it.
func StripPrefix(line string) string {
	if loc := prefixPattern.FindStringIndex(line); loc != nil {
		line = line[loc[1]:]
	}
	return strings.TrimSpace(line)
}

func hasCrashKeyword(s string) bool {
	for _, kw := range crashKeywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isBacktraceHeader(l string) bool {
	return strings.HasPrefix(l, "Call Trace") || strings.HasPrefix(l, "Call trace")
}

// buildPanicMessage collects the crash report lines from the first crash
// keyword up to (but not including) the backtrace, capped for readability.
// The backtrace frames are surfaced separately as the stack trace.
func buildPanicMessage(region []string) string {
	var out []string
	started := false
	for _, l := range region {
		if !started {
			if !hasCrashKeyword(l) {
				continue
			}
			started = true
		}
		if isBacktraceHeader(l) {
			break
		}
		out = append(out, l)
		if len(out) >= 60 {
			break
		}
	}
	return strings.Join(out, "\n")
}

// parseModules extracts the loaded-module names from the "Modules linked
// in:" line and its wrapped continuation lines. Taint suffixes such as
// "(OE)" are stripped so names match debugger-derived module lists.
func parseModules(region []string) []string {
	const marker = "Modules linked in:"
	idx := -1
	for i, l := range region {
		if strings.HasPrefix(l, marker) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}

	text := strings.TrimSpace(strings.TrimPrefix(region[idx], marker))
	for i := idx + 1; i < len(region); i++ {
		l := region[i]
		if l == "" || headerFieldPattern.MatchString(l) || isBacktraceHeader(l) {
			break
		}
		if _, ok := fingerprint.ParseKernelBacktraceFrame(l); ok {
			break
		}
		text += " " + l
	}

	var mods []string
	for _, tok := range strings.Fields(text) {
		// "[last unloaded: …]" trails the list; stop there.
		if strings.HasPrefix(tok, "[") {
			break
		}
		if p := strings.IndexByte(tok, '('); p >= 0 {
			tok = tok[:p]
		}
		if tok != "" {
			mods = append(mods, tok)
		}
	}
	return mods
}

// parseBacktrace extracts the kernel backtrace frames from the crash
// region, ensuring the faulting function (from the PC/RIP register line)
// is the first frame. Section markers and unreliable "?" frames are
// dropped; the list ends at the first non-frame line after the header.
func parseBacktrace(region []string) []string {
	pcFrame := ""
	lrFrame := ""
	for _, l := range region {
		if m := faultPCPattern.FindStringSubmatch(l); m != nil {
			pcFrame = strings.TrimSpace(m[1])
		}
		if m := faultLRPattern.FindStringSubmatch(l); m != nil {
			lrFrame = strings.TrimSpace(m[1])
		}
	}
	if pcFrame == "" {
		pcFrame = lrFrame
	}

	var frames []string
	inTrace := false
	for _, l := range region {
		if !inTrace {
			if isBacktraceHeader(l) {
				inTrace = true
			}
			continue
		}
		if l == "" {
			break
		}
		switch l {
		case "<TASK>", "</TASK>", "<IRQ>", "</IRQ>", "<NMI>", "</NMI>":
			continue
		}
		if strings.HasPrefix(l, "?") {
			continue
		}
		if addressOnlyFramePattern.MatchString(l) {
			continue
		}
		if _, ok := fingerprint.ParseKernelBacktraceFrame(l); !ok {
			break
		}
		frames = append(frames, l)
	}

	if pcFrame != "" {
		pcFunc, _ := fingerprint.ParseKernelBacktraceFrame(pcFrame)
		if len(frames) == 0 {
			frames = []string{pcFrame}
		} else if topFunc, _ := fingerprint.ParseKernelBacktraceFrame(frames[0]); topFunc != pcFunc {
			frames = append([]string{pcFrame}, frames...)
		}
	}

	return frames
}
