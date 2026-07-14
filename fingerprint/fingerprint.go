// SPDX-License-Identifier: MIT

package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Fingerprint holds all computed deduplication hashes for a crash.
type Fingerprint struct {
	RIP     string `json:"rip"`
	Top3    string `json:"top3"`
	Top5    string `json:"top5"`
	Full    string `json:"full"`
	TypeRIP string `json:"type_rip"`

	Inputs FingerprintInputs `json:"inputs"`
}

// FingerprintInputs records what went into each hash for transparency
// and debuggability.
type FingerprintInputs struct {
	FaultFunc  string   `json:"fault_func"`
	CrashType  string   `json:"crash_type"`
	Top3Funcs  []string `json:"top3_funcs"`
	Top5Funcs  []string `json:"top5_funcs"`
	AllFuncs   []string `json:"all_funcs"`
	FrameCount int      `json:"frame_count"`
	Filtered   int      `json:"filtered_infra_frames"`
}

// Frame is a parsed representation of a single drgn stack trace entry.
type Frame struct {
	Index    int
	Address  string
	Symbol   string // ELF symbol (e.g. "io_idle")
	Function string // Source-level function (e.g. "constant_test_bit")
	Source   string // Source file path
	Line     int
	Inlined  bool
}

// InfraFunctions is the set of kernel exception-dispatch, syscall-entry,
// and scheduling functions filtered out before fingerprinting, covering
// both x86 and arm64 entry paths. These are plumbing frames that appear in
// every crash of the same type regardless of root cause.
var InfraFunctions = map[string]bool{
	"show_regs":                     true,
	"__die":                         true,
	"die":                           true,
	"oops_end":                      true,
	"oops_begin":                    true,
	"do_exit":                       true,
	"page_fault_oops":               true,
	"do_page_fault":                 true,
	"exc_page_fault":                true,
	"asm_exc_page_fault":            true,
	"kernelmode_fixup_or_oops":      true,
	"__bad_area_nosemaphore":        true,
	"bad_area_nosemaphore":          true,
	"do_kern_addr_fault":            true,
	"search_exception_tables":       true,
	"do_general_protection":         true,
	"exc_general_protection":        true,
	"asm_exc_general_protection":    true,
	"do_trap":                       true,
	"do_error_trap":                 true,
	"exc_invalid_op":                true,
	"asm_exc_invalid_op":            true,
	"__softirq_entry":               true,
	"__do_softirq":                  true,
	"do_softirq_own_stack":          true,
	"__schedule":                    true,
	"schedule":                      true,
	"schedule_timeout":              true,
	"ret_from_fork":                 true,
	"entry_SYSCALL_64":              true,
	"do_syscall_64":                 true,
	"sugov_update_single_freq":      true,
	"sched_clock":                   true,
	"handle_bug":                    true,
	"__warn":                        true,
	"warn_slowpath_fmt":             true,
	"panic":                         true,
	"nmi_panic":                     true,
	"watchdog_overflow_callback":    true,
	"__lockup_detector_reconfigure": true,

	// arm64 exception vectors and handlers (entry-common.c).
	"el1h_64_sync":         true,
	"el1h_64_sync_handler": true,
	"el1h_64_irq":          true,
	"el1h_64_irq_handler":  true,
	"el1t_64_sync_handler": true,
	"el1t_64_irq_handler":  true,
	"el0t_64_sync":         true,
	"el0t_64_sync_handler": true,
	"el0t_64_irq":          true,
	"el0t_64_irq_handler":  true,
	"el1_abort":            true,
	"el1_sync":             true,
	"el1_irq":              true,
	"el0_sync":             true,
	"el0_irq":              true,
	// arm64 fault / abort dispatch (mm/fault.c); do_page_fault is shared
	// with x86 above.
	"do_mem_abort":         true,
	"do_sp_pc_abort":       true,
	"do_translation_fault": true,
	"do_bad_area":          true,
	"__do_kernel_fault":    true,
	"die_kernel_fault":     true,
	"do_sea":               true,
	"do_alignment_fault":   true,
	"arm64_notify_die":     true,
	"arm64_serror_panic":   true,
	// arm64 trap / undefined-instruction and debug handling (traps.c).
	"do_undefinstr":      true,
	"do_el0_undef":       true,
	"do_el1_undef":       true,
	"bug_handler":        true,
	"do_debug_exception": true,
	// arm64 syscall dispatch (syscall.c).
	"el0_svc":        true,
	"el0_svc_common": true,
	"do_el0_svc":     true,
	"invoke_syscall": true,
}

// framePattern matches drgn stack trace lines such as:
//
//	#0 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in constant_test_bit at ./arch/x86/include/asm/bitops.h:207:8 (inlined)
//	#12 at 0xffffffff9e200275 (secondary_startup_64+0x195/0x195) at arch/x86/kernel/head_64.S:457
var framePattern = regexp.MustCompile(
	`^#(\d+)\s+at\s+(0x[0-9a-fA-F]+)\s+` + // #N at 0xADDR
		`\(([^+]+)\+[^)]+\)` + // (symbol+offset/size)
		`(?:\s+in\s+(\S+))?\s+at\s+` + // optional: in function at
		`([^:]+):(\d+)` + // source:line
		`(?::(\d+))?` + // optional :col
		`(?:\s+\(inlined\))?$`, // optional (inlined)
)

// ParseFrame parses a single drgn stack trace line into a Frame.
// Returns nil if the line doesn't match the expected format.
func ParseFrame(line string) *Frame {
	line = strings.TrimSpace(line)
	m := framePattern.FindStringSubmatch(line)
	if m == nil {
		return nil
	}

	idx, _ := strconv.Atoi(m[1])
	lineNum, _ := strconv.Atoi(m[6])

	f := &Frame{
		Index:   idx,
		Address: m[2],
		Symbol:  m[3],
		Source:  m[5],
		Line:    lineNum,
		Inlined: strings.HasSuffix(line, "(inlined)"),
	}

	if m[4] != "" {
		f.Function = m[4]
	} else {
		f.Function = m[3]
	}

	return f
}

// Compute produces all five fingerprint hashes from a drgn stack trace
// and a panic message. The stack trace entries must be in the format
// produced by drgn's stack_trace() rendering (see ParseFrame).
//
// Returns nil if the stack trace is empty.
func Compute(stackTrace []string, panicMessage string) *Fingerprint {
	if len(stackTrace) == 0 {
		return nil
	}

	frames := make([]rawFrame, 0, len(stackTrace))
	for _, line := range stackTrace {
		if f := ParseFrame(line); f != nil {
			frames = append(frames, rawFrame{
				name:    f.Function,
				altName: f.Symbol,
				inlined: f.Inlined,
			})
		}
	}
	if len(frames) == 0 {
		return nil
	}

	return fingerprintFromFrames(frames, panicMessage)
}

// ComputeFromKernelBacktrace produces the same fingerprint hashes as
// Compute, but from the kernel's own backtrace as printed into the printk
// ring buffer (the "Call Trace:"/"Call trace:" section, recovered with
// makedumpfile --dump-dmesg or vmcore-dmesg). This is the fallback used
// when DWARF debug symbols are unavailable, so drgn cannot produce a
// symbolized trace.
//
// Each frame is a raw kernel backtrace line, fault frame first, e.g.:
//
//	kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia]
//	do_user_addr_fault+0x1d2/0x6a0
//
// The names the kernel prints come from kallsyms (the ELF symbol table),
// which line up with the symbols drgn reports for non-inlined frames, so
// fingerprints from the two paths are comparable for the same crash.
//
// Returns nil if no frames parse.
func ComputeFromKernelBacktrace(frames []string, panicMessage string) *Fingerprint {
	parsed := make([]rawFrame, 0, len(frames))
	for _, line := range frames {
		if fn, ok := ParseKernelBacktraceFrame(line); ok {
			parsed = append(parsed, rawFrame{name: fn, altName: fn})
		}
	}
	if len(parsed) == 0 {
		return nil
	}

	return fingerprintFromFrames(parsed, panicMessage)
}

// rawFrame is a parsed stack frame fed into the shared fingerprint
// pipeline. name is the function used for hashing — drgn's source-level
// function, or the kallsyms symbol for the kernel-log path. altName is a
// second name also checked against InfraFunctions (drgn's ELF symbol); it
// equals name when a source carries only one. Inlined frames are dropped.
type rawFrame struct {
	name    string
	altName string
	inlined bool
}

// fingerprintFromFrames is the shared core behind both Compute (drgn) and
// ComputeFromKernelBacktrace (kernel log). It drops inlined and
// infrastructure frames — falling back to all non-inlined frames if that
// would remove everything — then hands the surviving, fault-first function
// list to buildFingerprint. Callers differ only in how they parse raw
// lines into frames, so filtering, fallback, and hashing stay identical
// across sources.
func fingerprintFromFrames(frames []rawFrame, panicMessage string) *Fingerprint {
	var significant []string
	filtered := 0
	for _, f := range frames {
		if f.inlined {
			continue
		}
		if InfraFunctions[f.name] || InfraFunctions[f.altName] {
			filtered++
			continue
		}
		significant = append(significant, f.name)
	}

	// If everything was filtered, fall back to all non-inlined frames.
	if len(significant) == 0 {
		for _, f := range frames {
			if !f.inlined {
				significant = append(significant, f.name)
			}
		}
		filtered = 0
	}

	return buildFingerprint(significant, filtered, panicMessage)
}

// buildFingerprint computes the five deduplication hashes from an ordered
// list of significant function names (fault frame first) plus the panic
// message used for crash-type classification. It is the shared core of
// Compute (drgn frames) and ComputeFromKernelBacktrace (dmesg frames) so
// both paths hash identically.
func buildFingerprint(allFuncs []string, filtered int, panicMessage string) *Fingerprint {
	if len(allFuncs) == 0 {
		return nil
	}

	faultFunc := allFuncs[0]
	crashType := ClassifyPanic(panicMessage)

	top3 := take(allFuncs, 3)
	top5 := take(allFuncs, 5)

	return &Fingerprint{
		RIP:     hashStrings(faultFunc),
		Top3:    hashStrings(strings.Join(top3, "\n")),
		Top5:    hashStrings(strings.Join(top5, "\n")),
		Full:    hashStrings(strings.Join(allFuncs, "\n")),
		TypeRIP: hashStrings(crashType + ":" + faultFunc),
		Inputs: FingerprintInputs{
			FaultFunc:  faultFunc,
			CrashType:  crashType,
			Top3Funcs:  top3,
			Top5Funcs:  top5,
			AllFuncs:   allFuncs,
			FrameCount: len(allFuncs),
			Filtered:   filtered,
		},
	}
}

// kernelBacktraceFramePattern matches a single kernel backtrace frame as
// printed into the printk ring buffer, capturing the symbol name. The
// kernel log prefix ("[ 1234.5] [ T99] ") and any trailing " [module]",
// " (P)" reliability markers, or source annotations are ignored:
//
//	kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia]
//	do_user_addr_fault+0x1d2/0x6a0
//	el0t_64_sync_handler+0x120/0x130
var kernelBacktraceFramePattern = regexp.MustCompile(
	`^([A-Za-z_][A-Za-z0-9_.]*)\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?`,
)

// ParseKernelBacktraceFrame extracts the function/symbol name from a
// single kernel backtrace line. It returns ok=false for section markers
// (<TASK>, <IRQ>, …), unreliable "?"-prefixed frames (x86 stale-stack
// guesses, which would add noise to the fingerprint), and any line that
// is not a recognizable frame. The line should already have its kernel
// log timestamp prefix stripped.
func ParseKernelBacktraceFrame(line string) (string, bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "", false
	}
	switch s {
	case "<TASK>", "</TASK>", "<IRQ>", "</IRQ>", "<NMI>", "</NMI>":
		return "", false
	}
	// Unreliable frames (x86 prints "? func+0x..") are stale stack
	// guesses; skip them so they don't pollute the fingerprint.
	if strings.HasPrefix(s, "?") {
		return "", false
	}
	m := kernelBacktraceFramePattern.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func hashStrings(input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h)
}

func take(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
