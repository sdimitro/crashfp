// SPDX-License-Identifier: MIT

package fingerprint

import "strings"

// Crash type constants returned by ClassifyPanic.
const (
	CrashPageFault         = "page_fault"
	CrashNullPointer       = "null_pointer"
	CrashSoftLockup        = "soft_lockup"
	CrashGeneralProtection = "general_protection"
	CrashKernelBug         = "kernel_bug"
	CrashOops              = "oops"
	CrashWatchdog          = "watchdog"
	CrashUnknown           = "unknown"
)

// ClassifyPanic determines the crash type from a kernel panic/oops
// message. The message is the multi-line crash report text, e.g. as
// extracted from the printk ring buffer.
//
// Classification is based on distinctive keywords that appear in the
// kernel's crash reporting paths.
func ClassifyPanic(msg string) string {
	if msg == "" {
		return CrashUnknown
	}

	// Order matters: check more specific patterns first.
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "watchdog: bug:"):
		return CrashWatchdog
	case strings.Contains(lower, "bug: soft lockup"):
		return CrashSoftLockup
	case strings.Contains(lower, "kernel null pointer") ||
		strings.Contains(lower, "null pointer dereference"):
		return CrashNullPointer
	case strings.Contains(lower, "general protection fault"):
		return CrashGeneralProtection
	case strings.Contains(msg, "#PF:") ||
		strings.Contains(lower, "page fault") ||
		strings.Contains(lower, "not-present page"):
		return CrashPageFault
	case strings.Contains(lower, "kernel bug at"):
		return CrashKernelBug
	case strings.Contains(lower, "oops:") ||
		strings.Contains(lower, "kernel panic"):
		return CrashOops
	default:
		return CrashUnknown
	}
}
