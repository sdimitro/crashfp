// SPDX-License-Identifier: MIT

// Package dmesgcrash extracts a kernel crash report from raw kernel log
// text — the output of vmcore-dmesg /proc/vmcore, makedumpfile
// --dump-dmesg, or a dmesg capture. It is pure string parsing with no
// external dependencies, suitable for minimal environments such as a
// kdump crash kernel.
//
// [Parse] locates the last crash report in the log (kernel oops, panic,
// soft lockup, …) and returns its panic message, the kernel backtrace
// frames fault-first, the loaded module list, and the kernel banner and
// command line. Both x86 and arm64 oops formats are handled:
//
//   - Kernel log timestamp/caller-id prefixes ("[ 1234.5] [ T99] ") are
//     stripped.
//   - The faulting function from the register dump (x86 "RIP:", arm64
//     "pc :") is promoted to the first frame when the "Call Trace:"
//     section doesn't already start with it.
//   - On arm64 indirect-call crashes where the PC is an unsymbolizable
//     address (e.g. "pc : 0x0"), the link register ("lr :") frame is
//     used instead, naming the caller that invoked the bad function
//     pointer.
//   - Section markers (<TASK>, <IRQ>, …), unreliable "?" frames, and
//     address-only lines are dropped.
//
// The resulting StackTrace and PanicMessage feed directly into
// fingerprint.ComputeFromKernelBacktrace to produce deduplication hashes
// for the crash.
package dmesgcrash
