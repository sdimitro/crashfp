// SPDX-License-Identifier: MIT

// Package fingerprint computes deduplication hashes ("fingerprints") from
// Linux kernel crash stack traces, so that repeat occurrences of the same
// kernel bug can be recognized by comparing hashes.
//
// # Strategies
//
// A [Fingerprint] carries five SHA-256 hex hashes at different granularity
// levels, letting callers choose the trade-off between false-positive
// merges (distinct bugs treated as one) and false-negative splits (one bug
// treated as many):
//
//   - RIP: the fault function alone. Coarsest; merges any crash faulting
//     in the same function.
//   - TypeRIP: crash type + fault function (e.g. "page_fault:io_idle").
//     The recommended default deduplication key.
//   - Top3, Top5: the first 3 or 5 significant functions, newline-joined.
//   - Full: every significant function, newline-joined. Strictest.
//
// # Normalization
//
// Only ordered, bare function names feed the hashes. Addresses, offsets,
// module names, source paths, and line numbers are stripped. Inlined
// frames (drgn path only) are dropped, and functions in [InfraFunctions]
// — kernel exception-dispatch, syscall-entry, and scheduling plumbing
// that appears in every crash of a given type — are filtered out so
// fingerprints track root cause rather than entry path. If filtering
// would remove every frame, all non-inlined frames are used instead.
//
// # Ingestion paths
//
// Stack traces come from one of two sources, both feeding the same
// hashing core so fingerprints are comparable across them:
//
//   - [Compute] takes drgn-symbolized frames (requires DWARF debug
//     symbols at extraction time).
//   - [ComputeFromKernelBacktrace] takes the kernel's own kallsyms
//     backtrace as printed into the printk ring buffer (the "Call
//     Trace:" section of an oops). No debug symbols needed; this is
//     what a minimal environment such as a kdump crash kernel can use,
//     typically fed by package dmesgcrash.
//
// The names the kernel prints come from kallsyms (the ELF symbol table),
// which line up with the symbols drgn reports for non-inlined frames, so
// the same crash fingerprints identically regardless of the path.
//
// Crash types are classified from the panic message text by
// [ClassifyPanic] and affect only the TypeRIP hash.
package fingerprint
