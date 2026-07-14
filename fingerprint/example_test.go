// SPDX-License-Identifier: MIT

package fingerprint_test

import (
	"fmt"

	"github.com/sdimitro/crashfp/fingerprint"
)

// Fingerprint a crash from the kernel's own backtrace as printed into the
// log — no debug symbols required. ret_from_fork is filtered out as an
// infrastructure frame.
func ExampleComputeFromKernelBacktrace() {
	frames := []string{
		"kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia] (P)",
		"kgspRcAndNotifyAllChannels_IMPL+0x8c/0x220 [nvidia]",
		"osHandleGpuLost+0x138/0x140 [nvidia]",
		"kthread+0x100/0x120",
		"ret_from_fork+0x10/0x20",
	}
	panicMsg := "Unable to handle kernel NULL pointer dereference at virtual address 0000000000000360"

	fp := fingerprint.ComputeFromKernelBacktrace(frames, panicMsg)
	fmt.Println("fault func:", fp.Inputs.FaultFunc)
	fmt.Println("crash type:", fp.Inputs.CrashType)
	fmt.Println("type_rip:  ", fp.TypeRIP)
	// Output:
	// fault func: kfifoGetChannelIterator_IMPL
	// crash type: null_pointer
	// type_rip:   76571165e62ca40f72a8e6dd85b46b6c65781b814cea661a949c9126561f57f5
}

// Fingerprint a drgn-symbolized stack trace. Inlined frames are dropped,
// so the fault function is io_idle, not the inlined constant_test_bit.
func ExampleCompute() {
	stackTrace := []string{
		`#0 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in constant_test_bit at ./arch/x86/include/asm/bitops.h:207:8 (inlined)`,
		`#1 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in io_idle at drivers/acpi/processor_idle.c:533:6`,
		`#2 at 0xffffffff9f2e4a7b (acpi_idle_do_entry+0x2b/0x77) in acpi_idle_do_entry at drivers/acpi/processor_idle.c:575:3`,
	}
	panicMsg := "#PF: error_code(0x0000) - not-present page"

	fp := fingerprint.Compute(stackTrace, panicMsg)
	fmt.Println("fault func:", fp.Inputs.FaultFunc)
	fmt.Println("crash type:", fp.Inputs.CrashType)
	fmt.Println("rip:       ", fp.RIP)
	// Output:
	// fault func: io_idle
	// crash type: page_fault
	// rip:        db5f01567a2169dfa50fc4bcbedc2fa0202a9641792bd18de54ab8e8f8af6060
}

func ExampleClassifyPanic() {
	fmt.Println(fingerprint.ClassifyPanic("BUG: kernel NULL pointer dereference, address: 0000000000000010"))
	fmt.Println(fingerprint.ClassifyPanic("watchdog: BUG: soft lockup - CPU#0 stuck for 22s!"))
	fmt.Println(fingerprint.ClassifyPanic("kernel BUG at fs/btrfs/extent_tree.c:1234!"))
	// Output:
	// null_pointer
	// watchdog
	// kernel_bug
}

func ExampleParseKernelBacktraceFrame() {
	for _, line := range []string{
		"do_user_addr_fault+0x1d2/0x6a0",
		"osHandleGpuLost+0x138/0x140 [nvidia]",
		"? page_fault_oops+0x150/0x420", // unreliable frame, skipped
		"<TASK>",                        // section marker, skipped
	} {
		if fn, ok := fingerprint.ParseKernelBacktraceFrame(line); ok {
			fmt.Println(fn)
		}
	}
	// Output:
	// do_user_addr_fault
	// osHandleGpuLost
}
