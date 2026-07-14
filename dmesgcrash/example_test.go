// SPDX-License-Identifier: MIT

package dmesgcrash_test

import (
	"fmt"

	"github.com/sdimitro/crashfp/dmesgcrash"
	"github.com/sdimitro/crashfp/fingerprint"
)

// Parse a raw kernel log (e.g. from vmcore-dmesg /proc/vmcore) and
// fingerprint the crash. The faulting function from the RIP register line
// is promoted to the first frame, and the unreliable "?" frame is dropped.
func ExampleParse() {
	log := `[  100.000000] [ T42] BUG: kernel NULL pointer dereference, address: 0000000000000010
[  100.000002] [ T42] Oops: 0000 [#1] PREEMPT SMP NOPTI
[  100.000005] [ T42] RIP: 0010:fault_func+0x12/0x40
[  100.000008] [ T42] Call Trace:
[  100.000009] [ T42]  <TASK>
[  100.000010] [ T42]  ? page_fault_oops+0x150/0x420
[  100.000011] [ T42]  outer_func+0x30/0x90
[  100.000012] [ T42]  worker_thread+0x100/0x200
[  100.000013] [ T42]  </TASK>
`
	c := dmesgcrash.Parse(log)
	fmt.Println("frames:", c.StackTrace)

	fp := fingerprint.ComputeFromKernelBacktrace(c.StackTrace, c.PanicMessage)
	fmt.Println("fault func:", fp.Inputs.FaultFunc)
	fmt.Println("crash type:", fp.Inputs.CrashType)
	// Output:
	// frames: [fault_func+0x12/0x40 outer_func+0x30/0x90 worker_thread+0x100/0x200]
	// fault func: fault_func
	// crash type: null_pointer
}
