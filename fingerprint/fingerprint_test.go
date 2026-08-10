package fingerprint

import (
	"strings"
	"testing"
)

// Real drgn stack trace frames from a production crash dump.
var realStackTrace = []string{
	`#0 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in constant_test_bit at ./arch/x86/include/asm/bitops.h:207:8 (inlined)`,
	`#1 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in arch_test_bit at ./arch/x86/include/asm/bitops.h:239:36 (inlined)`,
	`#2 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in io_idle at drivers/acpi/processor_idle.c:533:6`,
	`#3 at 0xffffffff9f2e4a7b (acpi_idle_do_entry+0x2b/0x77) in acpi_idle_do_entry at drivers/acpi/processor_idle.c:575:3`,
	`#4 at 0xffffffff9f2e4ecb (acpi_idle_enter+0xbb/0x182) in acpi_idle_enter at drivers/acpi/processor_idle.c:707:2`,
	`#5 at 0xffffffff9f2e33ae (cpuidle_enter_state+0x8e/0x714) in cpuidle_enter_state at drivers/cpuidle/cpuidle.c:267:18`,
	`#6 at 0xffffffff9ef53bce (cpuidle_enter+0x2e/0x47) in cpuidle_enter at drivers/cpuidle/cpuidle.c:388:9`,
	`#7 at 0xffffffff9e365333 (call_cpuidle+0x23/0x52) in call_cpuidle at kernel/sched/idle.c:134:9`,
	`#8 at 0xffffffff9e36aa61 (do_idle+0x1f1/0x246) in cpuidle_idle_call at kernel/sched/idle.c:215:19 (inlined)`,
	`#9 at 0xffffffff9e36aa61 (do_idle+0x1f1/0x246) in do_idle at kernel/sched/idle.c:282:4`,
	`#10 at 0xffffffff9e36acdd (cpu_startup_entry+0x2d/0x2f) in cpu_startup_entry at kernel/sched/idle.c:380:3`,
	`#11 at 0xffffffff9e29f729 (start_secondary+0x129/0x159) in start_secondary at arch/x86/kernel/smpboot.c:326:2`,
	`#12 at 0xffffffff9e200275 (secondary_startup_64+0x195/0x195) at arch/x86/kernel/head_64.S:457`,
}

var realPanicMessage = `#PF: error_code(0x0000) - not-present page
PGD 1008f03e067 P4D 1008f03f067 PUD 1008f040063 PMD 1281ec063 PTE 800001008f418163
Oops: 0000 [#1] PREEMPT SMP NOPTI
CPU: 97 PID: 0 Comm: swapper/97 Kdump: loaded Tainted: G S         OE      6.5.13-65-...-85c45edc #1
Hardware name: Supermicro AS -2115HS-TNR/H13SSH, BIOS 13.5 06/13/2025
RIP: 0010:io_idle+0x3/0x30`

func TestParseFrame(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		symbol   string
		function string
		inlined  bool
		source   string
		line     int
	}{
		{
			name:     "inlined frame with source function",
			input:    `#0 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in constant_test_bit at ./arch/x86/include/asm/bitops.h:207:8 (inlined)`,
			symbol:   "io_idle",
			function: "constant_test_bit",
			inlined:  true,
			source:   "./arch/x86/include/asm/bitops.h",
			line:     207,
		},
		{
			name:     "non-inlined frame with matching symbol and function",
			input:    `#2 at 0xffffffff9f2e4a13 (io_idle+0x3/0x2d) in io_idle at drivers/acpi/processor_idle.c:533:6`,
			symbol:   "io_idle",
			function: "io_idle",
			inlined:  false,
			source:   "drivers/acpi/processor_idle.c",
			line:     533,
		},
		{
			name:     "frame without explicit function name",
			input:    `#12 at 0xffffffff9e200275 (secondary_startup_64+0x195/0x195) at arch/x86/kernel/head_64.S:457`,
			symbol:   "secondary_startup_64",
			function: "secondary_startup_64",
			inlined:  false,
			source:   "arch/x86/kernel/head_64.S",
			line:     457,
		},
		{
			name:    "garbage input",
			input:   "not a frame",
			wantNil: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ParseFrame(tc.input)
			if tc.wantNil {
				if f != nil {
					t.Fatalf("expected nil, got %+v", f)
				}
				return
			}
			if f == nil {
				t.Fatal("expected non-nil frame")
			}
			if f.Symbol != tc.symbol {
				t.Errorf("symbol: got %q, want %q", f.Symbol, tc.symbol)
			}
			if f.Function != tc.function {
				t.Errorf("function: got %q, want %q", f.Function, tc.function)
			}
			if f.Inlined != tc.inlined {
				t.Errorf("inlined: got %v, want %v", f.Inlined, tc.inlined)
			}
			if f.Source != tc.source {
				t.Errorf("source: got %q, want %q", f.Source, tc.source)
			}
			if f.Line != tc.line {
				t.Errorf("line: got %d, want %d", f.Line, tc.line)
			}
		})
	}
}

func TestCompute_RealTrace(t *testing.T) {
	fp := Compute(realStackTrace, realPanicMessage)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}

	// Fault function should be io_idle (first non-inlined frame).
	if fp.Inputs.FaultFunc != "io_idle" {
		t.Errorf("fault func: got %q, want %q", fp.Inputs.FaultFunc, "io_idle")
	}

	// Crash type should be page_fault (panic message contains #PF).
	if fp.Inputs.CrashType != CrashPageFault {
		t.Errorf("crash type: got %q, want %q", fp.Inputs.CrashType, CrashPageFault)
	}

	// All hashes should be non-empty.
	for name, hash := range map[string]string{
		"rip":      fp.RIP,
		"top3":     fp.Top3,
		"top5":     fp.Top5,
		"full":     fp.Full,
		"type_rip": fp.TypeRIP,
	} {
		if hash == "" {
			t.Errorf("%s hash is empty", name)
		}
		if len(hash) != 64 {
			t.Errorf("%s hash length: got %d, want 64", name, len(hash))
		}
	}

	// RIP and type+rip should differ (different inputs).
	if fp.RIP == fp.TypeRIP {
		t.Error("rip and type_rip should differ")
	}

	// Top3 should have 3 functions.
	if len(fp.Inputs.Top3Funcs) != 3 {
		t.Errorf("top3 funcs count: got %d, want 3", len(fp.Inputs.Top3Funcs))
	}

	// Top5 should have 5 functions.
	if len(fp.Inputs.Top5Funcs) != 5 {
		t.Errorf("top5 funcs count: got %d, want 5", len(fp.Inputs.Top5Funcs))
	}

	// Inlined frames should be excluded from allFuncs.
	for _, fn := range fp.Inputs.AllFuncs {
		if fn == "constant_test_bit" || fn == "arch_test_bit" || fn == "cpuidle_idle_call" {
			t.Errorf("inlined function %q should not appear in allFuncs", fn)
		}
	}

	// The real trace is a CPU idle path with no infrastructure frames.
	if fp.Inputs.Filtered != 0 {
		t.Errorf("filtered count: got %d, want 0 (idle path has no infra frames)", fp.Inputs.Filtered)
	}
}

func TestCompute_EmptyTrace(t *testing.T) {
	fp := Compute(nil, "some panic")
	if fp != nil {
		t.Error("expected nil for empty trace")
	}

	fp = Compute([]string{}, "some panic")
	if fp != nil {
		t.Error("expected nil for empty slice")
	}
}

func TestCompute_Deterministic(t *testing.T) {
	fp1 := Compute(realStackTrace, realPanicMessage)
	fp2 := Compute(realStackTrace, realPanicMessage)

	if fp1.RIP != fp2.RIP {
		t.Error("rip hash not deterministic")
	}
	if fp1.Full != fp2.Full {
		t.Error("full hash not deterministic")
	}
}

func TestCompute_DifferentPanicChangesTypeRIP(t *testing.T) {
	fp1 := Compute(realStackTrace, realPanicMessage)
	fp2 := Compute(realStackTrace, "BUG: soft lockup - CPU#3 stuck for 22s!")

	// Same stack, different crash types: rip should match, type_rip should differ.
	if fp1.RIP != fp2.RIP {
		t.Error("rip should match for same stack with different panic type")
	}
	if fp1.TypeRIP == fp2.TypeRIP {
		t.Error("type_rip should differ for different crash types")
	}
}

// Stack with infrastructure frames that should be filtered.
var infraHeavyTrace = []string{
	`#0 at 0xffffffff9e000001 (show_regs+0x72/0x90) in show_regs at arch/x86/kernel/dumpstack.c:500:1`,
	`#1 at 0xffffffff9e000002 (__die+0x25/0x80) in __die at arch/x86/kernel/dumpstack.c:400:1`,
	`#2 at 0xffffffff9e000003 (page_fault_oops+0x154/0x4c0) in page_fault_oops at arch/x86/mm/fault.c:600:1`,
	`#3 at 0xffffffff9e000004 (exc_page_fault+0x112/0x1b0) in exc_page_fault at arch/x86/mm/fault.c:700:1`,
	`#4 at 0xffffffff9e000005 (asm_exc_page_fault+0x27/0x30) in asm_exc_page_fault at arch/x86/include/asm/idtentry.h:100:1`,
	`#5 at 0xffffffff9e000006 (my_driver_func+0x42/0x100) in my_driver_func at drivers/my/driver.c:123:4`,
	`#6 at 0xffffffff9e000007 (my_driver_init+0x10/0x50) in my_driver_init at drivers/my/driver.c:200:2`,
}

func TestCompute_InfraFiltering(t *testing.T) {
	fp := Compute(infraHeavyTrace, "Oops: 0000 [#1]")
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}

	if fp.Inputs.FaultFunc != "my_driver_func" {
		t.Errorf("fault func: got %q, want %q", fp.Inputs.FaultFunc, "my_driver_func")
	}

	if fp.Inputs.Filtered != 5 {
		t.Errorf("filtered count: got %d, want 5", fp.Inputs.Filtered)
	}

	if fp.Inputs.FrameCount != 2 {
		t.Errorf("frame count: got %d, want 2", fp.Inputs.FrameCount)
	}
}

func TestClassifyPanic(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"BUG: soft lockup - CPU#3 stuck for 22s!", CrashSoftLockup},
		{"watchdog: BUG: soft lockup - CPU#0 stuck", CrashWatchdog},
		{"BUG: kernel NULL pointer dereference", CrashNullPointer},
		{"general protection fault, probably for non-canonical address", CrashGeneralProtection},
		{"#PF: error_code(0x0000) - not-present page\nOops: 0000", CrashPageFault},
		{"kernel BUG at fs/btrfs/extent_tree.c:1234!", CrashKernelBug},
		{"Oops: 0000 [#1] PREEMPT SMP", CrashOops},
		{"Kernel panic - not syncing: Fatal exception", CrashOops},
		{"", CrashUnknown},
		{"some random message", CrashUnknown},
	}

	for _, tc := range tests {
		got := ClassifyPanic(tc.msg)
		if got != tc.want {
			t.Errorf("ClassifyPanic(%q): got %q, want %q", tc.msg, got, tc.want)
		}
	}
}

// Verify that the watchdog classifier takes precedence over soft_lockup
// when both patterns match (watchdog: BUG: soft lockup).
func TestClassifyPanic_WatchdogVsSoftLockup(t *testing.T) {
	msg := "watchdog: BUG: soft lockup - CPU#0 stuck for 22s!"
	got := ClassifyPanic(msg)
	if got != CrashWatchdog {
		t.Errorf("expected watchdog, got %q", got)
	}
}

func TestParseKernelBacktraceFrame(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"arm64 module frame with PC marker", "kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia] (P)", "kfifoGetChannelIterator_IMPL", true},
		{"x86 reliable frame", "do_user_addr_fault+0x1d2/0x6a0", "do_user_addr_fault", true},
		{"offset without size", "kthread+0x100", "kthread", true},
		{"leading whitespace", "  osHandleGpuLost+0x138/0x140 [nvidia]", "osHandleGpuLost", true},
		{"unreliable question-mark frame", "? page_fault_oops+0x150/0x420", "", false},
		{"task marker", "<TASK>", "", false},
		{"end task marker", "</TASK>", "", false},
		{"raw address only", "0xffffffff9e200275", "", false},
		{"empty", "", "", false},
		{"prose", "Modules linked in: nvidia", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseKernelBacktraceFrame(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok: got %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("func: got %q, want %q", got, tc.want)
			}
		})
	}
}

// realKernelBacktrace is the kernel's own backtrace (kallsyms) for the
// BC877J4 GPU-fell-off-the-bus crash, as printed into the ring buffer.
var realKernelBacktrace = []string{
	"kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia] (P)",
	"kgspRcAndNotifyAllChannels_IMPL+0x8c/0x220 [nvidia]",
	"osHandleGpuLost+0x138/0x140 [nvidia]",
	"gpuSanityCheckRegRead_IMPL+0x124/0x140 [nvidia]",
	"_regRead+0xe8/0x1b0 [nvidia]",
	"kthread+0x100/0x120",
	"ret_from_fork+0x10/0x20",
}

func TestComputeFromKernelBacktrace(t *testing.T) {
	panicMsg := "Unable to handle kernel NULL pointer dereference at virtual address 0000000000000360"
	fp := ComputeFromKernelBacktrace(realKernelBacktrace, panicMsg)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}

	if fp.Inputs.FaultFunc != "kfifoGetChannelIterator_IMPL" {
		t.Errorf("fault func: got %q, want %q", fp.Inputs.FaultFunc, "kfifoGetChannelIterator_IMPL")
	}
	if fp.Inputs.CrashType != CrashNullPointer {
		t.Errorf("crash type: got %q, want %q", fp.Inputs.CrashType, CrashNullPointer)
	}
	// ret_from_fork is the only infrastructure frame; kthread is kept.
	if fp.Inputs.Filtered != 1 {
		t.Errorf("filtered: got %d, want 1", fp.Inputs.Filtered)
	}
	if fp.Inputs.FrameCount != 6 {
		t.Errorf("frame count: got %d, want 6", fp.Inputs.FrameCount)
	}
	for name, hash := range map[string]string{"rip": fp.RIP, "top3": fp.Top3, "type_rip": fp.TypeRIP} {
		if len(hash) != 64 {
			t.Errorf("%s hash length: got %d, want 64", name, len(hash))
		}
	}
}

func TestComputeFromKernelBacktrace_Empty(t *testing.T) {
	if fp := ComputeFromKernelBacktrace(nil, "x"); fp != nil {
		t.Error("expected nil for nil frames")
	}
	if fp := ComputeFromKernelBacktrace([]string{"<TASK>", "? noise+0x1/0x2"}, "x"); fp != nil {
		t.Error("expected nil when no frames parse")
	}
}

// The kallsyms path must hash identically to the drgn path for the same
// non-inlined symbols and crash type, so a crash dedupes to one JIRA
// issue regardless of whether debug symbols were available.
func TestComputeFromKernelBacktrace_MatchesDrgn(t *testing.T) {
	panicMsg := "Unable to handle kernel NULL pointer dereference at virtual address 0x0"
	drgnFrames := []string{
		`#0 at 0xffff0001 (alpha_func+0x10/0x40) at drivers/x/x.c:10`,
		`#1 at 0xffff0002 (beta_func+0x20/0x80) at drivers/x/y.c:20`,
	}
	kbtFrames := []string{
		"alpha_func+0x10/0x40 [mod]",
		"beta_func+0x20/0x80 [mod]",
	}

	fpD := Compute(drgnFrames, panicMsg)
	fpK := ComputeFromKernelBacktrace(kbtFrames, panicMsg)
	if fpD == nil || fpK == nil {
		t.Fatal("expected non-nil fingerprints")
	}
	if fpD.RIP != fpK.RIP {
		t.Errorf("rip mismatch: drgn %s vs dmesg %s", fpD.RIP, fpK.RIP)
	}
	if fpD.Top3 != fpK.Top3 {
		t.Errorf("top3 mismatch: drgn %s vs dmesg %s", fpD.Top3, fpK.Top3)
	}
	if fpD.TypeRIP != fpK.TypeRIP {
		t.Errorf("type_rip mismatch: drgn %s vs dmesg %s", fpD.TypeRIP, fpK.TypeRIP)
	}
}

// A driver fault reached through a syscall: the arm64 syscall-entry and
// exception-vector frames at the bottom of the trace must be filtered as
// infrastructure so the real fault function rises to the top.
func TestComputeFromKernelBacktrace_Arm64InfraFiltering(t *testing.T) {
	frames := []string{
		"my_driver_fault+0x10/0x40 [mymod]",
		"my_driver_ioctl+0x20/0x80 [mymod]",
		"__arm64_sys_ioctl+0x48/0x80",
		"invoke_syscall+0x4c/0x118",
		"el0_svc_common+0x60/0x120",
		"do_el0_svc+0x24/0x38",
		"el0_svc+0x2c/0xb0",
		"el0t_64_sync_handler+0xc0/0xc8",
		"el0t_64_sync+0x1a4/0x1a8",
	}
	fp := ComputeFromKernelBacktrace(frames, "Unable to handle kernel NULL pointer dereference")
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if fp.Inputs.FaultFunc != "my_driver_fault" {
		t.Errorf("fault func: got %q, want my_driver_fault", fp.Inputs.FaultFunc)
	}
	// invoke_syscall, el0_svc_common, do_el0_svc, el0_svc,
	// el0t_64_sync_handler, el0t_64_sync are infra; the two driver frames
	// and the syscall implementation (__arm64_sys_ioctl) are kept.
	if fp.Inputs.Filtered != 6 {
		t.Errorf("filtered: got %d, want 6", fp.Inputs.Filtered)
	}
	if fp.Inputs.FrameCount != 3 {
		t.Errorf("frame count: got %d, want 3", fp.Inputs.FrameCount)
	}
	wantTop := []string{"my_driver_fault", "my_driver_ioctl", "__arm64_sys_ioctl"}
	if strings.Join(fp.Inputs.Top3Funcs, ",") != strings.Join(wantTop, ",") {
		t.Errorf("top3: got %v, want %v", fp.Inputs.Top3Funcs, wantTop)
	}
}

// Stack-printer frames (dump_stack_lvl and friends) are pure plumbing that
// tops almost every oops/GP report; if they aren't filtered they become the
// "fault function" and unrelated crashes collapse onto one fingerprint.
func TestComputeFromKernelBacktrace_FiltersStackPrinters(t *testing.T) {
	frames := []string{
		"dump_stack_lvl+0x5c/0x80",
		"dump_stack+0x14/0x1c",
		"show_stack+0x18/0x28",
		"my_gp_faulting_func+0x42/0x100",
		"my_caller+0x10/0x50",
	}
	fp := ComputeFromKernelBacktrace(frames, "general protection fault, probably for non-canonical address")
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if fp.Inputs.FaultFunc != "my_gp_faulting_func" {
		t.Errorf("fault func: got %q, want %q", fp.Inputs.FaultFunc, "my_gp_faulting_func")
	}
	for _, f := range fp.Inputs.AllFuncs {
		if f == "dump_stack_lvl" || f == "dump_stack" || f == "show_stack" {
			t.Errorf("stack-printer %q should have been filtered; AllFuncs=%v", f, fp.Inputs.AllFuncs)
		}
	}
}

// Two unrelated crashes that both start with the stack-printer chain must not
// collide on one fingerprint once the printers are filtered.
func TestComputeFromKernelBacktrace_PrintersDontCauseCollision(t *testing.T) {
	a := ComputeFromKernelBacktrace([]string{"dump_stack_lvl+0x5c/0x80", "funcA+0x10/0x20"}, "general protection fault")
	b := ComputeFromKernelBacktrace([]string{"dump_stack_lvl+0x5c/0x80", "funcB+0x10/0x20"}, "general protection fault")
	if a == nil || b == nil {
		t.Fatal("expected non-nil fingerprints")
	}
	if a.RIP == b.RIP {
		t.Errorf("unrelated crashes collided on rip %s (fault funcs %q vs %q)", a.RIP, a.Inputs.FaultFunc, b.Inputs.FaultFunc)
	}
}
