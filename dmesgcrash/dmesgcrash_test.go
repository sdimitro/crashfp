// SPDX-License-Identifier: MIT

package dmesgcrash

import (
	"strings"
	"testing"

	"github.com/sdimitro/crashfp/fingerprint"
)

func TestStripPrefix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"[ 2855.217470] [ T131119] Internal error: Oops", "Internal error: Oops"},
		{"[    0.000000] [    T0] Linux version 6.14", "Linux version 6.14"},
		{"[  100.0] [ T42]  outer_func+0x30/0x90", "outer_func+0x30/0x90"},
		{"no prefix here", "no prefix here"},
		{"[ 2855.211771] [ T131119] Internal error: Oops: 0x96 [#1] SMP", "Internal error: Oops: 0x96 [#1] SMP"},
	}
	for _, tc := range tests {
		if got := StripPrefix(tc.in); got != tc.want {
			t.Errorf("StripPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// sampleArm64Dmesg is a trimmed arm64 (nvidia-64k) crash log with the
// kernel timestamp/caller-id prefixes makedumpfile --dump-dmesg emits.
const sampleArm64Dmesg = `[    0.000000] [    T0] Linux version 6.14.0-1008-nvidia-64k (buildd@bos03-arm64-088) (aarch64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #8-Ubuntu SMP PREEMPT_DYNAMIC
[    0.000000] [    T0] Kernel command line: vmlinuz root=UUID=abc ro panic=10 root=http://example.com/ncore-image-2.27.1-ofed-8096756-n580-kver6.14.0-1
[ 2855.144540] [ T131119] NVRM: GPU 0018:06:00.0: GPU has fallen off the bus.
[ 2855.144566] [ T131119] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000360
[ 2855.211771] [ T131119] Internal error: Oops: 0000000096000005 [#1] SMP
[ 2855.217470] [ T131119] Modules linked in: nvidia(OE) t241_clink_ioctl(OE) mlx5_core(OE) [last unloaded: mods(OE)]
[ 2855.350326] [ T131119] CPU: 10 UID: 0 PID: 131119 Comm: nv_open_q Kdump: loaded Tainted: G           OEL     6.14.0-1008-nvidia-64k #8-Ubuntu
[ 2855.369186] [ T131119] Hardware name: Dell Inc. Dell Server 9712a/Dell 9712a, BIOS 2.26 F01 12/30/2025
[ 2855.377728] [ T131119] pstate: 63400009 (nZCv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--)
[ 2855.384846] [ T131119] pc : kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia]
[ 2855.391295] [ T131119] lr : kfifoGetChannelIterator_IMPL+0x30/0x90 [nvidia]
[ 2855.397729] [ T131119] sp : ffff8000a27cf7c0
[ 2855.401113] [ T131119] x29: ffff8000a27cf7c0 x28: ffff8000ad2e0098 x27: 0000000000000002
[ 2855.474073] [ T131119] Call trace:
[ 2855.476568] [ T131119]  kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia] (P)
[ 2855.482996] [ T131119]  kgspRcAndNotifyAllChannels_IMPL+0x8c/0x220 [nvidia]
[ 2855.489403] [ T131119]  osHandleGpuLost+0x138/0x140 [nvidia]
[ 2855.541816] [ T131119]  nvidia_open_deferred+0x44/0xe8 [nvidia]
[ 2855.551585] [ T131119]  kthread+0x100/0x120
[ 2855.554887] [ T131119]  ret_from_fork+0x10/0x20
[ 2855.558544] [ T131119] Code: 94066b7d 3100069f 54000101 b9000e7f (b94362a0)
[ 2855.564779] [ T131119] SMP: stopping secondary CPUs
`

func TestParse_Arm64(t *testing.T) {
	c := Parse(sampleArm64Dmesg)
	if c == nil {
		t.Fatal("expected non-nil crash")
	}

	if !strings.HasPrefix(c.Banner, "Linux version 6.14.0-1008-nvidia-64k") {
		t.Errorf("banner: got %q", c.Banner)
	}
	if !strings.Contains(c.Cmdline, "ncore-image-2.27.1") {
		t.Errorf("cmdline: got %q", c.Cmdline)
	}

	if !strings.Contains(c.PanicMessage, "NULL pointer dereference") {
		t.Errorf("panic message missing NULL pointer: %q", c.PanicMessage)
	}
	if strings.Contains(c.PanicMessage, "Call trace") {
		t.Errorf("panic message should stop before the backtrace, got: %q", c.PanicMessage)
	}

	wantFrames := []string{
		"kfifoGetChannelIterator_IMPL+0x3c/0x90 [nvidia] (P)",
		"kgspRcAndNotifyAllChannels_IMPL+0x8c/0x220 [nvidia]",
		"osHandleGpuLost+0x138/0x140 [nvidia]",
		"nvidia_open_deferred+0x44/0xe8 [nvidia]",
		"kthread+0x100/0x120",
		"ret_from_fork+0x10/0x20",
	}
	if len(c.StackTrace) != len(wantFrames) {
		t.Fatalf("stack trace len: got %d (%v), want %d", len(c.StackTrace), c.StackTrace, len(wantFrames))
	}
	for i, f := range wantFrames {
		if c.StackTrace[i] != f {
			t.Errorf("frame %d: got %q, want %q", i, c.StackTrace[i], f)
		}
	}

	wantMods := []string{"nvidia", "t241_clink_ioctl", "mlx5_core"}
	if strings.Join(c.Modules, ",") != strings.Join(wantMods, ",") {
		t.Errorf("modules: got %v, want %v", c.Modules, wantMods)
	}

	// The recovered backtrace must fingerprint without debug symbols.
	fp := fingerprint.ComputeFromKernelBacktrace(c.StackTrace, c.PanicMessage)
	if fp == nil {
		t.Fatal("expected fingerprint from recovered backtrace")
	}
	if fp.Inputs.FaultFunc != "kfifoGetChannelIterator_IMPL" {
		t.Errorf("fault func: got %q", fp.Inputs.FaultFunc)
	}
	if fp.Inputs.CrashType != fingerprint.CrashNullPointer {
		t.Errorf("crash type: got %q, want %q", fp.Inputs.CrashType, fingerprint.CrashNullPointer)
	}
}

const sampleArm64IndirectCallDmesg = `[ 7927.194854] [     C34]  slab maple_node start ffff0000e342e200 pointer offset 69 size 256
[ 7927.194868] [     C34] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[ 7927.242961] [     C34] Internal error: Oops: 0000000086000005 [#1] SMP
[ 7927.382844] [     C34] CPU: 34 UID: 0 PID: 0 Comm: swapper/34 Kdump: loaded Tainted: G           OE      6.14.0-1008-nvidia-64k #8-Ubuntu
[ 7927.415589] [     C34] pc : 0x0
[ 7927.417832] [     C34] lr : rcu_do_batch+0x1c4/0x550
[ 7927.498293] [     C34] Call trace:
[ 7927.500789] [     C34]  0x0 (P)
[ 7927.503019] [     C34]  rcu_core+0x150/0x348
[ 7927.506406] [     C34]  rcu_core_si+0x1c/0x40
[ 7927.509880] [     C34]  handle_softirqs+0x13c/0x418
[ 7927.513893] [     C34]  __do_softirq+0x20/0x3c
[ 7927.548277] [     C34]  cpuidle_enter_state+0xd8/0x720 (P)
[ 7927.583101] [     C34] SMP: stopping secondary CPUs
`

func TestParse_Arm64IndirectCallUsesLR(t *testing.T) {
	c := Parse(sampleArm64IndirectCallDmesg)
	if c == nil {
		t.Fatal("expected non-nil crash")
	}

	want := []string{
		"rcu_do_batch+0x1c4/0x550",
		"rcu_core+0x150/0x348",
		"rcu_core_si+0x1c/0x40",
		"handle_softirqs+0x13c/0x418",
		"__do_softirq+0x20/0x3c",
		"cpuidle_enter_state+0xd8/0x720 (P)",
	}
	if len(c.StackTrace) != len(want) {
		t.Fatalf("stack trace: got %v, want %v", c.StackTrace, want)
	}
	for i := range want {
		if c.StackTrace[i] != want[i] {
			t.Errorf("frame %d: got %q, want %q", i, c.StackTrace[i], want[i])
		}
	}
	for _, f := range c.StackTrace {
		if strings.HasPrefix(f, "0x0") {
			t.Errorf("address-only frame leaked into trace: %q", f)
		}
	}

	fp := fingerprint.ComputeFromKernelBacktrace(c.StackTrace, c.PanicMessage)
	if fp == nil {
		t.Fatal("expected fingerprint from LR fallback trace")
	}
	if fp.Inputs.FaultFunc != "rcu_do_batch" {
		t.Errorf("fault func: got %q, want rcu_do_batch", fp.Inputs.FaultFunc)
	}
}

// sampleX86Dmesg exercises x86 specifics: the fault function comes from a
// separate "RIP:" line and must be prepended ahead of the call trace, and
// unreliable "?" frames must be dropped.
const sampleX86Dmesg = `[    0.000000] [    T0] Linux version 6.5.13-65-coreweave (root@b) (gcc-12 (Ubuntu 12.3.0) 12.3.0, GNU ld 2.38) #1 SMP
[  100.000000] [ T42] BUG: kernel NULL pointer dereference, address: 0000000000000010
[  100.000001] [ T42] #PF: supervisor read access in kernel mode
[  100.000002] [ T42] Oops: 0000 [#1] PREEMPT SMP NOPTI
[  100.000003] [ T42] CPU: 1 PID: 42 Comm: worker Tainted: G           O       6.5.13-65-coreweave #1
[  100.000004] [ T42] Hardware name: Supermicro Foo/Bar, BIOS 1.0
[  100.000005] [ T42] RIP: 0010:fault_func+0x12/0x40
[  100.000006] [ T42] Code: 00 01 02 03
[  100.000007] [ T42] RSP: 0018:ffffabc
[  100.000008] [ T42] Call Trace:
[  100.000009] [ T42]  <TASK>
[  100.000010] [ T42]  ? page_fault_oops+0x150/0x420
[  100.000011] [ T42]  outer_func+0x30/0x90
[  100.000012] [ T42]  worker_thread+0x100/0x200
[  100.000013] [ T42]  </TASK>
[  100.000014] [ T42] Modules linked in: foo bar baz
`

func TestParse_X86PrependsRIP(t *testing.T) {
	c := Parse(sampleX86Dmesg)
	if c == nil {
		t.Fatal("expected non-nil crash")
	}

	want := []string{
		"fault_func+0x12/0x40",
		"outer_func+0x30/0x90",
		"worker_thread+0x100/0x200",
	}
	if len(c.StackTrace) != len(want) {
		t.Fatalf("stack trace: got %v, want %v", c.StackTrace, want)
	}
	for i := range want {
		if c.StackTrace[i] != want[i] {
			t.Errorf("frame %d: got %q, want %q", i, c.StackTrace[i], want[i])
		}
	}
	for _, f := range c.StackTrace {
		if strings.Contains(f, "page_fault_oops") {
			t.Errorf("unreliable frame leaked into trace: %q", f)
		}
	}

	wantMods := []string{"foo", "bar", "baz"}
	if strings.Join(c.Modules, ",") != strings.Join(wantMods, ",") {
		t.Errorf("modules: got %v, want %v", c.Modules, wantMods)
	}
}

func TestParseBytes_MatchesParse(t *testing.T) {
	for _, src := range []string{sampleArm64Dmesg, sampleArm64IndirectCallDmesg, sampleX86Dmesg} {
		a := Parse(src)
		b := ParseBytes([]byte(src))
		if a.PanicMessage != b.PanicMessage ||
			strings.Join(a.StackTrace, "|") != strings.Join(b.StackTrace, "|") ||
			strings.Join(a.Modules, "|") != strings.Join(b.Modules, "|") ||
			a.Banner != b.Banner || a.Cmdline != b.Cmdline {
			t.Errorf("ParseBytes diverges from Parse:\n%+v\nvs\n%+v", a, b)
		}
	}
	if ParseBytes(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

// The returned Crash must not alias the input: callers may reuse or
// mutate the buffer after ParseBytes returns.
func TestParseBytes_DoesNotAliasInput(t *testing.T) {
	buf := []byte(sampleArm64Dmesg)
	c := ParseBytes(buf)
	frame0, banner := c.StackTrace[0], c.Banner
	for i := range buf {
		buf[i] = 'X'
	}
	if c.StackTrace[0] != frame0 || c.Banner != banner {
		t.Error("Crash aliases the input buffer")
	}
}

func TestParse_NoCrash(t *testing.T) {
	log := "[ 0.0] [ T0] Linux version 6.5.0 (root@host) (gcc) #1\n[ 1.0] [ T1] systemd: booted\n"
	c := Parse(log)
	if c == nil {
		t.Fatal("expected banner-only crash struct, got nil")
	}
	if len(c.StackTrace) != 0 {
		t.Errorf("expected no stack trace, got %v", c.StackTrace)
	}
	if c.PanicMessage != "" {
		t.Errorf("expected empty panic message, got %q", c.PanicMessage)
	}

	if Parse("nothing useful here\n") != nil {
		t.Error("expected nil when no banner, cmdline, or crash present")
	}
}
