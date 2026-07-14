// SPDX-License-Identifier: MIT

package dmesgcrash

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestParseReaderMatchesParse is the equivalence contract between the
// streaming and in-memory parsers: for any input, ParseReader must
// produce exactly what Parse produces. It covers the golden corpus, the
// unit-test samples, degenerate inputs, and synthetic logs built to
// exercise the streaming ring buffer's edge cases (captures restarted
// by a later crash, keyword clusters, crashes at the very top or tail).
func TestParseReaderMatchesParse(t *testing.T) {
	filler := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "[ %d.0] [ T1] systemd[1]: noise line %d\n", i, i)
		}
		return b.String()
	}
	crash := "[ 9.0] [ T9] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000360\n" +
		"[ 9.1] [ T9] Internal error: Oops: 96000005 [#1] SMP\n" +
		"[ 9.2] [ T9] pc : alpha_func+0x10/0x40\n" +
		"[ 9.3] [ T9] Call trace:\n" +
		"[ 9.4] [ T9]  alpha_func+0x10/0x40\n" +
		"[ 9.5] [ T9]  beta_func+0x20/0x80\n"
	secondCrash := strings.ReplaceAll(crash, "alpha_func", "gamma_func")

	srcs := map[string]string{
		"unit sample arm64":       sampleArm64Dmesg,
		"unit sample indirect":    sampleArm64IndirectCallDmesg,
		"unit sample x86":         sampleX86Dmesg,
		"empty":                   "",
		"no newline at eof":       "[ 0.0] [ T0] Linux version 6.5.0 (a@b) (gcc) #1",
		"banner only":             "[ 0.0] [ T0] Linux version 6.5.0 (a@b) (gcc) #1\n[ 1.0] [ T1] booted\n",
		"garbage":                 "nothing useful here\n",
		"crash at very top":       crash + filler(300),
		"crash at very tail":      filler(300) + crash,
		"two crashes far apart":   filler(100) + crash + filler(300) + secondCrash + filler(50),
		"two crashes in cluster":  filler(100) + crash + filler(20) + secondCrash + filler(10),
		"crash cluster at window": filler(100) + crash + filler(59) + secondCrash,
		"long tail after crash":   filler(10) + crash + filler(500),
		"huge log crash at end":   filler(20000) + crash,
	}
	logs, _ := filepath.Glob(filepath.Join("testdata", "corpus", "*.txt"))
	for _, p := range logs {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		srcs["corpus "+filepath.Base(p)] = string(data)
	}

	for name, src := range srcs {
		t.Run(name, func(t *testing.T) {
			want := Parse(src)
			got, err := ParseReader(strings.NewReader(src))
			if err != nil {
				t.Fatalf("ParseReader: %v", err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("streaming diverges from Parse:\nwant %+v\ngot  %+v", want, got)
			}
		})
	}
}

type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n > 0 {
		f.n--
		return copy(p, []byte("[ 1.0] [ T1] some line\n")), nil
	}
	return 0, fmt.Errorf("disk on fire")
}

func TestParseReader_ReadError(t *testing.T) {
	if _, err := ParseReader(&failingReader{n: 3}); err == nil {
		t.Error("expected error from failing reader")
	}
}
