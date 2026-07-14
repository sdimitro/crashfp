// SPDX-License-Identifier: MIT

package dmesgcrash

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdimitro/crashfp/fingerprint"
)

var update = flag.Bool("update", false, "regenerate expected corpus files")

// TestCorpus runs every *.txt kernel log under testdata/corpus through
// Parse and fingerprint.ComputeFromKernelBacktrace, comparing against the
// matching *.expected file. This is the compatibility contract for
// consumers that compare fingerprints computed by different binaries: any
// change that alters parsing or hashing for these real-world logs fails
// here. Regenerate intentionally with:
//
//	go test ./dmesgcrash -run TestCorpus -update
func TestCorpus(t *testing.T) {
	logs, err := filepath.Glob(filepath.Join("testdata", "corpus", "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("corpus is empty; expected *.txt files under testdata/corpus")
	}

	for _, logPath := range logs {
		name := strings.TrimSuffix(filepath.Base(logPath), ".txt")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}

			c := Parse(string(raw))
			if c == nil {
				t.Fatal("Parse returned nil; corpus entries must contain a crash report")
			}
			fp := fingerprint.ComputeFromKernelBacktrace(c.StackTrace, c.PanicMessage)
			if fp == nil {
				t.Fatalf("no fingerprint from stack trace %v", c.StackTrace)
			}

			got := formatExpected(fp)
			expPath := strings.TrimSuffix(logPath, ".txt") + ".expected"

			if *update {
				if err := os.WriteFile(expPath, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated %s", expPath)
				return
			}

			want, err := os.ReadFile(expPath)
			if err != nil {
				t.Fatalf("read expected file: %v\nRun with -update to create it", err)
			}
			if got != string(want) {
				t.Errorf("fingerprint mismatch for %s\ngot:\n%swant:\n%s", name, got, want)
			}
		})
	}
}

// formatExpected serializes the fingerprint fields checked by the corpus
// as stable key=value lines.
func formatExpected(fp *fingerprint.Fingerprint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "fault_func=%s\n", fp.Inputs.FaultFunc)
	fmt.Fprintf(&b, "crash_type=%s\n", fp.Inputs.CrashType)
	fmt.Fprintf(&b, "funcs=%s\n", strings.Join(fp.Inputs.AllFuncs, ","))
	fmt.Fprintf(&b, "filtered=%d\n", fp.Inputs.Filtered)
	fmt.Fprintf(&b, "rip=%s\n", fp.RIP)
	fmt.Fprintf(&b, "top3=%s\n", fp.Top3)
	fmt.Fprintf(&b, "top5=%s\n", fp.Top5)
	fmt.Fprintf(&b, "full=%s\n", fp.Full)
	fmt.Fprintf(&b, "type_rip=%s\n", fp.TypeRIP)
	return b.String()
}
