# crashfp

Deterministic fingerprints for Linux kernel crashes, computed from nothing
but text: the crash stack trace and the panic message. No vmcore analysis,
no debug symbols, no external tools — just the standard library.

`crashfp` is designed for crash deduplication: two occurrences of the same
kernel bug produce the same fingerprint, so a triage pipeline (or a tiny
utility running inside a crash kernel) can recognize a known issue by
comparing hashes.

## Packages

- **`fingerprint`** — computes SHA-256 deduplication hashes from a crash
  stack trace at five granularities (fault function, top-3, top-5, full
  stack, and crash-type + fault function). Accepts either drgn-symbolized
  frames or the kernel's own kallsyms backtrace as printed to the log;
  both paths hash identically. Frames are normalized to bare function
  names, and kernel exception-dispatch/scheduling plumbing frames are
  filtered out so fingerprints track root cause, not entry path.
- **`dmesgcrash`** — extracts a crash report (panic message, backtrace
  frames, module list, kernel banner, command line) from raw kernel log
  text, e.g. the output of `vmcore-dmesg /proc/vmcore` or
  `makedumpfile --dump-dmesg`. Handles x86 and arm64 oops formats,
  including RIP/PC fault-frame promotion and the arm64 LR fallback for
  indirect-call crashes.

Together they turn a raw kernel log into a fingerprint in two calls:

```go
crash := dmesgcrash.Parse(rawKernelLog)
fp := fingerprint.ComputeFromKernelBacktrace(crash.StackTrace, crash.PanicMessage)
fmt.Println(fp.TypeRIP) // e.g. 76571165e62ca40f...
```

## Install

```bash
go get github.com/sdimitro/crashfp
```

## Documentation

Full API documentation is on
[pkg.go.dev](https://pkg.go.dev/github.com/sdimitro/crashfp), including
runnable examples. Locally: `go doc github.com/sdimitro/crashfp/fingerprint`.

## Testing

The test suite includes a golden corpus of real (sanitized) kernel crash
logs with expected fingerprints under `dmesgcrash/testdata/corpus/`. Any
change that alters hashing behavior fails the corpus test — this is the
compatibility contract for consumers that compare fingerprints computed
by different binaries. Regenerate with:

```bash
go test ./dmesgcrash -run TestCorpus -update
```

## License

MIT — see [LICENSE](LICENSE).
