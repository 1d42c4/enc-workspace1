# Implementation review and validation

Recorded 2026-09-20T20:22:51.607898+00:00. Toolchain: Rust 1.98.1 on Windows x86_64 MSVC.

## Executed checks

- **452 Rust tests passed:** 24 integration/CLI tests for each of 18 apps, plus
  20 shared unit tests. No failed or ignored tests. The production Argon2 cost was
  used in password tests. Published known-answer vectors covered all six ciphers,
  Argon2id and HKDF-SHA256.
- **18 optimized Windows executables built and executed.** All apps have separate
  binaries. Both normal and release CLI runs were exercised.
- **84 independent direction checks passed:** OpenSSL/libsodium read Rust output
  and Rust read their output, for every app with empty and multi-record files;
  six additional 256 MiB + 1 byte cases crossed the actual rekey boundary, one
  per cipher family/size. See [independent results](verification/independent-results.json).
- All 18 apps decrypted committed independent full-format fixtures.
- Formatting (including shared include! tests), Clippy with warnings denied,
  and rustdoc with warnings denied passed.
- All workspace targets compile-checked for x86_64-unknown-linux-gnu. This local
  check did not run Linux executables. The checked-in CI workflow separately runs
  tests and release builds on Windows and Linux; consult GitHub Actions for its
  runtime results after publication.
- Windows build launcher selected and built a5 and copied its executable to dist/a5.
- 68 locked registry package versions were compared against non-withdrawn RustSec
  advisory ranges at database commit `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`; no affected
  versions found. This was a range-comparison script, not cargo-audit. See
  [the dependency report](verification/dependency-advisories.json).

## Implementation review

Reviewed algorithm/credential IDs, fixed KDF costs, fresh salt generation, HKDF
separation, nonce counters/rekeying, exact file sizing, full metadata AAD, mandatory
ending, rejection before plaintext publication, source preservation, no-clobber
publication races and private file creation. Regression tests exercise those
boundaries. The Windows ACL helper is reused from enc-workspace and tested here.
Application cipher code is supplied by the pinned RustCrypto dependencies.

Unused per-app unit-test harnesses are disabled; the actual integration tests and
the solid-core unit tests remain enabled. Initially Smart App Control blocked an
empty a12 harness. The user then disabled Smart App Control. Blocked checks were
resolved/rerun before the results above were recorded. Defender antivirus and
real-time protection remained enabled at the final status check. No Windows
protection setting was changed by the project or build launcher.

## Limits

This review and test suite is not an independent cryptographic audit. Interactive
hidden terminal prompting was reviewed but not manually tested in a real terminal;
automated CLI tests use password files. There was no long-running fuzz campaign,
timing/side-channel assessment, destructive disk-failure test, or testing on macOS,
network filesystems or arbitrary CPU architectures. Dependencies deliberately use
the compatible established aead 0.5/RustCrypto release family; newer major releases
exist and future upgrades must preserve interoperability and rerun these checks.

Read [SECURITY.md](SECURITY.md) for memory, crash, key management and embedded-key
limitations. Root [FORMAT.md](FORMAT.md) specifies the project-specific envelope.
