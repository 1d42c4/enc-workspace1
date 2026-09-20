# Maintenance

This is an independent workspace with 18 numbered apps and solid-core. Keep IDs,
algorithms, credential modes, embedded public seeds and v1 framing stable. Read
FORMAT.md and SECURITY.md before changing crypto or file handling. Do not add
raw/unauthenticated cipher modes or claim an independent security audit.

Use `cargo ... -p aN` for one app. Shared-core or shared-test changes require the
whole workspace test suite, formatting, strict Clippy and documentation checks.
Run `rustfmt --edition 2024 --check support/tests/app_tests.rs` separately: include!
files are not all discovered by cargo fmt. Add regression tests for fixes. Preserve
the independently generated fixtures; incompatible changes need a version change.
Run the independent OpenSSL/libsodium verifier after file-format/crypto changes.
Do not weaken tests or turn off Windows protection to hide a blocked check.

Update root and app AUDIT.md/README.md with actual results. Do not count cross-target
compile checks as runtime tests. Keep target/, dist/, secrets and temporary logs
out of Git. Embedded keys are intentionally public and must retain their warning.
