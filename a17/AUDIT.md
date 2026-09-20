# a17 validation

AES-256-GCM-SIV, key-file; verified with Rust 1.98.1 on Windows.

- 24 integration/CLI tests passed for this app's configured cipher and credential mode.
- Optimized Windows executable built and exercised in independent reference tests.
- Fixed independent OpenSSL/libsodium envelope decrypted successfully.
- Empty and multi-record files verified in both directions against the independent
  implementation. A 256 MiB + 1 byte file also passed both directions across rekeying.
- Formatting, strict Clippy, rustdoc, and Linux cross-target compile checks passed.
  Local Linux compile checks are not runtime tests; CI runs tests on Linux separately.

Shared code also passed 20 unit tests (published primitive/KDF vectors, permissions,
password/key handling, no-clobber publication and rekey boundaries). See
[the workspace validation record](../AUDIT.md) and [security limits](../SECURITY.md).
This is tested application code, not an independent cryptographic audit.
