# a3: ChaCha20-Poly1305 / embedded-key

**Public embedded key: anyone with this app or its source can decrypt and forge these files. Informal use only.**

The app includes a fixed public 32-byte seed. Fresh per-file salts still make repeated encryption different, but this does not turn a public key into a secret. Anyone holding the app can decrypt or forge any of its files. No credential options are accepted.

## Build and run

From the workspace root:

```console
cargo build --locked --release -p a3
cargo test --locked -p a3 -- --test-threads=2
```

The executable is `target/release/a3.exe` on Windows or `target/release/a3`
on Linux. `build.cmd -App a3` also copies it to `dist/a3/`.
From beside the executable:

```powershell
.\a3.exe encrypt input.dat encrypted.enc
.\a3.exe decrypt encrypted.enc restored.dat
```

The input remains intact. Output must not already exist. Decryption authenticates
all data before publishing the destination. Use this same numbered app to decrypt.
The file format is specific to enc-workspace1 and is not a raw cipher stream.

## Implementation and validation

Algorithm ID: 1; credential mode: 3.
Full 128-bit AEAD tags, 64 KiB authenticated records, fresh 256-bit file salts,
HKDF-SHA256 key separation, and rekeying every 256 MiB. The maximum input is 64 GiB.
The algorithm comes from RustCrypto; file handling comes from `solid-core`.

The app test suite covers empty/binary files, chunk boundaries, independent
reference decryption, wrong credentials, header/ciphertext/tag tampering,
truncation, appended data, reordered/duplicated/spliced records, no partial
publication, source/output preservation, and actual CLI behavior.
See [AUDIT.md](AUDIT.md) for run results and [security limits](../SECURITY.md).
