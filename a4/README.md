# a4: XChaCha20-Poly1305 / password

The password is entered without echo and confirmed on encryption. Argon2id v19 derives a 32-byte master key using 64 MiB memory, 3 passes and 1 lane. Use a strong passphrase (12–1024 UTF-8 bytes for encryption). `--password-file PATH` supports a single UTF-8 line for automation; one final LF/CRLF is removed, spaces remain significant. No password is accepted on the command line.

## Build and run

From the workspace root:

```console
cargo build --locked --release -p a4
cargo test --locked -p a4 -- --test-threads=2
```

The executable is `target/release/a4.exe` on Windows or `target/release/a4`
on Linux. `build.cmd -App a4` also copies it to `dist/a4/`.
From beside the executable:

```powershell
.\a4.exe encrypt input.dat encrypted.enc
.\a4.exe decrypt encrypted.enc restored.dat
```

The input remains intact. Output must not already exist. Decryption authenticates
all data before publishing the destination. Use this same numbered app to decrypt.
The file format is specific to enc-workspace1 and is not a raw cipher stream.

## Implementation and validation

Algorithm ID: 2; credential mode: 1.
Full 128-bit AEAD tags, 64 KiB authenticated records, fresh 256-bit file salts,
HKDF-SHA256 key separation, and rekeying every 256 MiB. The maximum input is 64 GiB.
The algorithm comes from RustCrypto; file handling comes from `solid-core`.

The app test suite covers empty/binary files, chunk boundaries, independent
reference decryption, wrong credentials, header/ciphertext/tag tampering,
truncation, appended data, reordered/duplicated/spliced records, no partial
publication, source/output preservation, and actual CLI behavior.
See [AUDIT.md](AUDIT.md) for run results and [security limits](../SECURITY.md).
