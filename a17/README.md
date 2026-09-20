# a17: AES-256-GCM-SIV / key-file

`keygen` generates exactly 32 raw random bytes in a private file. `--key PATH` is required; text/hex and wrong-length key files are rejected. The master key is expanded with HKDF to the algorithm-specific key length. Store a backup securely; lost keys cannot be recovered.

## Build and run

From the workspace root:

```console
cargo build --locked --release -p a17
cargo test --locked -p a17 -- --test-threads=2
```

The executable is `target/release/a17.exe` on Windows or `target/release/a17`
on Linux. `build.cmd -App a17` also copies it to `dist/a17/`.
From beside the executable:

```powershell
.\a17.exe keygen secret.key
.\a17.exe encrypt input.dat encrypted.enc --key secret.key
.\a17.exe decrypt encrypted.enc restored.dat --key secret.key
```

The input remains intact. Output must not already exist. Decryption authenticates
all data before publishing the destination. Use this same numbered app to decrypt.
The file format is specific to enc-workspace1 and is not a raw cipher stream.

## Implementation and validation

Algorithm ID: 6; credential mode: 2.
Full 128-bit AEAD tags, 64 KiB authenticated records, fresh 256-bit file salts,
HKDF-SHA256 key separation, and rekeying every 256 MiB. The maximum input is 64 GiB.
The algorithm comes from RustCrypto; file handling comes from `solid-core`.

The app test suite covers empty/binary files, chunk boundaries, independent
reference decryption, wrong credentials, header/ciphertext/tag tampering,
truncation, appended data, reordered/duplicated/spliced records, no partial
publication, source/output preservation, and actual CLI behavior.
See [AUDIT.md](AUDIT.md) for run results and [security limits](../SECURITY.md).
