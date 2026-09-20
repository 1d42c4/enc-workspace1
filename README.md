# enc-workspace1

18 separate file-encryption apps, **a1 through a18**, in one Rust workspace.
Six established authenticated encryption variants, each offered with a password,
a random key file, or an intentionally public embedded key. One shared support
library handles file framing, credentials, and safe output publication.

This is a separate project with its own app numbering and format. It does not
replace or read encrypted files from `enc-workspace`.

| Algorithm | Password | Key file | Public embedded key |
| --- | --- | --- | --- |
| ChaCha20-Poly1305 | [a1](a1/README.md) | [a2](a2/README.md) | [a3](a3/README.md) |
| XChaCha20-Poly1305 | [a4](a4/README.md) | [a5](a5/README.md) | [a6](a6/README.md) |
| AES-128-GCM | [a7](a7/README.md) | [a8](a8/README.md) | [a9](a9/README.md) |
| AES-256-GCM | [a10](a10/README.md) | [a11](a11/README.md) | [a12](a12/README.md) |
| AES-128-GCM-SIV | [a13](a13/README.md) | [a14](a14/README.md) | [a15](a15/README.md) |
| AES-256-GCM-SIV | [a16](a16/README.md) | [a17](a17/README.md) | [a18](a18/README.md) |

## Choose an app

Use **a4 (XChaCha20-Poly1305/password)** for the default password workflow,
**a5 (XChaCha20-Poly1305/key file)** for a separately stored random key, or
**a17 (AES-256-GCM-SIV/key file)** for the AES-GCM-SIV alternative.
Every app uses a full 128-bit authentication tag. ChaCha variants use 20 rounds.

**Embedded-key apps provide no secrecy or trustworthy sender authentication
against anyone who has the app or source.** They are convenient informal tools;
anyone can decrypt their files or make new valid encrypted files. Their CLI prints
this warning on every invocation. Choose a password/key-file app for private data.

## Build one app

Install Rust through rustup and, on Windows, the Visual Studio C++ build tools
and Windows SDK. `rust-toolchain.toml` selects Rust 1.98.1, rustfmt, and Clippy.
The code targets Windows and Unix desktop systems.

On Windows, double-click **build.cmd**, then choose an app number. It builds
only that app and its dependencies and copies the executable to **dist/aN/**.

```powershell
.\build.cmd -App a4
.\build.cmd -App a5 -Action test
.\build.cmd -App a17 -Action lint
```

Standard Cargo commands also work:

```console
cargo build --locked --release -p a4
cargo test --locked -p a4 -- --test-threads=2
cargo clippy --locked -p a4 --all-targets -- -D warnings
```

Run Cargo inside an app folder to select that package automatically. A bare root
`cargo build` selects a4. `cargo build --workspace --release --bins` builds all 18.
One root `Cargo.lock` pins the dependencies and one shared `target/` caches builds.
`cargo clean` at the root cleans the entire Cargo build cache at once; it does
not remove the convenience copies in `dist/`. Both directories are ignored by Git.

## Use the apps

All commands take an input file and an explicit **new** output path. They retain
the input and refuse to replace existing output. On Linux use the same commands
without `.exe` and with `/` path separators.

Password app (hidden prompt; encryption asks twice):

```powershell
.\dist\a4\a4.exe encrypt .\document.pdf .\document.pdf.enc
.\dist\a4\a4.exe decrypt .\document.pdf.enc .\restored.pdf
```

Key-file app (keep a backup of the secret key separately from encrypted data):

```powershell
.\dist\a5\a5.exe keygen .\secret.key
.\dist\a5\a5.exe encrypt .\document.pdf .\document.pdf.enc --key .\secret.key
.\dist\a5\a5.exe decrypt .\document.pdf.enc .\restored.pdf --key .\secret.key
```

Embedded-key app:

```powershell
.\dist\a6\a6.exe encrypt .\example.txt .\example.txt.enc
.\dist\a6\a6.exe decrypt .\example.txt.enc .\restored.txt
```

Password apps also support `--password-file PATH` for automation. The file holds
one UTF-8 line: at most one terminal LF or CRLF is removed; all spaces and other
UTF-8 bytes are preserved. NUL and embedded line endings are rejected. Use the
same spelling and normalization when typing it later. Encryption requires at
least 12 UTF-8 bytes; use a long, unpredictable passphrase, not merely 12 known
characters. The maximum is 1024 bytes. No password argument or environment
variable is accepted. Protect password files as secrets and avoid committing them.

Key files contain exactly 32 raw random bytes, even for AES-128 apps: HKDF derives
the required cipher key size. Generate them with `keygen`, not by typing text.
There is no recovery mechanism for lost keys or forgotten passwords.

## Implementation and tests

RustCrypto supplies the ciphers, Argon2id and HKDF. The apps use a documented,
versioned file envelope with fresh OS randomness, 64 KiB records, authenticated
metadata and ordering, a mandatory authenticated ending, and a new derived cipher
key every 256 MiB. Maximum plaintext size: 64 GiB. Password derivation uses
Argon2id v19 with 64 MiB memory, 3 passes, and 1 lane. Input cannot choose larger
KDF costs. Memory use is bounded; file size does not cause a whole-file allocation.

Plaintext goes to a private temporary file and is published only after the entire
encrypted file verifies. Windows files receive a protected owner/SYSTEM DACL at
creation; Unix files use mode 0600. Existing files are never overwritten.

```console
cargo test --locked --workspace -- --test-threads=2
cargo fmt --all --check
rustfmt --edition 2024 --check support/tests/app_tests.rs
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo doc --locked --workspace --no-deps
```

Each app has integration and real executable tests. Shared tests include published
NIST/RFC vectors, key-file validation, private permissions, no-clobber races,
rekey boundaries and password handling. Committed fixtures come from an independent
OpenSSL/libsodium implementation. See [verification](verification/README.md),
[the format specification](FORMAT.md), [security limits](SECURITY.md), and
[recorded validation](AUDIT.md). These checks are not an independent security audit.
