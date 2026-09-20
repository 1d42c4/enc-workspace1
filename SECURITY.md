# Security model and limits

Password and random-key apps aim to protect file contents against an attacker who
can read or modify encrypted files but cannot obtain the password/master key or
control the machine running the app. Every mode uses authenticated encryption.

Embedded-key apps have public credentials. They cannot provide confidentiality or
sender authenticity against anyone with the source or executable. Their useful
role is informal reversible encoding with accidental-damage detection.

## Design checks

- Ciphers are RustCrypto implementations of full-round ChaCha20-Poly1305,
  XChaCha20-Poly1305, AES-GCM and AES-GCM-SIV, not handwritten cipher code.
- A fresh 256-bit OS-random salt selects different derived keys for every file.
  Monotonic record nonces, domain-separated HKDF keys, and rekeying every 4096
  records limit key reuse. Randomness failures stop encryption.
- All metadata, indices, record lengths and finality are authenticated. The parser
  checks length bounds before allocation/KDF work. Untrusted KDF parameters cannot
  increase resource use. Argon2id remains deliberately costly (64 MiB, 3 passes).
- Outputs and generated keys start private: Unix mode 0600, Windows protected DACL
  granting the file owner and SYSTEM access. Existing files are never overwritten.
- Only authenticated whole-file results are published. No streaming plaintext is
  exposed through stdout. Caller-provided input/output/key directories must be
  trusted; this is not a sandbox for hostile local filesystem races.
- Application password, master-key, derived-key, Argon2 work-memory and record
  buffers use zeroization. This is best effort: library/internal copies, registers,
  allocator behavior, swap, hibernation and crash dumps are not comprehensively
  controlled. HKDF internal state is not guaranteed to be erased.

## Limits

This is newly written application/framing code with implementation review and
tests, **not an independent professional cryptographic audit or certification**.
RustCrypto's AES-GCM and ChaCha crates document a historical NCC Group audit;
that does not audit these apps or all later dependency releases. The selected
AES-GCM-SIV crate explicitly states that the crate itself has not been audited.

Use long, unpredictable passwords. Argon2 raises guessing cost but cannot protect
a weak password. Keep keys/password backups; there is no recovery service.
Encryption does not remove the original plaintext, securely erase storage, hide
file sizes, filenames or access patterns, or prevent replay of an older valid
ciphertext. Local administrators, malware, another process running as the same
user, and compromised OS random sources are outside the protection boundary.
Do not modify input files while an operation is running; length changes are
detected but a filesystem snapshot is not taken. File limits are 64 GiB per input.
Use local storage with normal atomic file-publication semantics; unusual network
filesystems may provide weaker guarantees. A crash can leave private temporary
files or an unsynced directory entry; this is not crash-proof backup software.

Pure software crypto assumes suitable constant-time CPU operations as documented
by upstream. This project targets desktop Windows/Unix; it does not claim support
for arbitrary microcontrollers or FIPS validation.

## Upstream references

- [RustCrypto AES-GCM security notes](https://docs.rs/aes-gcm/0.10.3/aes_gcm/)
- [RustCrypto ChaCha20-Poly1305 security notes](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
- [RustCrypto AES-GCM-SIV audit status](https://docs.rs/aes-gcm-siv/0.11.1/aes_gcm_siv/)
- [RFC 8439, ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html)
- [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)
- [RFC 8452, AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html)
- [RFC 9106, Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 5869, HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)

Dependencies are pinned by Cargo.lock. Check advisories again before future
releases. Please report security problems privately to the repository owner.
