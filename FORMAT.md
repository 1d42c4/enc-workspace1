# enc-workspace1 file format, version 1

This project-specific envelope uses standard AEAD primitives. It is not compatible
with enc-workspace, OpenSSL command-line file formats, age, or standalone AEAD blobs.
All integer fields are unsigned little-endian unless specified otherwise.

## Header (64 bytes)

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 8 | ASCII `ENCWS1` followed by CR LF |
| 8 | 1 | Format version, exactly 1 |
| 9 | 1 | Algorithm: 1 ChaCha20-Poly1305; 2 XChaCha20-Poly1305; 3 AES-128-GCM; 4 AES-256-GCM; 5 AES-128-GCM-SIV; 6 AES-256-GCM-SIV |
| 10 | 1 | Mode: 1 password; 2 secret key file; 3 public embedded key |
| 11 | 1 | KDF profile: 1 in password mode, 0 otherwise |
| 12 | 4 | Chunk size, exactly 65536 |
| 16 | 8 | Plaintext length, at most 2^36 bytes (64 GiB) |
| 24 | 32 | Fresh OS-random salt generated for each encryption |
| 56 | 8 | Reserved, all zero |

An app accepts only its algorithm and mode, fixed version/profile/chunk size,
zero reserved bytes, and supported length. The exact encrypted file size must be
`64 + L + 16 * (ceil(L/65536) + 1)`. Empty files still have a final record.

## Credentials, keys, and nonces

Password mode: UTF-8 password bytes (no Unicode normalization) are passed to
Argon2id version 0x13 with the 32-byte header salt, memory 65536 KiB, 3 iterations,
1 lane, and 32-byte output. These parameters are fixed by profile 1.
Key-file mode: the 32 raw bytes are the master key. Embedded mode: the app's
committed public seed is the master key. Credentials must match the selected mode.

HKDF-SHA256 extract uses the header salt and master key. For zero-based record
index `i`, let `segment = floor(i/4096)`. HKDF expand uses this info:

```
ASCII("enc-workspace1/v1/segment-key/") || header[8:12] || LE64(segment)
```

The output length is 16 for AES-128 variants and 32 for all others. Each segment
has a separate cipher key; an ordinary segment covers 256 MiB of plaintext.
The nonce is zero bytes followed by BE64(i), with total length 24 for XChaCha and
12 for the other algorithms. Nonces are unique under each derived key; cross-file
separation relies on the fresh 256-bit random salt. There is no salt/nonce override.

## Authenticated records

Data is split into 65536-byte chunks, with the last data chunk shorter if needed.
Each record is ciphertext followed by the full 16-byte AEAD tag. AAD is:

```
header[0:64] || LE64(i) || LE32(plaintext_record_length) || final_flag
```

Data records use final_flag 0. After all data, one mandatory empty plaintext record
uses the next index and final_flag 1; its encoding is just its tag. For empty files
this is record 0. This binds metadata, lengths, order and finality; swapping,
repeating, truncating or appending records is rejected. No extra bytes are allowed.

Decryption writes authenticated chunks to a private temporary file in the output
directory. Only after the final tag and EOF verify is it flushed, synced, and
published with `persist_noclobber`. A failed operation removes the temporary file
during normal error unwinding. A process crash may leave a private temporary file.

Future incompatible changes require a new format version. App numbering, mode and
algorithm IDs, public embedded seeds and derivation domains are compatibility data.
