"""Independent FORMAT.md implementation for tests only (OpenSSL + libsodium).

Install verification/requirements.txt in a Python virtual environment.
Run --fixtures to regenerate the fixed public test fixtures, or
--binary-dir target/release to cross-check all 18 actual Rust executables.
Never use the fixed fixture salts/keys below for real encryption.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import nacl
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b'correct horse battery staple 2026'
RAW_KEY = bytes([0x42])*32
FIXTURE_PLAIN = b'independent fixture\x00\xff'
CHUNK = 65536
MAX_LENGTH = 1 << 36

def master(app, salt):
    if app['mode_id'] == 1:
        return Argon2id(salt=salt, length=32, iterations=3, lanes=1, memory_cost=65536).derive(PASSWORD)
    if app['mode_id'] == 2:
        return RAW_KEY
    return hashlib.sha256(f'enc-workspace1/public-demo-key/{app["app"]}/v1'.encode()).digest()

def engine(app, root_key, header, index):
    algorithm = app['algorithm_id']
    key_size = 16 if algorithm in (3, 5) else 32
    info = b'enc-workspace1/v1/segment-key/' + header[8:12] + struct.pack('<Q', index // 4096)
    key = HKDF(algorithm=hashes.SHA256(), length=key_size, salt=header[24:56], info=info).derive(root_key)
    nonce = bytes((24 if algorithm == 2 else 12)-8) + struct.pack('>Q', index)
    if algorithm == 2:
        return (lambda msg, aad: crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key),
                lambda msg, aad: crypto_aead_xchacha20poly1305_ietf_decrypt(msg, aad, nonce, key))
    obj = (ChaCha20Poly1305 if algorithm == 1 else AESGCM if algorithm in (3, 4) else AESGCMSIV)(key)
    return lambda msg, aad: obj.encrypt(nonce, msg, aad), lambda msg, aad: obj.decrypt(nonce, msg, aad)

def header_for(app, length, salt):
    return b'ENCWS1\r\n' + bytes([1, app['algorithm_id'], app['mode_id'], int(app['mode_id'] == 1)]) + struct.pack('<IQ', CHUNK, length) + salt + bytes(8)

def encrypt_file(app, source, destination, salt=None):
    length = source.stat().st_size
    assert length <= MAX_LENGTH
    header = header_for(app, length, salt or os.urandom(32))
    root_key = master(app, header[24:56])
    with source.open('rb') as inp, destination.open('xb') as out:
        out.write(header)
        index = 0
        while plain := inp.read(CHUNK):
            seal, _ = engine(app, root_key, header, index)
            out.write(seal(plain, header + struct.pack('<QIB', index, len(plain), 0)))
            index += 1
        seal, _ = engine(app, root_key, header, index)
        out.write(seal(b'', header + struct.pack('<QIB', index, 0, 1)))

def decrypt_digest(app, source):
    digest = hashlib.sha256()
    with source.open('rb') as inp:
        header = inp.read(64)
        assert len(header) == 64
        length = struct.unpack('<Q', header[16:24])[0]
        assert length <= MAX_LENGTH and header == header_for(app, length, header[24:56])
        assert source.stat().st_size == 64 + length + ((length + CHUNK-1)//CHUNK+1)*16
        root_key = master(app, header[24:56])
        remaining = length
        index = 0
        while remaining:
            count = min(remaining, CHUNK)
            _, open_record = engine(app, root_key, header, index)
            digest.update(open_record(inp.read(count+16), header + struct.pack('<QIB', index, count, 0)))
            remaining -= count
            index += 1
        _, open_record = engine(app, root_key, header, index)
        assert open_record(inp.read(16), header + struct.pack('<QIB', index, 0, 1)) == b''
        assert not inp.read(1)
    return digest.hexdigest()

def digest_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def invoke(binary, app, action, source, output, directory):
    args = [str(binary), action, str(source), str(output)]
    if app['mode_id'] == 1:
        secret = directory / 'password.txt'
        secret.write_bytes(PASSWORD)
        args += ['--password-file', str(secret)]
    elif app['mode_id'] == 2:
        secret = directory / 'secret.key'
        secret.write_bytes(RAW_KEY)
        args += ['--key', str(secret)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, (app['app'], result.stderr)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixtures', action='store_true')
    parser.add_argument('--binary-dir', type=Path)
    parser.add_argument('--large', action='store_true', help='Also check a 256 MiB + 1 byte file across the rekey boundary for all six ciphers.')
    args = parser.parse_args()
    apps = json.loads((ROOT / 'apps.json').read_text())
    results = []
    for app in apps:
        with tempfile.TemporaryDirectory(prefix='encws1-reference-') as directory:
            directory = Path(directory)
            plain = directory / 'plain'
            if args.fixtures:
                plain.write_bytes(FIXTURE_PLAIN)
                sealed = directory / 'fixture'
                salt = hashlib.sha256(('fixture-only/' + app['app']).encode()).digest()
                encrypt_file(app, plain, sealed, salt)
                target = ROOT / 'verification' / 'fixtures' / (app['app'] + '.hex')
                target.parent.mkdir(exist_ok=True)
                target.write_text(sealed.read_bytes().hex()+'\n')
            if args.binary_dir:
                binary = args.binary_dir.resolve() / (app['app'] + ('.exe' if os.name == 'nt' else ''))
                cases = [0, 2*CHUNK+317]
                if args.large and app['mode_id'] == 2:
                    cases.append(256*1024*1024+1)
                for length in cases:
                    with plain.open('wb') as out:
                        chunk = bytes(range(256))*256
                        for _ in range(length//len(chunk)):
                            out.write(chunk)
                        out.write(chunk[:length%len(chunk)])
                    expected = digest_file(plain)
                    rust_file = directory / f'rust-{length}'
                    reference_file = directory / f'python-{length}'
                    restored = directory / f'restored-{length}'
                    invoke(binary, app, 'encrypt', plain, rust_file, directory)
                    assert decrypt_digest(app, rust_file) == expected
                    encrypt_file(app, plain, reference_file)
                    invoke(binary, app, 'decrypt', reference_file, restored, directory)
                    assert digest_file(restored) == expected
                    results.append({'app': app['app'], 'bytes': length, 'rust_to_reference': True, 'reference_to_rust': True})
        print(app['app'] + ': independent checks passed', flush=True)
    if args.binary_dir:
        report = {'cryptography': cryptography.__version__, 'pynacl': nacl.__version__, 'cases': results, 'directions_passed': len(results)*2}
        (ROOT / 'verification' / 'independent-results.json').write_text(json.dumps(report, indent=2)+'\n')

if __name__ == '__main__':
    main()
