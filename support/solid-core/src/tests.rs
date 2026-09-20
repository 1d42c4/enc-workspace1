use super::*;
use aes_gcm::Aes256Gcm;
use hex_literal::hex;

const APP: App = App {
    name: "test",
    algorithm: 4,
    mode: Mode::KeyFile,
};

#[test]
fn header_length_limits_do_not_overflow() {
    assert_eq!(encoded_length(0).unwrap(), 80);
    assert!(encoded_length(MAX_PLAINTEXT).is_ok());
    assert!(encoded_length(MAX_PLAINTEXT + 1).is_err());
    assert!(encoded_length(u64::MAX).is_err());
    let h = header(APP, u64::MAX, &[0; 32]);
    assert!(parse_header(APP, &h).is_err());
}

#[test]
fn key_generation_is_random_exact_length_and_private() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    generate_key(&a).unwrap();
    generate_key(&b).unwrap();
    assert_ne!(*read_key(&a).unwrap(), *read_key(&b).unwrap());
    #[cfg(windows)]
    private_file::assert_private(&File::open(a).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(a).unwrap().permissions().mode() & 0o077, 0);
    }
}

#[test]
fn invalid_key_lengths_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    for n in [0, 1, 16, 31, 33, 64, 1024] {
        fs::write(&path, vec![0; n]).unwrap();
        assert!(read_key(&path).is_err());
    }
    fs::write(&path, [5; 32]).unwrap();
    assert_eq!(*read_key(&path).unwrap(), [5; 32]);
}

#[test]
fn password_file_is_bounded_and_preserves_spaces_and_unicode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("password");
    for suffix in ["", "\n", "\r\n"] {
        fs::write(&path, format!("  café 東京 long passphrase  {suffix}")).unwrap();
        assert_eq!(
            &*read_password(&path).unwrap(),
            "  café 東京 long passphrase  ".as_bytes()
        );
    }
    for bytes in [
        vec![],
        vec![b'a'; 1025],
        b"two\nlines".to_vec(),
        b"nul\0byte".to_vec(),
        vec![0xff],
    ] {
        fs::write(&path, bytes).unwrap();
        assert!(read_password(&path).is_err());
    }
    fs::write(&path, vec![b'a'; 1024]).unwrap();
    assert_eq!(read_password(&path).unwrap().len(), 1024);
}

#[test]
fn weak_password_rejected_before_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, b"secret").unwrap();
    let app = App {
        mode: Mode::Password,
        ..APP
    };
    assert!(encrypt::<Aes256Gcm>(app, Credential::Password(b"short"), &input, &output).is_err());
    assert!(!output.exists());
}

#[test]
fn mismatched_credential_modes_are_rejected() {
    for mode in [Mode::Password, Mode::Embedded] {
        assert!(credentials::master(mode, Credential::Key(&[1; 32]), &[2; 32]).is_err());
    }
    assert!(
        credentials::master(
            Mode::KeyFile,
            Credential::Password(b"long enough password"),
            &[2; 32]
        )
        .is_err()
    );
}

#[test]
fn no_clobber_publication_survives_destination_creation_race() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("output");
    let mut tmp = temporary(&output).unwrap();
    tmp.write_all(b"new").unwrap();
    fs::write(&output, b"existing").unwrap();
    assert!(publish(tmp, &output).is_err());
    assert_eq!(fs::read(output).unwrap(), b"existing");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn decryption_output_has_restricted_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let sealed = dir.path().join("sealed");
    let output = dir.path().join("output");
    fs::write(&input, b"secret").unwrap();
    encrypt::<Aes256Gcm>(APP, Credential::Key(&[1; 32]), &input, &sealed).unwrap();
    decrypt::<Aes256Gcm>(APP, Credential::Key(&[1; 32]), &sealed, &output).unwrap();
    #[cfg(windows)]
    private_file::assert_private(&File::open(output).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}

#[cfg(unix)]
#[test]
fn output_symlink_is_not_followed() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, &link).unwrap();
    assert!(generate_key(&link).is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

fn kat<C: AeadInPlace + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
    expected: &[u8],
) {
    let cipher = C::new_from_slice(key).unwrap();
    let mut n = Nonce::<C>::default();
    n.copy_from_slice(nonce);
    let mut buffer = plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&n, aad, &mut buffer)
        .unwrap();
    buffer.extend_from_slice(&tag);
    assert_eq!(buffer, expected);
    let size = buffer.len() - 16;
    let mut t = aead::Tag::<C>::default();
    t.copy_from_slice(&buffer[size..]);
    buffer.truncate(size);
    cipher
        .decrypt_in_place_detached(&n, aad, &mut buffer, &t)
        .unwrap();
    assert_eq!(buffer, plain);
}

#[test]
fn nist_aes128_gcm_known_answer() {
    kat::<aes_gcm::Aes128Gcm>(
        &[0; 16],
        &[0; 12],
        &[],
        &[0; 16],
        &hex!("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),
    );
}
#[test]
fn nist_aes256_gcm_known_answer() {
    kat::<Aes256Gcm>(
        &[0; 32],
        &[0; 12],
        &[],
        &[0; 16],
        &hex!("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
    );
}
#[test]
fn rfc8452_aes128_gcm_siv_known_answer() {
    kat::<aes_gcm_siv::Aes128GcmSiv>(
        &hex!("01000000000000000000000000000000"),
        &hex!("030000000000000000000000"),
        &[],
        &hex!("0100000000000000"),
        &hex!("b5d839330ac7b786578782fff6013b815b287c22493a364c"),
    );
}
#[test]
fn rfc8452_aes256_gcm_siv_known_answer() {
    kat::<aes_gcm_siv::Aes256GcmSiv>(
        &hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        &hex!("030000000000000000000000"),
        &[],
        &hex!("0100000000000000"),
        &hex!("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
    );
}

const VECTOR_PLAIN:&[u8]=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const VECTOR_KEY: [u8; 32] =
    hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const VECTOR_AAD: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
#[test]
fn rfc8439_chacha20_poly1305_known_answer() {
    kat::<chacha20poly1305::ChaCha20Poly1305>(
        &VECTOR_KEY,
        &hex!("070000004041424344454647"),
        &VECTOR_AAD,
        VECTOR_PLAIN,
        &hex!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ),
    );
}
#[test]
fn xchacha_draft_known_answer() {
    kat::<chacha20poly1305::XChaCha20Poly1305>(
        &VECTOR_KEY,
        &hex!("404142434445464748494a4b4c4d4e4f5051525354555657"),
        &VECTOR_AAD,
        VECTOR_PLAIN,
        &hex!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        ),
    );
}

#[test]
fn rfc5869_hkdf_sha256_known_answer() {
    let hk = Hkdf::<Sha256>::new(Some(&hex!("000102030405060708090a0b0c")), &[0x0b; 22]);
    let mut out = [0; 42];
    hk.expand(&hex!("f0f1f2f3f4f5f6f7f8f9"), &mut out).unwrap();
    assert_eq!(
        out,
        hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
}

#[test]
fn rfc9106_argon2id_known_answer() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[4; 12]).unwrap())
        .build()
        .unwrap();
    let ctx =
        Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0; 32];
    ctx.hash_password_into(&[1; 32], &[2; 16], &mut out)
        .unwrap();
    assert_eq!(
        out,
        hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

fn segment_boundary<C: AeadInPlace + KeyInit>(algorithm: u8) {
    let app = App { algorithm, ..APP };
    let h = header(app, 1, &[7; 32]);
    let mut cipher = RecordCipher::<C>::new(app, Credential::Key(&[1; 32]), &h).unwrap();
    for index in [4095, 4096, 4097, 8191, 8192] {
        let mut record = Zeroizing::new(b"boundary".to_vec());
        cipher.seal(&h, index, false, &mut record).unwrap();
        let mut receiver = RecordCipher::<C>::new(app, Credential::Key(&[1; 32]), &h).unwrap();
        receiver.open(&h, index, false, &mut record).unwrap();
        assert_eq!(&*record, b"boundary");
    }
    let mut r = Zeroizing::new(b"test".to_vec());
    cipher.seal(&h, 4096, false, &mut r).unwrap();
    assert!(cipher.open(&h, 4095, false, &mut r).is_err());
}

#[test]
fn all_ciphers_rekey_and_authenticate_at_segment_boundaries() {
    segment_boundary::<chacha20poly1305::ChaCha20Poly1305>(1);
    segment_boundary::<chacha20poly1305::XChaCha20Poly1305>(2);
    segment_boundary::<aes_gcm::Aes128Gcm>(3);
    segment_boundary::<Aes256Gcm>(4);
    segment_boundary::<aes_gcm_siv::Aes128GcmSiv>(5);
    segment_boundary::<aes_gcm_siv::Aes256GcmSiv>(6);
}

#[test]
fn final_flag_and_length_are_authenticated_separately() {
    let h = header(APP, 0, &[3; 32]);
    let mut cipher = RecordCipher::<Aes256Gcm>::new(APP, Credential::Key(&[1; 32]), &h).unwrap();
    let mut record = Zeroizing::new(Vec::new());
    cipher.seal(&h, 0, true, &mut record).unwrap();
    assert!(cipher.open(&h, 0, false, &mut record).is_err());
}
