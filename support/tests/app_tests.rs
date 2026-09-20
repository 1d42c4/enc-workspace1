// Included by every app: the actual configured cipher and executable are tested.
use solid_core::{CHUNK_SIZE, Credential, HEADER_SIZE, Mode, TAG_SIZE};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const KEY: [u8; 32] = [0x42; 32];
const PASSWORD: &[u8] = b"correct horse battery staple 2026";

fn credential() -> Credential<'static> {
    match APP.mode {
        Mode::Password => Credential::Password(PASSWORD),
        Mode::KeyFile => Credential::Key(&KEY),
        Mode::Embedded => Credential::Embedded(EMBEDDED_KEY.unwrap()),
    }
}

fn payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|n| ((n * 73 + n / 251) % 256) as u8)
        .collect()
}

fn fixture(size: usize) -> (tempfile::TempDir, PathBuf, PathBuf, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.dat");
    let encrypted = dir.path().join("sealed.enc");
    let data = payload(size);
    fs::write(&input, &data).unwrap();
    solid_core::encrypt::<Cipher>(APP, credential(), &input, &encrypted).unwrap();
    (dir, input, encrypted, data)
}

fn assert_rejected(dir: &Path, bytes: &[u8]) {
    let damaged = dir.join("damaged.enc");
    let output = dir.join("must-not-exist");
    fs::write(&damaged, bytes).unwrap();
    assert!(solid_core::decrypt::<Cipher>(APP, credential(), &damaged, &output).is_err());
    assert!(
        !output.exists(),
        "unauthenticated output must never be published"
    );
    assert!(
        !fs::read_dir(dir).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".enc-workspace1-")),
        "failed operation left a temporary file"
    );
}

fn round_trip(size: usize) {
    let (dir, input, encrypted, data) = fixture(size);
    let output = dir.path().join("restored.dat");
    solid_core::decrypt::<Cipher>(APP, credential(), &encrypted, &output).unwrap();
    assert_eq!(fs::read(input).unwrap(), data);
    assert_eq!(fs::read(output).unwrap(), data);
    assert_eq!(
        fs::metadata(encrypted).unwrap().len(),
        (HEADER_SIZE + size + (size.div_ceil(CHUNK_SIZE) + 1) * TAG_SIZE) as u64
    );
}

#[test]
fn empty_file_round_trip() {
    round_trip(0);
}
#[test]
fn one_byte_round_trip() {
    round_trip(1);
}
#[test]
fn below_chunk_boundary() {
    round_trip(CHUNK_SIZE - 1);
}
#[test]
fn exact_chunk_boundary() {
    round_trip(CHUNK_SIZE);
}
#[test]
fn above_chunk_boundary() {
    round_trip(CHUNK_SIZE + 1);
}
#[test]
fn multiple_chunks_and_binary_bytes() {
    round_trip(2 * CHUNK_SIZE + 17);
}

#[test]
fn algorithm_and_mode_are_bound_to_the_numbered_app() {
    let number: u8 = APP.name.strip_prefix('a').unwrap().parse().unwrap();
    assert_eq!(number, (APP.algorithm - 1) * 3 + APP.mode as u8);
    assert_eq!(EMBEDDED_KEY.is_some(), APP.mode == Mode::Embedded);
    let (dir, _, encrypted, _) = fixture(32);
    let mut other = APP;
    other.mode = if APP.mode == Mode::Password {
        Mode::KeyFile
    } else {
        Mode::Password
    };
    assert!(
        solid_core::decrypt::<Cipher>(
            other,
            credential(),
            &encrypted,
            &dir.path().join("wrong-mode")
        )
        .is_err()
    );
    other = APP;
    other.algorithm = if APP.algorithm == 6 {
        1
    } else {
        APP.algorithm + 1
    };
    assert!(
        solid_core::decrypt::<Cipher>(
            other,
            credential(),
            &encrypted,
            &dir.path().join("wrong-algorithm")
        )
        .is_err()
    );
}

#[test]
fn repeated_encryption_has_distinct_salts_and_ciphertext() {
    let (dir, input, encrypted, _) = fixture(80);
    let second = dir.path().join("second.enc");
    solid_core::encrypt::<Cipher>(APP, credential(), &input, &second).unwrap();
    let first = fs::read(encrypted).unwrap();
    let second = fs::read(second).unwrap();
    assert_ne!(&first[24..56], &second[24..56]);
    assert_ne!(&first[HEADER_SIZE..], &second[HEADER_SIZE..]);
}

#[test]
fn wrong_credentials_never_publish_plaintext() {
    let (dir, _, encrypted, _) = fixture(CHUNK_SIZE + 9);
    let wrong = match APP.mode {
        Mode::Password => Credential::Password(b"this is the wrong password"),
        Mode::KeyFile => Credential::Key(&[7; 32]),
        Mode::Embedded => Credential::Embedded(&[7; 32]),
    };
    let output = dir.path().join("wrong");
    assert!(solid_core::decrypt::<Cipher>(APP, wrong, &encrypted, &output).is_err());
    assert!(!output.exists());
}

#[test]
fn every_header_byte_is_validated_or_authenticated() {
    let (dir, _, encrypted, _) = fixture(19);
    let original = fs::read(encrypted).unwrap();
    for index in 0..HEADER_SIZE {
        let mut changed = original.clone();
        changed[index] ^= 1;
        assert_rejected(dir.path(), &changed);
    }
}

#[test]
fn ciphertext_record_tags_and_final_tag_are_authenticated() {
    let (dir, _, encrypted, _) = fixture(CHUNK_SIZE + 9);
    let original = fs::read(encrypted).unwrap();
    for index in [
        HEADER_SIZE,
        HEADER_SIZE + CHUNK_SIZE - 1,
        HEADER_SIZE + CHUNK_SIZE,
        HEADER_SIZE + CHUNK_SIZE + TAG_SIZE,
        original.len() - 17,
        original.len() - 1,
    ] {
        let mut changed = original.clone();
        changed[index] ^= 0x80;
        assert_rejected(dir.path(), &changed);
    }
}

#[test]
fn truncation_including_whole_final_record_is_rejected() {
    let (dir, _, encrypted, _) = fixture(CHUNK_SIZE + 9);
    let original = fs::read(encrypted).unwrap();
    for end in (0..=HEADER_SIZE).chain([
        HEADER_SIZE + 1,
        HEADER_SIZE + CHUNK_SIZE + TAG_SIZE,
        original.len() - 16,
        original.len() - 1,
    ]) {
        assert_rejected(dir.path(), &original[..end]);
    }
}

#[test]
fn trailing_bytes_and_concatenated_files_are_rejected() {
    let (dir, _, encrypted, _) = fixture(32);
    let mut original = fs::read(encrypted).unwrap();
    let doubled = [original.clone(), original.clone()].concat();
    assert_rejected(dir.path(), &doubled);
    original.push(0);
    assert_rejected(dir.path(), &original);
}

#[test]
fn reordered_and_duplicated_records_are_rejected() {
    let (dir, _, encrypted, _) = fixture(2 * CHUNK_SIZE);
    let original = fs::read(encrypted).unwrap();
    let record = CHUNK_SIZE + TAG_SIZE;
    let mut reordered = original.clone();
    reordered[HEADER_SIZE..HEADER_SIZE + record]
        .copy_from_slice(&original[HEADER_SIZE + record..HEADER_SIZE + record * 2]);
    reordered[HEADER_SIZE + record..HEADER_SIZE + record * 2]
        .copy_from_slice(&original[HEADER_SIZE..HEADER_SIZE + record]);
    assert_rejected(dir.path(), &reordered);
    let mut duplicate = original.clone();
    duplicate[HEADER_SIZE + record..HEADER_SIZE + record * 2]
        .copy_from_slice(&original[HEADER_SIZE..HEADER_SIZE + record]);
    assert_rejected(dir.path(), &duplicate);
}

#[test]
fn cross_file_record_splicing_is_rejected() {
    let (dir, input, encrypted, _) = fixture(2 * CHUNK_SIZE);
    let second = dir.path().join("second.enc");
    solid_core::encrypt::<Cipher>(APP, credential(), &input, &second).unwrap();
    let mut first = fs::read(encrypted).unwrap();
    let other = fs::read(second).unwrap();
    first[HEADER_SIZE..HEADER_SIZE + CHUNK_SIZE + TAG_SIZE]
        .copy_from_slice(&other[HEADER_SIZE..HEADER_SIZE + CHUNK_SIZE + TAG_SIZE]);
    assert_rejected(dir.path(), &first);
}

#[test]
fn authenticated_prefix_is_not_published_when_final_tag_is_wrong() {
    let (dir, _, encrypted, _) = fixture(3 * CHUNK_SIZE);
    let mut bytes = fs::read(encrypted).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert_rejected(dir.path(), &bytes);
}

#[test]
fn existing_outputs_and_input_are_preserved() {
    let (dir, input, encrypted, data) = fixture(40);
    let output = dir.path().join("existing");
    fs::write(&output, b"keep this").unwrap();
    assert!(solid_core::encrypt::<Cipher>(APP, credential(), &input, &output).is_err());
    assert!(solid_core::decrypt::<Cipher>(APP, credential(), &encrypted, &output).is_err());
    assert!(solid_core::encrypt::<Cipher>(APP, credential(), &input, &input).is_err());
    assert!(solid_core::decrypt::<Cipher>(APP, credential(), &encrypted, &encrypted).is_err());
    assert_eq!(fs::read(output).unwrap(), b"keep this");
    assert_eq!(fs::read(input).unwrap(), data);
}

#[test]
fn directories_and_missing_inputs_fail_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("output");
    assert!(solid_core::encrypt::<Cipher>(APP, credential(), dir.path(), &output).is_err());
    assert!(
        solid_core::decrypt::<Cipher>(APP, credential(), &dir.path().join("missing"), &output)
            .is_err()
    );
    assert!(!output.exists());
}

fn cli_credentials(dir: &Path, command: &mut Command) {
    match APP.mode {
        Mode::Password => {
            let p = dir.join("password.txt");
            fs::write(&p, PASSWORD).unwrap();
            command.arg("--password-file").arg(p);
        }
        Mode::KeyFile => {
            let p = dir.join("secret.key");
            fs::write(&p, KEY).unwrap();
            command.arg("--key").arg(p);
        }
        Mode::Embedded => (),
    }
}

#[test]
fn executable_encrypts_decrypts_and_preserves_unicode_paths() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input résumé 日本語.dat");
    let encrypted = dir.path().join("sealed.enc");
    let output = dir.path().join("output.dat");
    let data = payload(CHUNK_SIZE + 19);
    fs::write(&input, &data).unwrap();
    for (action, from, to) in [
        ("encrypt", &input, &encrypted),
        ("decrypt", &encrypted, &output),
    ] {
        let mut command = Command::new(EXE);
        command.arg(action).arg(from).arg(to);
        cli_credentials(dir.path(), &mut command);
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if APP.mode == Mode::Embedded {
            assert!(String::from_utf8_lossy(&result.stderr).contains("anyone with this app"));
        }
    }
    assert_eq!(fs::read(output).unwrap(), data);
    assert_eq!(fs::read(input).unwrap(), data);
}

#[test]
fn executable_reports_authentication_failure_with_nonzero_exit() {
    let (dir, _, encrypted, _) = fixture(32);
    let mut bytes = fs::read(&encrypted).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&encrypted, bytes).unwrap();
    let output = dir.path().join("output");
    let mut command = Command::new(EXE);
    command.arg("decrypt").arg(&encrypted).arg(&output);
    cli_credentials(dir.path(), &mut command);
    assert!(!command.output().unwrap().status.success());
    assert!(!output.exists());
}

#[test]
fn executable_rejects_inapplicable_credential_options() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, b"hello").unwrap();
    let option = if APP.mode == Mode::KeyFile {
        "--password-file"
    } else {
        "--key"
    };
    let result = Command::new(EXE)
        .arg("encrypt")
        .arg(input)
        .arg(&output)
        .arg(option)
        .arg("missing")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn executable_keygen_is_mode_scoped_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("generated.key");
    let result = Command::new(EXE)
        .arg("keygen")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.success(), APP.mode == Mode::KeyFile);
    if APP.mode == Mode::KeyFile {
        let original = fs::read(&output).unwrap();
        assert_eq!(original.len(), 32);
        assert!(
            !Command::new(EXE)
                .arg("keygen")
                .arg(&output)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(fs::read(output).unwrap(), original);
    } else {
        assert!(!output.exists());
    }
}

#[test]
fn executable_help_and_argument_validation() {
    let help = Command::new(EXE).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains(APP.name));
    assert!(
        !Command::new(EXE)
            .arg("encrypt")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !Command::new(EXE)
            .arg("unknown-command")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn decrypts_fixed_fixture_from_independent_openssl_or_libsodium() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../verification/fixtures")
        .join(format!("{}.hex", APP.name));
    let text = fs::read_to_string(path).unwrap();
    let bytes: Vec<u8> = text
        .trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("fixture");
    let output = dir.path().join("plain");
    fs::write(&input, bytes).unwrap();
    solid_core::decrypt::<Cipher>(APP, credential(), &input, &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), b"independent fixture\x00\xff");
}
