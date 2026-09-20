use crate::{Credential, Mode, Result, input_file, invalid, publish, temporary};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub const PASSWORD_MAX: usize = 1024;
pub const PASSWORD_MIN: usize = 12;

fn validate_password(password: &[u8]) -> Result<()> {
    if password.is_empty()
        || password.len() > PASSWORD_MAX
        || password.iter().any(|b| matches!(b, 0 | b'\n' | b'\r'))
        || std::str::from_utf8(password).is_err()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "password must be one UTF-8 line of 1 to 1024 bytes without NUL",
        ));
    }
    Ok(())
}

pub(crate) fn validate_for_encryption(credential: &Credential<'_>) -> Result<()> {
    if let Credential::Password(password) = credential {
        validate_password(password)?;
        if password.len() < PASSWORD_MIN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "use a strong passphrase of at least 12 UTF-8 bytes",
            ));
        }
    }
    Ok(())
}

/// Read exactly 32 raw bytes; text/hex keys and extra bytes are rejected.
pub fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let mut file = input_file(path)?;
    if file.metadata()?.len() != 32 {
        return Err(invalid());
    }
    let mut key = Zeroizing::new([0; 32]);
    file.read_exact(&mut *key)?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(invalid());
    }
    Ok(key)
}

/// Read one UTF-8 line, removing at most one trailing LF or CRLF.
pub fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    input_file(path)?
        .take((PASSWORD_MAX + 3) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    validate_password(&bytes)?;
    Ok(bytes)
}

/// Generate a random master key using owner-only creation and no-clobber publication.
pub fn generate_key(path: &Path) -> Result<()> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *key).map_err(std::io::Error::other)?;
    let mut temp = temporary(path)?;
    temp.write_all(&*key)?;
    publish(temp, path)
}

pub(crate) fn master(
    mode: Mode,
    credential: Credential<'_>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut master = Zeroizing::new([0; 32]);
    match (mode, credential) {
        (Mode::Password, Credential::Password(password)) => {
            validate_password(password)?;
            // Fixed v1 profile: Argon2id v19, 64 MiB, 3 passes, 1 lane.
            // Untrusted headers cannot request arbitrary memory/time costs.
            let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| invalid())?;
            let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into_with_memory(password, salt, &mut *master, &mut *memory)
                .map_err(|_| invalid())?;
        }
        (Mode::KeyFile, Credential::Key(key)) | (Mode::Embedded, Credential::Embedded(key)) => {
            master.copy_from_slice(key)
        }
        _ => return Err(invalid()),
    }
    Ok(master)
}
