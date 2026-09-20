//! Authenticated, bounded-memory file encryption using established AEAD crates.
//! See FORMAT.md for the versioned framing and SECURITY.md for its limits.
pub mod cli;
mod credentials;
mod private_file;

use aead::{AeadInPlace, KeyInit, Nonce};
pub use credentials::{generate_key, read_key, read_password};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub const CHUNK_SIZE: usize = 65_536;
pub const HEADER_SIZE: usize = 64;
pub const TAG_SIZE: usize = 16;
pub const MAX_PLAINTEXT: u64 = 1 << 36;
pub const RECORDS_PER_KEY: u64 = 4096;
const MAGIC: &[u8; 8] = b"ENCWS1\r\n";
pub type Result<T> = io::Result<T>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Password = 1,
    KeyFile = 2,
    Embedded = 3,
}

#[derive(Clone, Copy, Debug)]
pub struct App {
    pub name: &'static str,
    pub algorithm: u8,
    pub mode: Mode,
}

pub enum Credential<'a> {
    Password(&'a [u8]),
    Key(&'a [u8; 32]),
    Embedded(&'a [u8; 32]),
}

pub fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "wrong app or credentials, damaged file, or unsupported format",
    )
}

fn validate_cipher<C: AeadInPlace + KeyInit>(app: App) -> Result<()> {
    let expected = match app.algorithm {
        1 => (32, 12),
        2 => (32, 24),
        3 | 5 => (16, 12),
        4 | 6 => (32, 12),
        _ => return Err(invalid()),
    };
    if (C::key_size(), Nonce::<C>::default().len()) != expected
        || aead::Tag::<C>::default().len() != TAG_SIZE
    {
        return Err(invalid());
    }
    Ok(())
}

fn header(app: App, length: u64, salt: &[u8; 32]) -> [u8; HEADER_SIZE] {
    let mut h = [0; HEADER_SIZE];
    h[..8].copy_from_slice(MAGIC);
    h[8] = 1;
    h[9] = app.algorithm;
    h[10] = app.mode as u8;
    h[11] = u8::from(app.mode == Mode::Password);
    h[12..16].copy_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
    h[16..24].copy_from_slice(&length.to_le_bytes());
    h[24..56].copy_from_slice(salt);
    h
}

fn encoded_length(length: u64) -> Result<u64> {
    if length > MAX_PLAINTEXT {
        return Err(invalid());
    }
    let records = length.div_ceil(CHUNK_SIZE as u64) + 1;
    Ok(HEADER_SIZE as u64 + length + records * TAG_SIZE as u64)
}

fn parse_header(app: App, h: &[u8; HEADER_SIZE]) -> Result<u64> {
    let length = u64::from_le_bytes(h[16..24].try_into().map_err(|_| invalid())?);
    let salt: &[u8; 32] = h[24..56].try_into().map_err(|_| invalid())?;
    if *h != header(app, length, salt) {
        return Err(invalid());
    }
    encoded_length(length)?;
    Ok(length)
}

fn aad(
    h: &[u8; HEADER_SIZE],
    index: u64,
    length: usize,
    final_record: bool,
) -> [u8; HEADER_SIZE + 13] {
    let mut aad = [0; HEADER_SIZE + 13];
    aad[..HEADER_SIZE].copy_from_slice(h);
    aad[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&index.to_le_bytes());
    aad[HEADER_SIZE + 8..HEADER_SIZE + 12].copy_from_slice(&(length as u32).to_le_bytes());
    aad[HEADER_SIZE + 12] = u8::from(final_record);
    aad
}

// Every file has an OS-random 256-bit salt. Every 4096 records gets a different
// HKDF-derived key. A monotonic counter makes nonces unique under each key.
struct RecordCipher<C> {
    hkdf: Hkdf<Sha256>,
    context: [u8; 4],
    engine: Option<C>,
    segment: Option<u64>,
}

impl<C: AeadInPlace + KeyInit> RecordCipher<C> {
    fn new(app: App, credential: Credential<'_>, h: &[u8; HEADER_SIZE]) -> Result<Self> {
        let master = credentials::master(app.mode, credential, &h[24..56])?;
        Ok(Self {
            hkdf: Hkdf::<Sha256>::new(Some(&h[24..56]), &*master),
            context: h[8..12].try_into().map_err(|_| invalid())?,
            engine: None,
            segment: None,
        })
    }

    fn cipher(&mut self, index: u64) -> Result<&C> {
        let segment = index / RECORDS_PER_KEY;
        if self.segment != Some(segment) {
            let mut info = b"enc-workspace1/v1/segment-key/".to_vec();
            info.extend_from_slice(&self.context);
            info.extend_from_slice(&segment.to_le_bytes());
            let mut key = Zeroizing::new(vec![0; C::key_size()]);
            self.hkdf.expand(&info, &mut key).map_err(|_| invalid())?;
            self.engine = Some(C::new_from_slice(&key).map_err(|_| invalid())?);
            self.segment = Some(segment);
        }
        self.engine.as_ref().ok_or_else(invalid)
    }

    fn nonce(index: u64) -> Nonce<C> {
        let mut nonce = Nonce::<C>::default();
        let end = nonce.len();
        nonce[end - 8..].copy_from_slice(&index.to_be_bytes());
        nonce
    }

    fn seal(
        &mut self,
        h: &[u8; HEADER_SIZE],
        index: u64,
        final_record: bool,
        buffer: &mut Zeroizing<Vec<u8>>,
    ) -> Result<()> {
        let aad = aad(h, index, buffer.len(), final_record);
        let tag = self
            .cipher(index)?
            .encrypt_in_place_detached(&Self::nonce(index), &aad, buffer)
            .map_err(|_| invalid())?;
        buffer.extend_from_slice(&tag);
        Ok(())
    }

    fn open(
        &mut self,
        h: &[u8; HEADER_SIZE],
        index: u64,
        final_record: bool,
        buffer: &mut Zeroizing<Vec<u8>>,
    ) -> Result<()> {
        let count = buffer.len().checked_sub(TAG_SIZE).ok_or_else(invalid)?;
        let mut tag = aead::Tag::<C>::default();
        tag.copy_from_slice(&buffer[count..]);
        buffer.truncate(count);
        self.cipher(index)?
            .decrypt_in_place_detached(
                &Self::nonce(index),
                &aad(h, index, count, final_record),
                buffer,
                &tag,
            )
            .map_err(|_| invalid())
    }
}

pub(crate) fn input_file(path: &Path) -> Result<File> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    Ok(file)
}

pub(crate) fn temporary(output: &Path) -> Result<tempfile::NamedTempFile<File>> {
    match fs::symlink_metadata(output) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "output already exists; choose a new filename",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    tempfile::Builder::new()
        .prefix(".enc-workspace1-")
        .make_in(parent, private_file::create_private)
}

pub(crate) fn publish(mut temp: tempfile::NamedTempFile<File>, output: &Path) -> Result<()> {
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(output).map_err(|e| e.error)?;
    Ok(())
}

fn eof(reader: &mut impl Read) -> Result<()> {
    let mut extra = [0];
    if reader.read(&mut extra)? != 0 {
        return Err(invalid());
    }
    Ok(())
}

/// Encrypt a regular file. Retain the source and never replace an existing output.
pub fn encrypt<C: AeadInPlace + KeyInit>(
    app: App,
    credential: Credential<'_>,
    input: &Path,
    output: &Path,
) -> Result<()> {
    validate_cipher::<C>(app)?;
    credentials::validate_for_encryption(&credential)?;
    let mut source = input_file(input)?;
    let length = source.metadata()?.len();
    encoded_length(length)?;
    let mut salt = [0; 32];
    getrandom::fill(&mut salt).map_err(io::Error::other)?;
    let h = header(app, length, &salt);
    let mut temp = temporary(output)?;
    let mut cipher = RecordCipher::<C>::new(app, credential, &h)?;
    temp.write_all(&h)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE));
    let mut remaining = length;
    let mut index = 0;
    while remaining > 0 {
        let count = remaining.min(CHUNK_SIZE as u64) as usize;
        buffer.resize(count, 0);
        source.read_exact(&mut buffer)?;
        cipher.seal(&h, index, false, &mut buffer)?;
        temp.write_all(&buffer)?;
        remaining -= count as u64;
        index += 1;
    }
    eof(&mut source)?;
    buffer.clear();
    cipher.seal(&h, index, true, &mut buffer)?;
    temp.write_all(&buffer)?;
    publish(temp, output)
}

/// Verify every record and the mandatory final tag before publishing plaintext.
pub fn decrypt<C: AeadInPlace + KeyInit>(
    app: App,
    credential: Credential<'_>,
    input: &Path,
    output: &Path,
) -> Result<()> {
    validate_cipher::<C>(app)?;
    let mut source = input_file(input)?;
    let mut h = [0; HEADER_SIZE];
    source.read_exact(&mut h).map_err(|_| invalid())?;
    let length = parse_header(app, &h)?;
    if source.metadata()?.len() != encoded_length(length)? {
        return Err(invalid());
    }
    let mut temp = temporary(output)?;
    let mut cipher = RecordCipher::<C>::new(app, credential, &h)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE));
    let mut remaining = length;
    let mut index = 0;
    while remaining > 0 {
        let count = remaining.min(CHUNK_SIZE as u64) as usize;
        buffer.resize(count + TAG_SIZE, 0);
        source.read_exact(&mut buffer).map_err(|_| invalid())?;
        cipher.open(&h, index, false, &mut buffer)?;
        temp.write_all(&buffer)?;
        remaining -= count as u64;
        index += 1;
    }
    buffer.resize(TAG_SIZE, 0);
    source.read_exact(&mut buffer).map_err(|_| invalid())?;
    cipher.open(&h, index, true, &mut buffer)?;
    eof(&mut source)?;
    publish(temp, output)
}

#[cfg(test)]
mod tests;
